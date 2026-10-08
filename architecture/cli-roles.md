# CLI roles

This document describes **current implemented behavior** for every `wg-basic`
subcommand in `src/main.rs`. Native system installation is implemented under
M002 qualification; M004 update commands are implemented but fail closed
while the production trust root is unprovisioned and qualification remains open.
See [overview](overview.md) for status.

Part of the [architecture overview](overview.md). Role internals live in
[management-http](management-http.md) (`serve`, `reconcile`, `health`),
[privilege-boundary](privilege-boundary.md) (`netd`, UDS auth),
[state-store](state-store.md) (`state`, leases, backup/restore), and
[diagnostics-maintenance](diagnostics-maintenance.md) (`doctor`, `network`,
`state purge`, operational events).

## Global surface

- No subcommand prints help output side effects; bare `wg-basic` prints the
  version plus `use --help for runtime roles` and exits 0.
- Global `--log-format human|json` (default `human`). Operational events go to
  **stderr**; command results stay on **stdout**. JSON mode emits one object
  per line; failure text goes through `operational::command_failure`
  (`src/operational.rs`). The binary writes no log files.
- Any `Err(String)` from a role prints via `command_failure` and exits **2**.
  Linux-only roles refuse to run off-Linux with
  `network service roles require Linux` (exit 2).
- Defaults: `--state /var/lib/wg-basic/state.db`,
  `--socket /run/wg-basic/netd.sock`, `serve --http-bind 127.0.0.1:8000`,
  `admin set-password --username admin`.

## Flags table

| Role / subcommand | Key flags (defaults) | Touches | Never touches |
|---|---|---|---|
| `serve` | `--state`, `--socket`, `--http-bind` (`127.0.0.1:8000`), `--canonical-origin` (none), `--allow-non-loopback` (false) | state DB via bounded worker, netd via UDS client, TCP listener | kernel/netlink/nft directly; never spawns or elevates netd |
| `netd` | `--socket`, `--allow-uid UID`, `--allow-user NAME` (repeatable) | UDS socket bind, kernel via typed backends (Generic Netlink, RTNETLINK, bounded `nft`, `/proc/sys/net/ipv4/ip_forward` fixed write) | state DB (database-free) |
| `doctor` | `--state`, `--socket`, `--json`, `--http-bind`, `--canonical-origin`, `--allow-non-loopback` | read-only SQLite inspection, netd plan-only/observe requests, read-only `/proc/sys/net/ipv4/ip_forward` | migrations, kernel applies, state writes |
| `reconcile` | `--state`, `--socket` | state DB open, one aggregate reconcile via UDS | kernel directly |
| `health` | `--state`, `--socket` | state DB open, health projection | netd, kernel |
| `admin set-password` | `--username`, `--password-stdin` (required), `--state` | state DB credential row + session revocation | argv/env password sources, verifier/token output |
| `admin status` | `--state` | state DB safe projection | verifiers, tokens |
| `state status` | `--state` | state DB metadata/convergence | keys, row contents, kernel |
| `state init` | `--state` | create current schema or validate/migrate existing owned DB | network IPC, kernel |
| `state backup <dest>` | `--state` | consistent snapshot write (fails if dest exists, owner-only `0600`) | kernel |
| `state restore <cand>` | `--state` | validate-then-replace, retains `<state>.pre-restore` | kernel |
| `state verify <cand>` | (positional only) | read-only candidate check | live DB, migrations, kernel |
| `state purge` | `--confirm-installation-id`, `--dry-run`, `--state`, `--socket` | verified DB files only, after guards | lease files, operator files, foreign kernel state |
| `network status` | `--state` | read-only inspection | kernel, netd |
| `network disable/enable` | `--state`, `--socket` | durable flag commit + reconcile attempt | kernel directly |
| `system install` | `--candidate` (current executable by default) | root-owned system layout, sysusers, systemd units and services | automatic sudo, release discovery, signature claims |
| `system status` | none | installation receipt, file ownership and systemd lifecycle inspection | state mutation, kernel mutation |

## `system` (native installation)

- `install`: requires effective root and an active systemd system manager. It
  serializes with a root-owned advisory lock, accepts a local executable with
  the exact running release identity, installs the canonical binary/sysusers/
  service layout, starts netd before serve, and writes the private receipt
  last. It refuses unowned or modified destinations and never invokes sudo.
  This is a local-candidate path and does not claim signature authenticity.
- `status`: validates the root-owned receipt, executable and exact product
  definition digests, systemd registration/lifecycle, and state directory
  ownership. It does not mutate the installation.

## `serve` (unprivileged management role)

- Purpose: own the durable store on one bounded worker thread and serve the
  loopback management HTTP surface plus embedded UI.
- Privilege: unprivileged. Never escalates, never spawns/elevates netd, never
  touches the kernel directly; HTTP code reaches the store and netd only
  through the worker.
- Bind policy (exactly three shapes): loopback default; `--canonical-origin
  https://…` for loopback-behind-TLS-proxy (switches to `__Host-` `Secure`
  cookie + HSTS); `--allow-non-loopback --canonical-origin …` for an
  acknowledged routable bind. Anything else (e.g. non-https origin on
  loopback, `--allow-non-loopback` without an origin) is a startup error.
- Lifecycle: acquires `<state>.serve.lock` (nonblocking advisory, held for
  life; a second `serve` exits before HTTP bind), attempts startup
  reconciliation, runs until Ctrl-C. Shutdown is a one-shot channel:
  stop-accept → drain → stop worker → release store.
- Exit: `Err` → exit 2; Ctrl-C → graceful `Ok(())`.

## `netd` (privileged network role)

- Purpose: the only kernel-touching role; serves typed WireGuard / link /
  firewall operations over a Unix-domain socket.
- Privilege: the role that holds `CAP_NET_ADMIN`. Authorizes peers by kernel
  `SO_PEERCRED` UID: own effective UID + root by default, plus each
  `--allow-uid UID`.
- Socket: binds `--socket` only after directory ownership/mode checks;
  preserves conflicting paths instead of replacing them; on shutdown removes
  only the inode it created (device/inode/owner rechecked).
- Kernel reach is typed-only: Generic Netlink WireGuard, RTNETLINK
  link/address/route, bounded direct `nft` subprocess for the owned
  `inet wg_basic` table, fixed forwarding write. No shell, no raw nft source,
  no sysctl paths, no file writes. Never opens the state DB.
- Exit: Ctrl-C sets an `AtomicBool` shutdown flag (`run_until_shutdown`);
  emits `netd.started` / `netd.stopping` (`graceful` vs `runtime_error`);
  runtime failure → exit 2.

## `doctor` (read-only check)

- Purpose: capability/drift preflight that proves nothing was mutated.
- Behavior: immutable read-only SQLite inspection (deliberately **not**
  `StateStore::open`, so no migrations); capability snapshot via netd
  `InspectCapabilities`; aggregate **plan-only** request plus read-only
  WireGuard observation and procfs forwarding read. A missing DB is `Warn`;
  live WAL sidecars that block an immutable view are `Unknown`.
- Optional `--http-bind` (+ `--canonical-origin` / `--allow-non-loopback`)
  validates the same `ServeConfig` policy `serve` would enforce, without
  binding. `--json` switches the report to JSON on stdout.
- Mutations: none. Unproven port availability is reported `Unknown` rather
  than bound; ownership conflicts are reported, never repaired.
- Exit: `0` all pass, `1` any warn/unknown, `2` any fail or invalid
  invocation (`DoctorReport::exit_code`, `src/doctor.rs`).

## `reconcile` (one-shot management runtime)

- Purpose: open the store and reconcile the current desired generation
  against netd, e.g. after a restart or a degraded commit.
- Privilege: unprivileged; reaches the network only through the authorized
  socket. Never mutates the kernel directly.
- Output: `no managed interface; nothing to reconcile` for an empty
  installation (normal, exit 0), else `generation N -> converged|not
  converged (<disposition>)`.
- Exit: store/socket errors → exit 2.

## `health` (one-shot projection)

- Purpose: print the durable management health projection and exit.
- Behavior: opens the store, prints pretty JSON. Carries categories only,
  never receipts/secrets. Contacts neither netd nor the kernel.
- Exit: errors → exit 2.

## `admin` (local credentials)

- `set-password`: creates the administrator or resets the password, revoking
  all live sessions in the same transaction. Opens the store directly
  (one-shot, no worker) before any service runs.
- `status`: prints the safe projection (identity, enabled state, live session
  count). Never prints a verifier, token, or password.
- Password-stdin rule: `--password-stdin` is **required**; without it the
  command errors without reading. The password arrives only on this
  process's own stdin — never as an argv value (visible via `/proc`) and
  never from the environment (inherited by children). Exactly one trailing
  newline (`\n`, plus optional preceding `\r`) is trimmed; all other bytes,
  including a genuine trailing newline piped without `echo`, are preserved.

## `state` (inspection, backup, restore, purge)

- `status`: opens the store, prints identifiers, generations, convergence,
  and `integrity: ok`. Never prints keys or row contents.
- `backup <destination>`: consistent snapshot; destination must not exist;
  created owner-only. Output warns the file holds VPN keys and must never be
  committed. Emits `state.backup_completed`.
- `restore <candidate>`: validates first for a clear error, then the library
  revalidates before replacing; retains the previous DB as
  `<state>.pre-restore`. Requires serve stopped (cross-process lease refuses
  an active `serve`; open-handle check is defense in depth). Touches no
  kernel state — output says to start the service to reconcile, and that
  startup still fails closed on foreign/untagged resources. Emits
  `state.restore_completed`.
- `verify <candidate>`: read-only check (installation id, generation,
  schema, integrity, foreign keys, would-migrate, too-new). Modifies
  nothing, migrates nothing, with a keys warning.
- `purge`: uninstall/reset. Guards, in order: acquire service lease +
  exclusive maintenance lease; read-only snapshot; `--confirm-installation-id`
  must equal the DB's id; desired network must be **disabled** (a configured
  server is also required — empty state cannot purge); current generation
  must be recorded **converged**; fresh netd plan must be a **no-op**. Any
  unmet guard fails the command; `--dry-run` prints the report (paths +
  preconditions) without removing anything. Removal is limited to verified
  wg-basic DB files (live DB, `-wal`/`-shm`, `.pre-restore`, pre-migration
  snapshots, known temp files); each must be a regular non-symlink file owned
  by the caller with no group/world bits, else abort. The service and
  maintenance lease files, other directory files, and kernel state are never
  removed.

## `network` (availability switch)

- `status`: read-only inspection (installation id, generation, enabled flag,
  last converged, serve-lease state, interface name, client count). Contacts
  neither netd nor the kernel.
- `disable` / `enable`: acquire the service lease, commit the durable
  operational flag as a new generation, then attempt reconcile. Already-in-
  state is a no-op message. Output distinguishes `committed … and enforced`
  from `committed … but not yet enforced / could not be confirmed` (rerun
  `wg-basic reconcile`). Emits `network.disabled` / `network.enabled`
  (`Info` when enforced, `Warn` otherwise). Never touches the kernel
  directly — enforcement goes through netd.
