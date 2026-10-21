# Privilege boundary

## Current protocol behavior

`wg-basic netd` binds only a Unix-domain stream socket. It serves one connection at a time, with at most 16 queued connections, one bounded request per connection, and a two-second read/write timeout. On Linux it authenticates the kernel-reported peer UID with `SO_PEERCRED`; on macOS (M002) it uses the Apple-documented `getpeereid(3)` via the audited `nix::unistd::getpeereid` wrapper, rechecked on every connection, and accepted streams are forced to blocking mode so one slow peer occupies the server for at most the timeout on both OSes. It supports `ping`, `inspect_capabilities`, `observe_wireguard_device`, and `apply_wireguard_device`. The protocol uses JSON in a four-byte big-endian length frame capped at 64 KiB. Major protocol version and request ID are checked; malformed input is closed without reflecting request bytes.

The socket parent must already exist, be a real directory owned by the effective netd UID, and not be group/world writable. The socket is created with mode `0660`. Existing regular files, symlinks, active sockets, and sockets owned by another UID are preserved and treated as conflicts. A stale socket owned by netd may be removed after a failed connect and inode/owner recheck. Shutdown removes the socket only if its device/inode/owner still match the socket netd created.

By default Linux netd authorizes its own effective UID and root, while macOS netd (M002) authorizes only its own effective UID with no root bypass; `--allow-uid UID` adds explicit management-service UIDs on both, and `--allow-user` resolves local account names. Root on macOS is rejected unless explicitly allowlisted. The protocol carries no UID/PID authorization fields. `serve` is the unprivileged management role: it hosts the authenticated HTTP API and embedded product UI, and reaches the durable store and netd only through its bounded worker. `reconcile` and `health` are one-shot management commands: `reconcile` opens the durable state store, projects the current desired generation, and submits it to netd over the authorized socket; `health` reports the same convergence state without contacting netd. None of these roles escalates privilege, mutates the kernel directly, or spawns netd — a missing or unprivileged `netd` is reported as an unavailable backend, never worked around locally. `doctor` asks netd for the capability snapshot. A dedicated management user should be supplied to netd with `--allow-uid` and granted access to the socket's group as needed.

The snapshot reports the OS, architecture, effective UID/GID, runtime-directory safety, and — on Linux — whether `CAP_NET_ADMIN` appears in `/proc/self/status` plus the kernel release from `/proc`. On macOS there are no Linux capabilities (`cap_net_admin` is absent) and the kernel release comes from `uname`; Linux backend fields report `unavailable` while the Darwin WireGuard helper (M003), routes (M004), and PF/NAT (M005) remain unqualified. Namespace, WireGuard, and nftables capability fields remain `unknown` on Linux until their owning backends provide authoritative probes. Capability inspection does not create links/namespaces, load modules, change sysctls, or install firewall objects. WireGuard and link/address/route operations use typed Rust netlink backends. Firewall policy uses a typed protocol operation and a bounded direct `nft` subprocess; it does not invoke a shell or accept raw nft source. Forwarding writes are fixed to `/proc/sys/net/ipv4/ip_forward` and explicitly requested `/proc/sys/net/ipv6/conf/all/forwarding`.

## Intended service privilege contract

When installed, use separate service identities where practical:

- management role: no `CAP_NET_ADMIN`; access only to its state/config and the netd socket;
- network role: the only role granted `CAP_NET_ADMIN`, plus access to the runtime socket and narrowly required configuration;
- no shell is needed for either role.

No service unit is shipped yet; package installation and service lifecycle belong to later distribution work. The protocol exposes typed network operations alongside the original peer-authorized, bounded-framed read-only operations. Two further operations carry one installation's network intent at one desired generation: `PlanInstallationNetworkIntent` and `ApplyInstallationNetworkIntent`. They revalidate owner identity and generation before any privileged work and cannot carry raw nft source, sysctl paths, or key material beyond the typed configuration the interface intent already contains. Arbitrary command, path-based sysctl, nftables-source, file-write, and raw-netlink operations are not part of the protocol.

The Linux network service supports typed WireGuard configuration, managed interface/address/route reconciliation, and dual-stack firewall/forwarding policy. The firewall service owns only `inet wg_basic`; it never flushes unrelated tables. IPv4 forwarding and explicitly requested IPv6 global forwarding may only be enabled to `1`; policy disable removes the owned table but never resets either control. IPv6 uses the fixed `net.ipv6.conf.all.forwarding` control, with its host-wide Host/Router and Router Advertisement consequences documented for operators. The supported policy and external-firewall interaction are documented in [firewall ownership](firewall.md). Persistence is implemented and confined to the unprivileged management role, which publishes its browser surface through `serve`.

## Darwin service identity (C002)

On Darwin the deployment is two launchd system daemons with different
identities:

- `netd` is the only root component. It owns the typed OS mutations.
- `serve` is a dedicated, unprivileged local principal (`_wg-basic-serve`).
  It owns SQLite and HTTP and never touches the kernel.

The management account is **preprovisioned**. The installer never creates
accounts and never adopts an unknown identity: it resolves the account
through the directory service, refuses a missing account, refuses an account
that resolves into macOS's reserved UID range, and refuses an account whose
primary group is not the dedicated group. A renamed or reused identity is
refused rather than trusted.

The privileged socket is the whole path from the management daemon to the
privileged one. The privileged daemon always sets the socket's ownership
explicitly, because a socket keeps the creating process's group by default and
that group is not an identity this product chose: it is mode `0660`, owned by
root and the management group, when the *verified install receipt* records a
management identity, and mode `0600`, owned by the privileged daemon alone,
when it does not. The privileged daemon admits the management UID that the
*verified install receipt* records, never a name supplied on a command line.

The install receipt lives inside the management-owned state directory and
belongs to the management identity, so the management daemon can read the
helper digest and its own identity from it. A root-owned receipt in a
management-owned directory would be unreadable by the management daemon that
owns it.

## Darwin boot-time runtime and backend readiness (C006)

On macOS `/var/run` is `/private/var/run`, and macOS **recreates it at every
boot**. A directory created under it by the installer is therefore gone in the
next boot, and the privileged daemon would find no runtime directory to bind
its socket in. The privileged daemon now creates its own runtime directory
when it is missing, with the installer's published mode (`0755`), before it
binds. It never adopts, widens, or repairs a directory it did not create: an
existing directory is left exactly as it is, and a symlink or a non-directory
in its place is refused. This is the Darwin analogue of the Linux unit's
`RuntimeDirectory=`.

`launchd` starts the system-domain jobs concurrently — measured 174 ms apart on
a cold boot — so the management daemon cannot assume the privileged daemon is
already listening. The management daemon now waits, **bounded** (ten seconds),
for the privileged daemon to answer a read-only capability request — the same
request the doctor makes — before its startup reconciliation. A missing
socket, a refused connection, an unanswered request, and a refusal all mean
"not yet". The wait adds no privilege and opens no new channel: it is a
read-only request over the socket the management daemon is already permitted
to use. The listener still comes up either way, so a backend that never
appears leaves the deployment degraded rather than absent — the same
"degraded, not absent" contract the Linux units express with `Requires=` and
`After=` plus their `doctor` pre-flight.

The wait is **Darwin's need, and Darwin's only** (C009). The Linux units
already order the two services, so a wait there would only delay the
listener — and it delayed it by ten seconds in every Linux harness that
starts the management daemon without a privileged daemon beside it. The
bound is therefore zero off Darwin, where it is a true no-op: the deadline is
checked before the request, so the management daemon neither probes nor
sleeps. The bound is a named, exported constant, so the test harnesses that
wait for the management daemon's listener derive their own bound from the
product's instead of hard-coding one.

## The isolated Darwin OS boundary (C001)

The Darwin kernel boundary needs FFI. It lives in one small workspace member,
`crates/darwin-sys`, whose only `unsafe` module is the OS boundary itself.
The product crate keeps its crate-wide `#![forbid(unsafe_code)]`. This is the
shape the M002 implementation plan anticipated: isolate audited `unsafe` in a
tiny OS boundary rather than weaken the crate-wide rule.

The boundary exposes a typed API only: interface and address observation,
routing-table observation, link and address control, route mutation, process
executable lookup, and the host forwarding state. No raw pointer, file
descriptor, or `errno` escapes to a caller, and nothing in it parses a
human-readable tool's output or executes a subprocess.

The only process this product runs on Darwin is `launchctl`, from
`src/launchd_install.rs`, with a closed verb set, a closed target set, and an
absolute path. The pure layout module (`src/launchd.rs`) contains no process
execution at all.
