# macOS Native Server C006 — Boot-Time Runtime Directory and Backend Readiness

Status: **implemented**; the regression evidence is in
`plans/closure/macos-native-server-corrective/c006-status.md`.
Baseline: `plans/macos-native-support@cdc4439`.
Source: corrective roadmap C002; `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md`; `plans/closure/macos-native-server-corrective/c002-status.md`.
Authority: ADR-008, ADR-001 (privilege boundary); `plans/003-planning-process.md` §13 (corrective passes), §11 (network-control evidence rule), §12 (security rule).
Primary class: corrective / invariant.

## 1. The defect, as observed

C002's cold-reboot qualification was run end to end on a disposable arm64
macOS 26.6.2 guest (UTM 5.0.8, Apple Virtualization backend). The **reboot
was observed** — the kernel boot time advanced from `1792555189` to
`1792556479` — and the verify phase proved the parts of the deployment that
do not depend on the privileged daemon:

```
the kernel boot time is 1792556479
the host really rebooted: the kernel boot time advanced
both roles came back from the system domain after the reboot
the management daemon runs as uid=8998 pid=546
the management daemon still runs unprivileged
the administrator credential survived the reboot
the authenticated session is available in the new boot
```

The deployment then **failed to reconverge**. The management API answered the
telemetry request with `503 Service Unavailable` and the body `unavailable`,
because the privileged daemon was not there to answer it:

```
HTTP/1.1 503 Service Unavailable
content-type: text/plain; charset=utf-8
content-length: 11

unavailable
```

The privileged daemon's own log says why, once per `KeepAlive` respawn:

```
wg-basic: could not safely bind the configured netd socket path
```

## 2. Root cause

Two independent defects, both in the boot path, both exposed only by a real
cold reboot.

### 2.1 The privileged daemon's runtime directory did not survive the reboot

`/var/run` on macOS is `/private/var/run`, and **macOS recreates it at every
boot**. The guest proves it: after the reboot every entry under
`/private/var/run` carried the new boot's timestamp, while the state
directory `/var/db/wg-basic` kept the install's.

C002 puts the privileged socket in `/var/run/wg-basic`, and the installer
creates that directory **once**, at install time
(`src/launchd.rs::install_to_root` → `secure_directory(RUNTIME_DIR,
RUNTIME_DIR_MODE)`). The boot-time job starts the privileged daemon from
`/Library/LaunchDaemons/com.wg-basic.netd.plist`, and nothing recreates the
directory. `SocketServer::bind` then fails at its own safety check —
`fs::symlink_metadata(&runtime_directory)?` on a directory that no longer
exists — and the error is reported as `could not safely bind the configured
netd socket path`.

### 2.2 The management daemon raced the privileged daemon at boot

With the runtime directory restored, the privileged daemon started and bound
its socket, but the management daemon's **startup reconciliation still lost
the race** and the deployment stayed degraded:

```
INFO serve serve.started operation=startup outcome=degraded resource_kind=http_listener resource_id=127.0.0.1:8000 stage=reconcile
WARN serve serve.reconcile operation=startup_reconcile outcome=degraded stage=startup
WARN serve serve.degraded operation=startup_reconcile outcome=not_converged stage=reconcile
```

`launchd` spawns the two jobs concurrently — measured in the guest's unified
log, `netd` at `21:51:37.424` and `serve` at `21:51:37.598`, **174 ms
apart** — and the management daemon's startup attempt has a short retry
budget (three attempts, 250 ms apart). Against a privileged daemon that
publishes its socket within tens of milliseconds of its own launch, that is a
coin flip. There is no background reconcile, so a lost race leaves the
deployment degraded until an operator acts.

Linux does not have this problem, and its mechanism is the reference: the
`serve` unit declares `Requires=wg-basic-netd.service` and
`After=wg-basic-netd.service`, and gates itself on a `doctor` pre-flight
(`src/distribution.rs`: `NETD_UNIT`, `SERVE_UNIT`). `launchd` has no
ordering and no pre-flight, so the management daemon has to provide the
equivalent itself.

Every other path in the layout is persistent and did survive: the state
database `/var/db/wg-basic`, the log directory `/var/log/wg-basic`, the
installed binary, the installed helper, and both LaunchDaemon plists were all
present and correct in the new boot.

## 3. Why the earlier evidence missed it

- The **hosted** macOS qualification never reboots the host, so the runtime
  directory is always the one the installer just created.
- The **arm phase** of the cold-reboot qualification runs on the host the
  installer just ran on, so it cannot see the directory disappear.
- The hosted restart cycle (SIGTERM → `KeepAlive` re-supervision → `bootout`
  → reinstall) proves that the daemon **restarts**; it never proves that the
  daemon **comes back in a new boot**, because nothing is removed from the
  filesystem between the two, and the two jobs are never started concurrently
  against a fresh boot.

Only an actual cold reboot exposes either defect, which is exactly what
C002's gate asks for and what no hosted runner can produce.

## 4. The fix

### 4.1 The privileged daemon creates its own runtime directory

A daemon that launchd starts at boot has to own the preparation of its
runtime path; the installer cannot, because it does not run at boot.

1. `src/launchd.rs` — a new `ensure_runtime_directory(path)`:
   - a **missing** directory is created with the installer's exact mode
     (`RUNTIME_DIR_MODE`, `0755`), owned by the creating root process;
   - a directory that is **already there** is left exactly as it is. The
     function never repairs, widens, or adopts a directory it did not
     create. `SocketServer::bind` remains the single place that refuses a
     symlink, a foreign owner, or a world/group-writable mode.
   - a symlink or a non-directory in the path is refused, exactly as
     `secure_directory` refuses it at install time.
2. `src/main.rs::run_darwin_netd` — calls it for the socket's parent
   directory before the socket is bound, and fails with a distinct message if
   the directory cannot be prepared.

This is the Darwin analogue of the Linux unit's `RuntimeDirectory=wg-basic`:
the unit manager creates the runtime directory for the service, so the
service itself does not have to.

### 4.2 The management daemon waits for the privileged daemon

1. `src/management/worker.rs` — a new `wait_for_backend(socket, budget)`:
   the worker's startup probes the backend with the **same read-only
   capability request the doctor makes**, so "ready" means the backend is
   serving *and* admits this peer, not merely that a socket file exists. A
   missing socket, a refused connection, an unanswered request, and a
   refusal all mean "not yet".
2. The wait is **bounded** (`BACKEND_STARTUP_WAIT`, ten seconds by default,
   and a `WorkerConfig` knob). It runs before the startup reconciliation, so
   the reconciliation that is reported is the one that actually ran.
3. The listener still comes up either way: a backend that never appears
   leaves the startup attempt degraded, which is what ADR-002 requires the
   operator to see. The wait never turns an outage into a hang.

This is the Darwin analogue of the Linux unit's `After=` plus its `doctor`
pre-flight: the management daemon does not begin its startup attempt until
the privileged daemon is answering.

The change is **Darwin-only in effect**: the Linux daemon's runtime
directory is owned by systemd and the Linux units already order the two
services, so on Linux the probe succeeds on the first attempt and nothing
changes. The shared `SocketServer::bind` is not touched, so no Linux path,
unit, service, or schema changes.

Neither fix widens the privileged boundary. The first creates one directory
the privileged daemon already owns, with the mode the installer already
publishes. The second is a read-only probe of a socket the management daemon
is already allowed to use. The socket's ownership, group, mode,
peer-credential check, and the receipt's authority are all unchanged.

## 5. Regression evidence

- **Unit**: `src/launchd.rs` — `ensure_runtime_directory` creates a missing
  directory with the exact mode; it refuses a symlink and a file in its
  place; it leaves an existing directory's mode untouched.
- **Unit**: `src/management/worker.rs` — the startup wait reports "not
  ready" for a backend that never answers, within its budget.
- **Architecture guard**: the layout module stays free of process execution
  (the existing guard covers this), and the fix must not introduce a
  `Command` anywhere.
- **Controlled host**: the C002 cold-reboot qualification re-run end to end on
  the disposable macOS guest — arm phase, `shutdown -r now`, and the verify
  phase at boot — with the boot time observed to advance, both roles back
  from the system domain, the management daemon still unprivileged, the
  credential and the enrolled client preserved, the network **reconverged**,
  and the uninstall leaving no job, plist, or binary behind.

## 6. Scope

This corrective does **not** reopen any closed scope. It does not change the
service identity, the socket ownership contract, the receipt's authority, the
Linux layout, the wire or schema, the release policy, or C001's evidence. It
does not claim a macOS release, and M007's MUST-NOT-release standing is
unchanged.

## 7. Unclosed requirements this corrective does not close

- C002's **native Intel** arch of the cold-reboot leg: the leg is proven on
  arm64 only. A native Intel host remains required.
- C001's native Intel arch of the off-host product path: unchanged.
- C003–C005 remain blocked on their own predecessors.
