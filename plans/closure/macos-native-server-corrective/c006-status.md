# macOS Native Server C006 — Boot-Time Runtime Directory and Backend Readiness

Disposition: **closed** (2026-10-21) — the two boot-path defects that stopped
the C002 cold-reboot qualification from reconverging are fixed, and the
qualification was re-run end to end on a disposable arm64 macOS guest: the
reboot was **observed**, both roles came back from the system domain, the
management daemon was still the unprivileged identity, the credential and the
enrolled client survived, the network **reconverged**, and the uninstall left
no job, plist, or binary behind. C002's own residual is the **native Intel**
arch of the same leg, which C006 does not close.

Date: 2026-10-21.

## Implementation revision

- Repository baseline: `cdc4439`.
- Implementation head: `e37210b` ("macos(c006): make the deployment survive a
  cold reboot").
- Source plan: `plans/implementation/macos-native-server/c006-boot-time-runtime-and-backend-readiness.md`.
- Source roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md` (C002's corrective).
- Corrected plan: `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md`.
- Corrected closure record: `plans/closure/macos-native-server-corrective/c002-status.md`.
- The C001 closure record and the historical M003–M007 closures are untouched and
  remain as recorded.

## What the qualification found

C002's cold-reboot qualification was run end to end on a disposable arm64
macOS guest for the first time. The reboot was taken and **observed**, and the
verify phase proved everything that does not depend on the privileged daemon:

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

and the privileged daemon's own log said why, once per `KeepAlive` respawn:

```
wg-basic: could not safely bind the configured netd socket path
```

Two independent boot-path defects, both invisible to every qualification that
does not actually reboot a host:

1. **`/var/run` is transient on macOS.** It is `/private/var/run`, and macOS
   recreates it at every boot — the guest proves it: after the reboot every
   entry under `/private/var/run` carried the new boot's timestamp, while
   `/var/db/wg-basic` kept the install's. The privileged daemon's runtime
   directory was therefore gone in the new boot, and `SocketServer::bind` failed
   at its own safety check on the missing directory.
2. **The management daemon raced the privileged daemon at boot.** `launchd`
   spawns the two jobs concurrently — measured in the guest's unified log,
   `netd` at `21:51:37.424` and `serve` at `21:51:37.598`, **174 ms apart** —
   and the management daemon's startup attempt has a short retry budget
   (three attempts, 250 ms apart). It lost the race, and with no background
   reconcile the deployment stayed degraded until an operator acted.

The same run also found three defects in the **qualification fixture itself**,
all of which had to be fixed before the leg could produce its evidence.

## Requirement-to-evidence matrix

| Requirement (C006 plan) | Evidence | Result |
|---|---|---|
| §4.1 The privileged daemon creates its own runtime directory when it is missing, with the installer's exact mode, and refuses a symlink or a foreign path | `src/launchd.rs`: `ensure_runtime_directory(path)` creates a **missing** directory with `RUNTIME_DIR_MODE` (0755) and leaves an existing one exactly as it is — it never repairs, widens, or adopts a directory it did not create; a symlink or a non-directory in the path is refused as `InstallError::Modified`. `src/main.rs::run_darwin_netd` calls it for the socket's parent directory before the socket is bound, and reports `could not create the netd runtime directory` if it cannot. `SocketServer::bind` remains the single place that refuses a symlink, a foreign owner, or a world/group-writable mode. This is the Darwin analogue of the Linux unit's `RuntimeDirectory=wg-basic` | Passed (code + unit + controlled host) |
| §4.2 The management daemon waits, bounded, for the privileged daemon before its startup reconciliation, and the listener still comes up either way | `src/management/worker.rs`: `wait_for_backend(socket, budget)` probes with the **same read-only capability request the doctor makes**, so "ready" means the backend is serving *and* admits this peer; a missing socket, a refused connection, an unanswered request and a refusal all mean "not yet". The budget is `BACKEND_STARTUP_WAIT` (ten seconds) and a `WorkerConfig` knob. The wait runs **before** the startup reconciliation, so the reconciliation that is reported is the one that actually ran, and a backend that never appears leaves the startup attempt degraded — ADR-002's "the listener must come up either way" still holds. This is the Darwin analogue of the Linux unit's `Requires=`/`After=` plus its `doctor` pre-flight | Passed (code + unit + controlled host) |
| §4 Neither fix widens the privileged boundary, and neither touches Linux | The first change creates one directory the privileged daemon already owns, with the mode the installer already publishes. The second is a read-only probe of a socket the management daemon is already allowed to use. The socket's ownership (`0660`, root and the management group), its peer-credential check, the receipt's authority, the shared `SocketServer::bind`, the Linux unit files, the wire and the schema are all unchanged. The Linux daemon's runtime directory is owned by systemd and the Linux units already order the two services, so on Linux the probe succeeds on the first attempt | Passed (code + unit + gates) |
| §5 Regression evidence: the cold-reboot qualification re-run end to end, with the reboot observed and the network reconverged | See *Controlled-host cold-reboot qualification* below: the arm phase, a real `shutdown -r now`, and the verify phase at boot, all observed on a disposable arm64 macOS 26.6.2 guest | Passed |
| §5 The qualification fixture must produce its evidence | Three fixture defects were found and fixed: the reconvergence wait **panicked** on a `503` body instead of treating it as "not yet"; the arm phase's bootout used `launchctl bootout system <label>`, which launchctl rejects with `Boot-out failed: 5: Input/output error` because after a domain target it expects a service *path* or a qualified `system/<label>` target; and the verify phase removed its own job **before** writing its evidence, so the evidence could never be written — `launchctl bootout` stops the running job, which is that process. The evidence is now written first, the plist is removed next, and the bootout is detached into its own process group | Passed |
| Scope: no closed scope reopened, no release claimed | C001's evidence and disposition are untouched; the historical M003–M007 closures are untouched; no macOS release, tag, or asset is claimed; M007's MUST-NOT-release standing is unchanged | Passed |

## Controlled-host cold-reboot qualification

Run on a **disposable arm64 macOS 26.6.2 guest** (build `25G83`) under UTM
5.0.8 on the Apple Virtualization.framework backend, with the host's shared
network (`bridge100`, `192.168.64.0/24`); the guest is `192.168.64.2`. The
guest is disposable: it is created, exercised, and deleted. It is a macOS
guest, so the leg has a real launchd system domain, a real `utun`, and a real
reboot.

The pinned helper was staged from the CI recipe and its digest matched the
pinned reference in the fixture:

```
helper sha256 matches the pinned reference
helper under test: /Users/test/wg-qual/wireguard-go
```

**Arm phase** (root, in the guest) — the deployment is installed through the
product's own transactional installer, a client is enrolled through the real
HTTP surface, the expectations are recorded, and the boot-time job is
installed **without** being registered:

```
the transactional installer completed the deployment
the administrator was provisioned as the management identity
the product enrolled client 87d6e2b4-d770-4079-97c2-33b7852c577c with public key lEAN+GJREY9d85dC1pwLtrAAoMSW6MGequ6cwDfmigI=
the kernel boot time is 1792560151
recorded the expectations that must survive the reboot at /var/db/wg-basic-qual/reboot-expectations.json
the boot-time job is installed and will run in the next boot, not now
```

The recorded expectations:

```json
{
  "boot_time_seconds": 1792560151,
  "client_id": "87d6e2b4-d770-4079-97c2-33b7852c577c",
  "client_public_key": "lEAN+GJREY9d85dC1pwLtrAAoMSW6MGequ6cwDfmigI=",
  "interface_id": "9062ddff-33bc-47c6-8c1d-cc69b72ad33c",
  "management_gid": 8998,
  "management_uid": 8998,
  "peer_id": "a4b557b3-c0b7-4b2a-8ba8-1ce8d3cdba20"
}
```

The host was left in that state, and the state was **observed** before the
reboot:

```
--- qual job registered? (expect: not found) ---
Bad request.
Could not find service "com.wg-basic.qual-reboot" in domain for system
--- netd ---
	state = running
	pid = 819
--- serve ---
	state = running
	pid = 821
--- serve process ---
 8998 _wg-basic-serve   821 /usr/local/bin/wg-basic
--- runtime dir ---
drwxr-xr-x  4 root  daemon  128 /var/run/wg-basic
srw-rw----  1 root  _wg-basic-serve     0 /var/run/wg-basic/netd.sock
--- tunnel ---
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
	inet 10.77.0.1 --> 10.77.0.1 netmask 0xffffffff
--- installed binary hash ---
874033d905293791fbe7827fbbfbe6a1fd7a03074514816c9bb024cc48904a6c  /usr/local/bin/wg-basic
--- helper hash ---
a490f82f540130730f0fde5d10a3e6dab6a4dfa066b94c6968873c8104c69d21  /usr/local/libexec/wg-basic/wireguard-go
```

**Reboot phase** — the fixture's own phase, in the guest:

```
the reboot was requested: "Shutdown NOW!\n\r\nSystem shutdown time has arrived\u{7}\u{7}\r\n"
```

**Verify phase** — the boot-time job, in the new boot, as root, writing its
evidence to `/Users/test/wg-qual/evidence/c002-cold-reboot-verify.txt`:

```
the kernel boot time is 1792560319
the host really rebooted: the kernel boot time advanced
both roles came back from the system domain after the reboot
the management daemon runs as uid=8998 pid=525
the management daemon still runs unprivileged
the administrator credential survived the reboot
the authenticated session is available in the new boot
the network reconverged after the reboot: {"client_id":"87d6e2b4-d770-4079-97c2-33b7852c577c","drift":false,"enabled":true,"endpoint":null,"latest_handshake_age_seconds":null,"latest_handshake_unix_seconds":null,"observation":"present","peer_id":"a4b557b3-c0b7-4b2a-8ba8-1ce8d3cdba20","rx_bytes":0,"tx_bytes":0}
the uninstall left no job, plist, or binary behind
the enrolled client survived the reboot with the same key lEAN+GJREY9d85dC1pwLtrAAoMSW6MGequ6cwDfmigI= and peer a4b557b3-c0b7-4b2a-8ba8-1ce8d3cdba20
wrote /Users/test/wg-qual/evidence/c002-cold-reboot-verify.txt
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 3.04s
```

The kernel boot time advanced from the recorded `1792560151` to the observed
`1792560319`, so the reboot is **observed** and not inferred. The client id,
the client key and the peer id are the ones recorded before the reboot, so
the state database survived with the same contents.

The end state, observed after the verify phase:

```
--- qual plist ---
ls: /Library/LaunchDaemons/com.wg-basic.qual-reboot.plist: No such file or directory
--- qual stage dir ---
ls: /usr/local/libexec/wg-basic-qual: No such file or directory
--- product plists ---
--- product binary/helper ---
ls: /usr/local/bin/wg-basic: No such file or directory
ls: /usr/local/libexec/wg-basic: No such file or directory
--- runtime dir ---
ls: /var/run/wg-basic: No such file or directory
--- state dir ---
ls: /var/db/wg-basic: No such file or directory
--- log dir ---
ls: /var/log/wg-basic: No such file or directory
```

### The maintainer's own working Mac was refreshed to the same build

The abandoned arm-phase attempt on the maintainer's own working Mac had left
that host armed with the **pre-C006** product and a **pre-C006** staged
fixture. Left alone, that host's next reboot would have crash-looped the
privileged daemon (no runtime directory after macOS recreates `/var/run`) and
then **panicked** the old fixture on the `503 unavailable` body — so it would
have written no evidence and left a degraded deployment behind. The host was
therefore refreshed by re-running the arm phase with this corrective's build.
What was observed afterwards:

```
the transactional installer completed the deployment
the product enrolled client b89fedc6-dd3d-43fd-be5e-860118d26de7 with public key ZWrFivUgrk385XNHYlmGh60THIFJq7YVHfwxrfdCpBg=
the kernel boot time is 1791353209
recorded the expectations that must survive the reboot at /var/db/wg-basic-qual/reboot-expectations.json
the boot-time job is installed and will run in the next boot, not now
```

```
--- netd ---  state = running  pid = 50813
--- serve --- state = running  pid = 50815
--- serve process --- 8998 _wg-basic-serve 50815 /usr/local/bin/wg-basic serve --state /var/db/wg-basic/state.db --socket /var/run/wg-basic/netd.sock
--- runtime dir ---
drwxr-xr-x 4 root  daemon  128 /var/run/wg-basic
srw-rw---- 1 root  _wg-basic-serve  0 /var/run/wg-basic/netd.sock
--- installed binary hash ---
874033d905293791fbe7827fbbfbe6a1fd7a03074514816c9bb024cc48904a6c  /usr/local/bin/wg-basic
--- helper hash ---
a490f82f540130730f0fde5d10a3e6dab6a4dfa066b94c6968873c8104c69d21  /usr/local/libexec/wg-basic/wireguard-go
--- boot-time job ---
-rw-r--r-- 1 root  wheel  1037 /Library/LaunchDaemons/com.wg-basic.qual-reboot.plist
Could not find service "com.wg-basic.qual-reboot" in domain for system
--- tunnel ---
utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
	inet 10.77.0.1 --> 10.77.0.1 netmask 0xffffffff
```

The installed product's digest — `874033d9…` — is **byte-identical** to the
digest the passing guest run installed, so both hosts carry the same C006
build. The boot-time job is installed and **not registered**, exactly as the
arm phase's invariant requires, and the managed tunnel is up on `utun7` with
`inet 10.77.0.1`, the same address the guest run carried. That host's next
reboot will therefore exercise the corrected boot path and, if it succeeds,
produce an **independent arm64 cold-reboot proof on real hardware** rather
than in a guest. That proof has not happened yet, so nothing is claimed from
it here.

## Verification

On the host (Apple M4 Pro, macOS 26.6.2, rustc 1.89.0), from the repository
root:

- `cargo fmt --all -- --check` — passed.
- `cargo clippy --all-targets --locked -- -D warnings` — passed.
- `cargo test --locked` — passed: **647 tests, 0 failures**. The suite now
  carries three additional unit tests (two for `ensure_runtime_directory`, one
  for the startup wait).
- `cargo +1.89.0 check --all-targets --locked` — passed (MSRV).
- `cargo check --locked --target x86_64-apple-darwin --all-targets` — passed.
- `cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets` —
  passed (the Linux **test** targets compile too).
- `cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings` —
  passed with `CC_x86_64_unknown_linux_gnu` pointed at a `zig cc` wrapper.
  **Without** that wrapper the command cannot run on this host at all:
  `libsqlite3-sys`'s build script needs `x86_64-linux-gnu-gcc`, which is not
  installed. That failure is **pre-existing and unrelated to this change** —
  it was reproduced on the clean tree at `cdc4439` with the working tree
  stashed. The `cargo zigbuild` gate above covers the same Linux target
  without a cross C toolchain.

In the guest, the leg itself is the verification: `arm` → `reboot` →
`verify`, each phase run by the fixture as root, each phase's output
recorded above.

## Security and ownership evidence

- `netd` is the only root component. `serve` is the dedicated unprivileged
  local principal, and the verify phase **read the running process's
  effective UID**: `the management daemon runs as uid=8998 pid=525` — the
  management identity, in the new boot.
- The privileged socket's ownership was observed before the reboot:
  `srw-rw----  1 root  _wg-basic-serve  0 /var/run/wg-basic/netd.sock` — root
  owned, the management group reachable, nobody else.
- The runtime directory is root-owned and never world-writable:
  `drwxr-xr-x  4 root  daemon  128 /var/run/wg-basic`.
- The management identity was resolved by the directory service and recorded:
  `management identity _wg-basic-serve uid=8998 gid=8998`. The installer
  still never creates an account.
- The helper's digest was checked before every spawn and matched the pinned
  reference `a490f82f540130730f0fde5d10a3e6dab6a4dfa066b94c6968873c8104c69d21`.
- The new wait is a **read-only capability request** over the socket the
  management daemon is already permitted to use. It adds no privilege, opens
  no new channel, and broadens no protocol.
- The new runtime-directory creation is done by the root daemon, for the
  directory it already owns, with the mode the installer already publishes.
  It cannot adopt, widen, or repair a directory it did not create.

## Docs and operations evidence

- `architecture/privilege-boundary.md` — the Darwin service identity, the
  socket ownership contract, the runtime directory's boot-time creation, and
  the management daemon's bounded wait for the privileged daemon.
- `docs/development.md` — the controlled-host cold-reboot leg and what it
  now proves.

## Known limitations

1. **The cold-reboot leg is proven on arm64 only.** The native Intel arch of
   the same leg remains unqualified, because a hosted Intel runner cannot be
   rebooted and no native Intel host is available. C002 therefore stays
   **blocked (narrowed)** on that residual; C006 itself is closed.
2. **The management listener can come up late.** When the privileged daemon
   is not answering, the management daemon waits its bounded budget (ten
   seconds) before its startup attempt, so the listener appears degraded
   after that budget rather than immediately. The wait is what makes a
   concurrent `launchd` start deterministic; the alternative — a
   non-deterministic race — is what made the deployment stay degraded.
3. **The boot-time job's registration lingers in the session.** The verify
   phase removes its own plist and its staged binary, so the job **cannot run
   in a later boot**, which is what the leg requires. Its registration
   nevertheless remained in the session's domain, because
   `launchctl bootout` stops the running job — which is that process — before
   launchd records the unload. The plist removal is the load-bearing part.
4. **The disposable guest is deleted.** The VM bundle, the IPSW and the
   working directory are removed after the evidence is captured, so the
   evidence lives in this record and in the C002 record, not on a host.
5. **No release claim exists.** ADR-008/M007 still withhold every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **High (introduced by C002's implementation, found by this qualification,
  fixed here):** the deployment did not survive a cold reboot on macOS. The
  privileged daemon's runtime directory is under `/var/run`, which macOS
  recreates at every boot, so the privileged daemon could never bind its
  socket in a new boot; it crash-looped on `KeepAlive` and the management
  daemon started degraded with the managed tunnel never converging. The
  privileged daemon now creates its own runtime directory when it is missing.
- **High (introduced by C002's implementation, found by this qualification,
  fixed here):** the management daemon's startup reconciliation raced the
  privileged daemon at boot. `launchd` starts the two jobs concurrently
  (measured 174 ms apart) and the startup attempt's retry budget is short, so
  the race was lost and, with no background reconcile, the deployment stayed
  degraded. The management daemon now waits, bounded, for the privileged
  daemon to answer before its startup attempt.
- **Medium (introduced by this qualification's fixture, found by this
  qualification, fixed here):** the reconvergence wait **panicked** on the
  `503 unavailable` body the management surface answers while the
  deployment is still converging, instead of treating it as "not yet" and
  waiting. The failure it produced looked like a product failure and was
  not one. The wait now retries on a non-JSON body, in every telemetry poll
  of the controlled-host target.
- **Medium (introduced by this qualification's fixture, found by this
  qualification, fixed here):** the arm phase booted the boot-time job out
  with `launchctl bootout system <label>`, which launchctl rejects with
  `Boot-out failed: 5: Input/output error` — after a domain target it
  expects a service *path* or a qualified `system/<label>` target. The
  bootout silently did nothing, so the "the job must not be registered in the
  running session" invariant was not enforced. The service target is now
  qualified, the removal is retried within a bounded window, and the
  invariant is asserted.
- **Medium (introduced by this qualification's fixture, found by this
  qualification, fixed here):** the verify phase removed its own job
  **before** writing its evidence. `launchctl bootout` stops the running job
  — which is the process writing the evidence — so the evidence could never
  be written. The evidence is now written first, the plist is removed next,
  and the bootout is detached into its own process group so it survives the
  job's own termination.
- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job fails
  on three upstream `zip 6.0.0` advisories reached through `eggup-archive =
  "=0.1.3"`. Not resolvable in this repository without an upstream release.
- **Low (environmental, recorded):** the Linux clippy target cannot be built
  on this host without a cross C toolchain (`x86_64-linux-gnu-gcc` is
  absent). The failure is identical on the clean tree at `cdc4439`, and the
  `cargo zigbuild` gate covers the same target.
- **Informational:** the disposable guest's account is `test` and its
  password is the disposable one the maintainer set when enabling Remote
  Login. The guest and its working directory are deleted; nothing about it
  is carried into the product or the repository.

## Disposition

**Closed.** The boot-path defects the C002 cold-reboot qualification exposed
are fixed, and the qualification itself now passes end to end on a disposable
arm64 macOS host with the reboot observed rather than inferred. C002's
disposition becomes **blocked (narrowed)** on the native Intel arch of the
same leg, and C003–C005 are unchanged.
