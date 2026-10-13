# macOS Native Server M002 — Darwin Privileged IPC, Identities, and Capability Discovery

Status: **closed** (`96075b5`; closure `plans/closure/macos-native-server/002-status.md`, 2026-10-13)
Primary class: invariant / infrastructure
Source: plans/subsystems/macos-native-server-roadmap.md M002
Baseline: main 47c72b0e81d569d48396c615120453bf0cf1d46e (2026-10-11); rebase/revalidate against actual implementation head before applying.
Canonical: plans/000-long-term-specification.md; plans/002-long-term-roadmap.md; plans/003-planning-process.md; plans/adr/008-macos-headless-platform-backends.md; Linux ADR-001–007 are preserved.
Dependencies: M001 strict closure; M002 becomes ready only after accepted backend and compiled shared protocol contracts.

## 1. Objective

Port netd's narrow, authorized Unix-domain request/response service to macOS with real kernel-derived peer credentials, correct socket ownership, bounded framing, and honest capability probes. Prove unprivileged serve cannot perform privileged operations directly.

## 2. Non-goals

No tunnel provisioning, interface/route mutation, PF, launchd installer or blanket root execution fallback. No reliance on Linux SO_PEERCRED or Linux capabilities as Darwin evidence.

## 3. Repository evidence

src/protocol/socket.rs assumes nix sockopt::PeerCredentials (SO_PEERCRED), hardcodes Linux backend instances, runtime directory ownership, stale UNIX socket cleanup and one-frame 64 KiB messages. src/protocol/capability.rs reads /proc/self/status CapEff and /proc/sys/kernel/osrelease. src/protocol/auth.rs authorizes current user/root plus UID allowlist. Linux service contract assumes dedicated netd/serve service users and Unix socket groups.

## 4. Invariants

- Darwin authentication derives peer effective UID/GID from the accepted stream's kernel credentials, not request content, pid files or socket path labels.
- A process with netd authority never opens SQLite, HTTP listeners or arbitrary commands.
- Unsafe socket parent, foreign socket, symlink, owner mismatch and stale inode race fail closed; teardown only removes owned inode.
- Exact framing, versioning, limits and operation authorization stay compatible for existing Linux users.
- Health distinguishes missing process, auth rejection, unsupported capability, and backend failure.

## 5. Ordered implementation packages

1. Select a safe, audited getpeereid binding/wrapper (the Apple documented API), gated to Darwin; confirm if nix already supplies adequate safe abstraction. If FFI unsafe is unavoidable, isolate audited unsafe in a tiny OS boundary via explicit ADR/lint exception rather than weakening crate-wide forbid(unsafe_code).
2. Create portable socket peer-identity and capability observation traits while keeping Linux SO_PEERCRED implementation intact. Enforce explicit allowlisted Darwin service UID and group, not automatic blanket local-user trust.
3. Port protected runtime socket directory/permissions; reject unsafe parent chains, foreign sockets and symlink attacks, preserve bind/cleanup inode checks. Verify macOS filesystem semantics and effective/group identity behavior.
4. Produce Darwin backend capability snapshot (utun permission, helper availability as unknown until M003, PF attachment as unknown until M005, route capability) without mutation. Represent unavailable and untested separately.
5. Build native macOS netd + serve loopback integration fixtures with real OS accounts, bogus peers, races, SIGTERM, stale socket rebind and daemon restarts.

## 6. Privilege, secrets, and host ownership

One privileged local socket with os-verified peer id and one bounded operation per connection. Recheck kernel credential on every connection; no generic operation names, paths or files in wire values. Root privileges must be isolated to netd only; use dedicated unprivileged management UID. Avoid opening network listener from netd.

## 7. Storage, protocol, compatibility and runtime failures

Do not change serialized request/response protocol format to add Darwin details unless version negotiation/mixed-version error tests accompany it. Capability data can gain additive optional fields; no fake Linux CapEff. A restart with a bound socket must not accidentally adopt foreign instances. Authorization and cancellation do not leave mutating tasks running outside the bounded service.

## 8. Focused and integration tests

- Native Darwin permitted UID, disallowed UID, spoofed fields, invalid version, huge frame, partial write/timeouts, parallel client attempts, malformed JSON, and forged socket paths.
- Real symlink/stale inode/foreign socket ownership preservation; compare device/inode/uid before unlink.
- Reboot/launchd is M006; M002 runs both processes manually with documented explicit identities.
- Linux socket, protocol, doctor, aggregate fixtures all remain green; run source-boundary anti-command-injection guards.

## 9. Verification, documentation, and closure

Run native cargo fmt/check/clippy/test plus Darwin privileged IPC fixture on a controlled machine, recording current OS build, identity assignments and command output. Update architecture/privilege-boundary.md and docs/development.md only for actually implemented Darwin behavior; leave launchd docs future tense until M006.

## 10. Acceptance criteria

- Authorized serve-to-netd communication works on native macOS; unauthorized local user consistently refused.
- Netd cannot be used as generic shell/PF/route/file/sysctl proxy; bounded framing and cleanup semantics proven.
- Doctor correctly reports Darwin capabilities and unsupported backends without Linux error messages.
- Native Darwin fixture and all Linux privileged protocol suites pass.

## 11. Stop conditions

If no safe kernel credential API can be used without uncontrolled unsafe code; UID mapping is ambiguous; socket ownership can be bypassed; or netd needs to operate as an HTTP service, stop for ADR/security review.

Closure record: plans/closure/macos-native-server/002-status.md, authored only after implementation and evidence. Record commit/PR, baseline and final head, passed/failed exact commands, native host/kernel traffic, foreign-state snapshots, security findings, documentation diffs, and strict disposition.
