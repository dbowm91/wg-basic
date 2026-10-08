# Operational Hardening M004 — Abuse, Security, and Dependency Qualification

Status: closed

Source roadmap:

- `plans/subsystems/operational-hardening-roadmap.md#8-m004--abuse-and-security-qualification`

Canonical architecture:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

Primary class: security / adversarial qualification

Hard dependency: Operational Hardening M003 strict closure.

## 1. Objective

Perform the pre-release adversarial review of the complete IPv4 appliance without changing its product scope.

M004 is evidence-first: exercise the existing HTTP, worker, state, privileged IPC, nftables, enrollment, and ownership boundaries under malformed and abusive input, then correct defects found.

## 2. Threat classes

Review at least:

- unauthenticated remote/browser client;
- authenticated administrator making malformed/stale requests;
- brute-force login attacker;
- one-time-enrollment token attacker;
- unauthorized local Unix-socket peer;
- compromised process running as the authorized management UID;
- local root, which is outside confidentiality/availability protection but must not create false product claims;
- accidental operator conflict with foreign WireGuard/nftables state.

Document what each actor can and cannot be expected to achieve.

## 3. HTTP framing/resource abuse

Use real TCP/EggServe where possible.

Qualify:

- connection churn beyond 64-connection ceiling;
- request concurrency beyond configured in-flight ceiling where the workload can actually make it binding;
- slow/incomplete headers;
- slow/incomplete bodies;
- header count exactly 32 and 33;
- header bytes at/over 8 KiB;
- target at/over 1 KiB;
- body at/over route/global ceilings;
- keepalive request count around 256;
- total connection lifetime;
- malformed request syntax handled by transport;
- invalid/duplicate Host;
- duplicate/conflicting Origin;
- oversized/malformed JSON;
- invalid UTF-8 where applicable;
- repeated unknown routes and resource IDs.

Do not use flat wall-clock assertions that merely benchmark CI speed. Assert configured deadlines/admission outcomes.

## 4. Authentication abuse

Use deterministic limiter time/seams.

Qualify:

- global login budget;
- raw-peer login budget;
- bounded peer-cardinality map;
- dummy Argon2 path for unknown user;
- limiter runs before Argon2;
- session cap/oldest-session eviction from M003;
- repeated password reset/session revocation;
- no persistent attacker-controlled lockout.

Record CPU/memory cost under admitted versus rejected attempts.

## 5. Enrollment abuse

Qualify:

- high-volume wrong-token attempts;
- global/raw-peer enrollment limiter;
- wrong token never consumes;
- scanner GET never consumes;
- exact one successful consume;
- replay refused;
- expired/revoked/deleted-client token refused;
- live-capability per-client cap;
- terminal-row housekeeping;
- URL fragment secret absent from server request target/logs/audit;
- no CORS/cross-origin consume.

## 6. Product/generation races

Drive concurrent authenticated mutations with the same expected generation.

Prove:

- exactly one valid generation transition wins where requests conflict;
- stale requests return 409/pre-commit conflict;
- no duplicate client address allocation;
- no duplicate client/peer IDs;
- audit remains consistent;
- committed-but-not-enforced semantics remain truthful during backend outage.

Exercise create, address reassignment, disable/delete, and network operational disable where relevant.

## 7. Privileged UDS framing abuse

Qualify real Unix-socket behavior for:

- unauthorized peer rejected before payload parse;
- zero frame length;
- frame >64 KiB rejected from header before payload allocation;
- truncated 4-byte length;
- truncated payload;
- malformed JSON;
- unknown protocol version;
- unknown/invalid typed fields;
- slow header/payload reaching the 2-second I/O bound;
- connection backlog pressure;
- repeated connect/disconnect;
- response write peer disappearance.

After malformed peers, a legitimate management request must still succeed.

## 8. Authorized-local-UID DoS analysis

Because netd deliberately serves one request at a time, an authorized same-UID process can repeatedly hold a connection until the I/O timeout.

Measure and document:

- maximum per-connection stall;
- recovery after the connection closes/times out;
- whether backlog/resource usage remains bounded;
- whether repeated authorized stalls can indefinitely deny the legitimate management service.

Do not overstate mitigation: a compromised dedicated management UID is already inside the trusted local control domain, though the typed protocol must still prevent privilege escalation beyond intended network actions.

If the measured availability risk is judged high/medium for the deployment, correct it before closure through a narrower timeout/admission design without introducing concurrent privileged mutations.

## 9. Privileged operation review

Review every `RequestOperation` and prove there is still no:

- generic exec;
- arbitrary file read/write;
- arbitrary sysctl path;
- raw nft source from caller;
- raw netlink message;
- shell command;
- caller-selected executable.

Fuzz/fixture malformed typed operations through decode/validation and prove mutation is not reached.

## 10. nft subprocess review

The only production process execution remains the bounded nft backend.

Review:

- executable selection/path policy;
- argv fixed/bounded;
- stdin generated internally;
- no shell;
- no client label/HTTP string can become nft syntax without typed rendering/validation;
- stdout/stderr/time/output bounds;
- failed nft apply preserves firewall-first disable invariants.

Add static guards for `Command::new` locations.

## 11. Ownership preservation

Against real namespaces/nftables:

- foreign same-name interface;
- foreign owner tag;
- duplicate owner tag;
- foreign `inet wg_basic` marker;
- unrelated routes/addresses/tables;
- malformed/rejected requests.

No rejected/abusive input may broaden deletion ownership or mutate unrelated state.

## 12. Secret exposure review

Seed a recognizable secret corpus:

- password;
- PHC verifier;
- server private key;
- client private key;
- PSK;
- session token;
- CSRF token;
- enrollment token;
- complete exported config.

Exercise:

- human logs;
- JSON logs;
- audit API;
- doctor human/JSON;
- CLI errors;
- HTTP generic errors;
- process argv;
- child-process environment where applicable.

Assert secrets do not appear except in the explicitly requested config/QR/enrollment artifact body.

State DB/backups are intentionally secret-bearing and excluded from the “must not contain” scan.

## 13. Filesystem/socket permissions review

Qualify current modes/ownership:

- state DB 0600;
- backups/recovery snapshots 0600;
- state parent not group/world writable;
- serve lease safe;
- netd runtime directory safe;
- netd socket 0660 with peer credential authorization;
- symlink substitution rejected;
- purge/restore do not follow unsafe paths.

## 14. Dependency advisory gate

Add a dedicated CI security check.

At planning time the current cargo-audit release is 0.22.2.

Preferred CI model:

- install/run a pinned cargo-audit tool version under its own suitable toolchain;
- audit the committed `Cargo.lock`;
- do not change wg-basic's Rust 1.89 MSRV merely because the audit tool itself tracks newer Rust;
- record advisory DB/tool version in CI output where practical.

Also run/record:

```text
cargo tree --locked
```

Review direct dependencies and enabled features.

An advisory may be explicitly dispositioned only with evidence that it is not applicable/reachable; do not blanket-ignore advisory classes.

## 15. SQLite advisory/runtime check

Confirm in CI/doctor evidence:

- runtime SQLite version/source;
- version is beyond 3.51.2 WAL-reset affected range;
- WAL + FULL synchronous remain configured;
- only the intended management connection owns ordinary write authority.

No forced SQLite upgrade if the locked bundled version already satisfies the security requirement.

## 16. Security review record

Create a Phase 9 threat/security report capturing:

- attack surface;
- finding severity;
- exploit preconditions;
- corrective commit;
- verification;
- accepted low/informational residual risks.

Phase 9 cannot close with unresolved high/medium findings.

## 17. Tests/CI

Add deterministic adversarial suites rather than one monolithic slow test.

Suggested targets:

- `http_abuse`;
- `protocol_abuse`;
- `security_secret_scan`;
- rootful ownership abuse cases in existing/new target.

Keep total runtime bounded.

## 18. Acceptance criteria

M004 closes only when:

1. HTTP limits/deadlines are load-bearing under real malformed/slow clients;
2. login/enrollment limiters are deterministic and pre-expensive-work;
3. generation races cannot duplicate/corrupt product state;
4. privileged framing survives malformed/slow/unauthorized peers;
5. no generic privileged escape hatch exists;
6. nft subprocess remains bounded/non-shell/internal-rendered;
7. unrelated host state survives abusive/rejected inputs;
8. secret corpus does not leak to logs/audit/doctor/errors/argv;
9. dependency advisory gate is active and dispositioned;
10. no unresolved high/medium finding remains;
11. all ordinary/MSRV/rootful product tests remain green.

## 19. Stop conditions

Stop/write a corrective if an abuse test reveals an ownership expansion, secret disclosure, privilege escalation, unbounded allocation, limiter bypass before Argon2/token lookup, or an unresolved advisory affecting a reachable privileged/security path.

## 20. Closure evidence

Record threat matrix, HTTP/UDS abuse outcomes, authorized-UID DoS disposition, generation-race evidence, nft/process review, secret scan, filesystem permissions, cargo-audit version/results/dispositions, SQLite runtime, CI/MSRV, and M005 readiness.
