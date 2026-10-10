# Release Readiness R003 — Bootstrap Installer Trust and Root Execution Boundary

Status: **wrapper hardening and high-assurance operator procedure implemented; production acceptance blocked** on R002's real trust root and signed draft. The rootless regression covers the documented verification order and trust labels; the existing Rust signing-handoff fixture now also rejects a wrong key, truncated signature, tampering, wrong product, and wrong release ID.
Repository baseline: `dbowm91/wg-basic@0b814fe` (2026-10-10).
Source roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.
Primary class: invariant / security corrective / operator ergonomics.
Authority: ADR-006 §§6–11, 18; `plans/closure/distribution/003-final-status.md`, `004-status.md`, `005-status.md`.

## 1. Objective

Give operators a genuinely authenticated, reproducible high-assurance first-install path **before executing any downloaded candidate or installer as root**. Preserve a separately labeled convenience installation mode only if its bootstrap HTTPS/GitHub trust limitation is explicit and its implementation remains bounded, auditable, and non-misleading.

## 2. Verified baseline and gap

`release/eggpack/install.sh` has two modes:
- `--candidate PATH --sha256 HEX --size BYTES`: copies a local executable into a temporary private directory, checks supplied size/digest, executes `--version`, and delegates to `wg-basic system install --candidate`. Correctly verifies *integrity against supplied inputs*; it does **not** independently authenticate the source of those inputs or prevent code execution from an operator-provided malicious candidate.
- `--version X.Y.Z`: fetches `https://github.com/dbowm91/wg-basic/releases/download/vX.Y.Z/install-exact.sh`, then runs it as root with `sh`. It still does not verify a detached signature in this convenience mode and implicitly trusts the GitHub/HTTPS delivery channel. Help and stderr now label that trust boundary explicitly; the wrapper fixes `PATH`, ignores inherited `TMPDIR`, and stages in a private `/tmp` directory.
- `scripts/test-release-installer.py` mocks `curl` to return shell script bytes and asserts that the wrapper executes them; it does not check a genuine Minisign-authenticated path or a compromised/malicious bootstrap.
- `docs/installation.md` now gives a full future signed-release command path: independent key installation, manifest and installer signature checks before parsing/execution, exact tag/source and target/hash checks, root-owned staging, and signature/hash rechecks before root execution. The script-order regression ensures these gates precede the root installer call. Production use remains unavailable without actual signed artifacts and independently published trust material.

The current production `PRODUCTION_PUBLIC_KEY=None` protects **self-update** only; it does not authenticate a candidate executed by the first-install script. Do not conflate the two.

## 3. Security invariants

1. An independently obtained and authenticated project Minisign public key/fingerprint is required for the **high-assurance path**. Verify `release-manifest.json.minisig` and `install.sh.minisig` before running any downloaded script or candidate. Manifest checks bind selected platform, exact version, executable hash+size, source commit and supported target.
2. No script or candidate received from a network endpoint is executed with root privileges *before its independent trust decision* in the verified path. A script run under the user account before verification can also be dangerous; prefer read-only tooling over executing any untrusted download.
3. HTTPS-only, no redirect to HTTP, canonical repository/asset names, finite response sizes/timeouts, no arbitrary URL override, no DNS-host-derived package name, no shell eval and no untrusted file path in a shell command.
4. Verify candidate exact ELF/native architecture, `--version` identity and manifest artifact size/digest *before* installation; never call candidate `--version` as root before authenticity is established.
5. Harden local staging against symlink/hardlink/TOCTOU, world-readable VPN state leakage, attacker-chosen `TMPDIR` paths, unexpected relative paths, and unsafe cleanup. Restrict executable paths to a private owner-only directory and refuse unsafe inherited environment where feasible. Root delegated install remains subject to `system install`'s exact owned-artifact checks.
6. If retaining the convenience path, label it clearly "HTTPS/GitHub bootstrap trusted; not independently end-to-end authenticated" in script help/docs. Treat unauthenticated executable bootstrap as an explicit lower-assurance choice, not the default description of a "verified" release installer.
7. No new package manager, broad Bash execution feature, external arbitrary artifact URL selector, automatic privilege escalation, or changes to native systemd/SQLite ownership model.

## 4. Ordered work packages

### WP1 — Document threat model and canonical install recommendation

Define attacker controls: compromised release asset/CDN, compromised GitHub draft publisher, altered local download, modified or spoofed unsigned checksum sidecar, malicious `PATH` helper, executable candidate replacing bytes between validation/install, and a user copying the wrong public key from the same compromised channel. For each, document the assurance provided by detached signature, exact artifact digest, signed source revision, and out-of-band key fingerprint.

Recommend an exact signed high-assurance installation procedure. It MUST be usable on a fresh Linux x86_64/aarch64 system before installing wg-basic and without a program key embedded in the downloaded executable. State clearly that obtaining a public key only from the same site as a compromised installer is not a sufficient independent trust anchor.

### WP2 — Implement high-assurance verification path

Provide a small documented verify-only operator flow (script or README commands) that downloads expected manifest, `.minisig` files, target binary and checksum; bounds/validates them; verifies the production Minisign signatures against the independently authenticated key; validates manifest source/release/product/target and exact size/SHA256; then invokes the authenticated candidate under the required privilege boundary only after successful verification. Prefer simple external Minisign + standard platform utilities; do not reimplement Ed25519 in shell.

If an installer helper is developed, it must not execute downloaded scripts in order to perform verification. Ensure no unverifiable local trust input makes the "verified" branch silently fall back to convenience behavior. If `install-exact.sh` is generated by Eggpack and needs modification, make a bounded **upstream Eggpack-owned** change and repin/regenerate product contract; never manually fork a generated script as the canonical producer output.

### WP3 — Review and harden existing wrapper

Review `release/eggpack/install.sh`, `release/eggpack/installer-presentation.json`, product `install-policy.toml`, and native candidate handling for:
- robust argument/version/size/digest validation;
- secure temporary directory creation and cleanup, symlink/nonregular-file rejection and race resistance;
- `PATH` helper selection and untrusted inherited environment as root;
- clear separation of integrity check from authenticated origin;
- exact shell exit on failure, no fallthrough into ordinary unverified downloads;
- explicit installer origin, no substitutions in release URL, bounded curl redirects, no downgrade;
- no unsupported Windows/PowerShell route despite generated assets;
- no accidental logging of admin password, DB keys, or signed private material.

Minimize code changes. If the convenience script remains intentionally lower assurance under ADR-006, do **not** falsely mark it as independently signed merely because the manifest is checked by another tool later.

### WP4 — Adversarial tests with controlled rootless fixtures

Extend `scripts/test-release-installer.py` and add a verified installer fixture with ephemeral Minisign keypair under test-only paths. Negative controls:
- wrong/out-of-band key, tampered signed manifest or installer, mismatched tag/source revision, changed ELF target, wrong size/hash, absent signature, additional/duplicate archive entries;
- candidate symlink/hardlink, replaced staging file, nonexistent/unreadable candidate, malformed version/size and unsafe `TMPDIR`;
- insecure redirect/HTTP URL, path command substitution, fake `curl` helper, candidate `--version` exiting unusually, download timeout/partial result;
- untrusted convenience path correctly annotated, high-assurance path **never executes any unverified fixture script**, and only a verified candidate reaches product install.

Use fake `system install` entrypoint or disposable systemd host to prove the execution boundary; never run destructive installers against a development host as part of routine unit tests. On signed production draft availability, perform real installed binary qualification on disposable native x86_64 and aarch64 machines.

## 5. Failure/retry/restart semantics

Any verification error aborts without launching scripts/binaries or modifying systemd, users, install receipt or DB. Retry starts from a fresh private staging dir with no stale partial files silently trusted. A failed native install keeps the existing exact-owned installation safe and reports actionable diagnostics. `uninstall` continues to preserve secret-bearing state by default.

## 6. Compatibility, security and external responsibilities

Do not change the source WireGuard protocol, management API, SQLite schema, service privileges, or existing Eggup transaction interface. Producer script generation belongs to Eggpack; high-assurance project operator UX/authenticity belongs to wg-basic. Project-owned Minisign public trust root is operationally gated on R002; fixture-only tests may implement a fake signed flow but MUST NOT authorize production release.

## 7. Tests and verification

```text
python3 scripts/test-release-installer.py
python3 scripts/test-signing-request.py
python3 scripts/test-release-smoke.py
python3 scripts/test-verified-install.py
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo audit
git diff --check
```

Repeat Eggpack generated installer/workflow drift checks and `distribution-foundation` on exact qualified source. Run actual freshly installed program+health on native supported runners. Verify that installer smoke uses the exact release artifact; do not claim signature verification for unsigned/fake fixtures.

## 8. Documentation, acceptance and stop

Update `docs/installation.md`, `README.md`, `release/eggpack/install.sh` help, `docs/release-signing.md` (R002), `plans/subsystems/release-readiness-security-roadmap.md` and `plans/registry.md` after implementation. Preserve historical M002–M005 closures.

R003 technical closure requires the documented authenticated high-assurance command path, regression evidence that signature checks precede downloaded-code execution, truthful convenience-mode trust description, source/target/version/digest binding, staging/path safety, and complete old native systemd install/uninstall/rollback regression. Its **production** acceptance requires the real R002 public key and valid signed release artifacts; maintain a separate blocked operational status until available.

Stop if no independent out-of-band public-key distribution exists, verification can be bypassed by fallback, generated installer changes need an unqualified upstream Eggpack revision, a file mutation race invalidates verification before exec, or an unverified candidate executes under root in the purported high-assurance path.

## 9. Closure evidence

Write `plans/closure/release-readiness/003-status.md` with exact fixture and real-draft evidence differentiated, before/after adversarial results, source/release asset mapping, script trust labels, native host/CI runs, producer-owned changes, unresolved risks, and R004 readiness. Do not claim public release if trust root or signed draft remains absent.
