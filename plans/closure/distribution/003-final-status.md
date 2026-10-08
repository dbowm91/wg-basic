# Distribution M003 Closure — Eggpack Release Pipeline and Signing Handoff

Status: closed — mechanically qualified; production signing and public release remain pending.

Source plan: `plans/implementation/distribution/003-eggpack-release-pipeline-and-signed-draft.md`

Roadmap: `plans/subsystems/distribution-install-update-roadmap.md`

Implementation commits: `26e1cdb`, `2cb569d`, `af75aa7`, `0e99424`, `7806a95`, `3fc8ba3`, `568d568`.

Final implementation head: `568d56889d64aba2bea806b58ae24415dc01ac8e`.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Pin a compatible Eggpack producer and keep generated workflow in sync | Eggpack is pinned to `d61ca71fc0112be63e7e8ba31ba8fa2b1ce5a628`; release workflow is generated from committed policy/shape inputs; release-contract job checks generator drift and `eggpack ci check`. Run [37853066003](https://github.com/dbowm91/wg-basic/actions/runs/37853066003) passed. | Pass |
| Bind stable tag, source revision, Cargo version, and manifest release identity | Upstream identity mode `v_prefixed_stable_semver` retains tag, source revision, and unprefixed stable manifest ID independently. Upstream corrective evidence is in `003-unblock-review.md`; disposable `v0.1.0` tag check resolved the ID and source revision, and the temporary tag was deleted. Consumer validation compares Cargo source version, candidate `--version`, and Eggpack runtime `release_id` before aggregation/staging. | Pass |
| Build and execute both canonical GNU targets at the declared glibc floor | Both native `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` release-candidate lanes passed on final producer workflow run [37853066003](https://github.com/dbowm91/wg-basic/actions/runs/37853066003). Earlier recorded native qualification run [37851666978](https://github.com/dbowm91/wg-basic/actions/runs/37851666978) measured x86_64 at 9,746,552 bytes, SHA-256 `13de491eaba9f992581adad16265e8c4c2efbd309068d9985cf464af426bb1f9`, and aarch64 at 8,937,792 bytes, SHA-256 `6be174d571bd035ab669182e58046fb6a4005c4dc0f1f34f4ef3421211b5a010`; both had maximum GLIBC symbol 2.17. | Pass |
| Validate the staged signing receipt and exact artifact inventory | `scripts/verify-signing-request.py` checks identity, inventory, sizes, digests, checksum sidecars, and optional detached signatures; `scripts/test-signing-request.py` covers malformed/mismatched receipts. `tests/release_signing_handoff.rs` creates an ephemeral test-only key, verifies exact manifest/installer bytes through production verification code, and rejects tampering. No production key enters CI. | Pass |
| Generate an installer that delegates to M002 and preserves the trust boundary | Eggpack generated bootstrap and product wrapper are checked in. `release/eggpack/install.sh` supports HTTPS exact-version convenience install and high-assurance preverified local-candidate mode; the latter validates exact signed-manifest size, SHA-256, and version from a private root-owned copy before delegating to `system install`. `scripts/test-release-installer.py` passed both mocked modes and asserted the local-candidate path made no network request. The convenience path has an explicit trust limitation. | Pass |
| Keep draft staging non-publishing and tag-safe | The pinned generated workflow requires an existing exact stable tag, validates source/tag identity, uses draft policy, and never creates or moves a tag or automatically publishes. Workflow generation and policy checks passed. No remote stable release tag existed during closure, so no real GitHub draft was staged. | Mechanically qualified |
| Preserve prior Rust, rootful, upgrade, and advisory gates | Full CI [37853066011](https://github.com/dbowm91/wg-basic/actions/runs/37853066011) passed: Rust, system-install-systemd, old/new upgrade rehearsals, product rootful, network/kernel, maintenance, and dependency-audit jobs. Local gates recorded during implementation: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (543 passed, 3 ignored), Rust 1.89 locked check, and `cargo audit` all passed. | Pass |

## Security and operational disposition

- No production Minisign private key or provisioned production trust root is present. Fixture signing qualifies mechanics only.
- The remote repository had no stable release tag at closure, so an actual draft, maintainer signature upload, and re-download verification were not performed. The generated path is configured and policy-checked; the first use requires an already-pushed stable tag and maintainer operation.
- No public release was created or published. The convenience bootstrap is HTTPS transport, not self-authenticating. The documented high-assurance process requires independent script and manifest signature verification.
- No high or medium M003 implementation finding remains open.

## M004 readiness

M003's implementation dependency is closed. M004 is **ready** for fixture-backed implementation. Production update must remain disabled until the maintainer provisions the production public key. M005 remains blocked on M004 closure.

Disposition: **closed — mechanically qualified / production signing pending**.
