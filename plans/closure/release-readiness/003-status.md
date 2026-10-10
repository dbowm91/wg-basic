# Release Readiness R003 — Conditional Technical Closure

Disposition: **conditionally closed for repository engineering; production verified-install blocked**.
Implementation commit: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Repository baseline: `0b814fe` (`2026-10-10`).
Repository implementation head: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Source plan: `plans/implementation/release-readiness/003-bootstrap-installer-trust-and-root-execution-boundary.md`.
Roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.

## Evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Separate integrity from authenticity | Wrapper help and lower-assurance stderr warning; README and install docs call out HTTPS/GitHub bootstrap trust | Pass |
| Harden local candidate handling | Fixed system `PATH`, fixed private `/tmp` stage, no inherited `TMPDIR`, regular executable and single-link checks, copied candidate size/hash/version check | Pass |
| High-assurance trust ordering | `docs/installation.md` verifies manifest and installer signatures before parsing or executing, compares tag/source/Cargo identity, validates target/size/hash/ELF/version, copies into root-owned stage and rechecks before root execution | Documented path passes ordering regression |
| Signed fixture mechanics | `tests/release_signing_handoff.rs` makes ephemeral Minisign signatures for the exact manifest and installer bytes and tests wrong-key, truncated signature, tampering, wrong product, and wrong release ID | Hosted Rust suite passed |
| Native systemd regression | Hosted Distribution Foundation run covers x86_64 and aarch64 candidate install/uninstall/reinstall lifecycle | Pass |
| Production signed install | No production public key or signed artifact exists | Blocked, no production claim |

## Exact verification run

- Local `python3 scripts/test-verified-install.py`: passed signature-before-root
  command-order and trust-label checks.
- Local `python3 scripts/test-release-installer.py`: passed mocked lower
  assurance delegation, no-network candidate path, wrong digest rejection,
  symlink/hardlink rejection, and inherited `TMPDIR` rejection.
- Local `sh -n release/eggpack/install.sh`: passed.
- Hosted [CI run 38022851605](https://github.com/dbowm91/wg-basic/actions/runs/38022851605): all jobs passed at the implementation SHA.
- Hosted [Distribution Foundation run 38022853831](https://github.com/dbowm91/wg-basic/actions/runs/38022853831): native candidate and systemd lifecycle jobs passed for both GNU targets.
- No production key or signed draft was used; no first-install was run against a live host.

## Security and limitations

The `--version` wrapper path still downloads and executes the generated
`install-exact.sh` as root without detached signature verification. It is
explicitly labeled lower assurance and remains a convenience option under
ADR-006. The recommended high-assurance command sequence independently obtains
the trust key, verifies both signed metadata and installer, validates
source/tag/artifact identity, stages exact bytes root-owned, then runs the
verified installer and candidate.

The automated high-assurance regression checks command ordering and the Rust
fixture checks detached-signature cryptography; the exact shell procedure has
not yet consumed a real production-signed draft because the production key and
assets are absent. R002 key custody, signed artifacts, and native signed
first-install evidence remain operational blockers.

## Findings and handoff

- RF-04 lower-assurance network bootstrap remains intentionally available and
  is clearly labeled (High consequence if misrepresented; accepted limitation
  under ADR-006).
- RF-05 production signed-install/lifecycle evidence is absent (release gate).

R004 remains blocked until a real R002 key and signed draft are independently
verified and this path is run on disposable supported native hosts.
