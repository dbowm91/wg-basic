# S001 Closure — Typed interpreter and admission corrective

Status: **closed** (2026-11-16).

Planning baseline: `plans/implementation/security-audit/001-typed-interpreter-and-admission-corrective.md`.
Repository baseline at implementation start: `2c38726`
(`Keep the owned NetNAT name inside WinNAT's 80-byte key.`).
Final implementation head: `797e466`.
Disposition: **closed**.

## Outcome

S001 restores the typed-interpreter contract at the three places the
2026-11-16 security audit found incomplete:

1. **D1 — Darwin PF interface tokens.** `render_policy` and
   `render_routed_policy` refuse any interface name that is not one PF
   token (`[A-Za-z0-9._-]`, 1–15 bytes, not `.` / `..`) before producing
   rule text. Gateway install maps that refusal to `InvalidPolicy` and
   does not write the anchor file or spawn `pfctl`.
2. **D2 — Absolute `nft`.** Linux `netd` selects `/usr/sbin/nft` then
   `/sbin/nft`, accepting only a regular, executable, non-symlink file.
   `PATH` is never consulted.
3. **D3 — Separate `/healthz` admission.** Unauthenticated liveness has
   its own token-bucket budget, checked before the management worker
   queue. A spent health budget returns the existing `503 unavailable`
   answer and leaves login/mutation admission untouched.

No historical closure was edited. No schema or protocol change.

## 1. Requirement-to-evidence matrix

| Criterion | Evidence |
|---|---|
| 1. Renderers refuse `!en0`, brace lists, quotes, `;`, `#`; accept `en0` / `utun4` | `src/firewall/pf.rs` unit tests `pf_interface_tokens_accept_ordinary_names_and_refuse_operators`, `both_renderers_refuse_a_pf_operator_interface_name` |
| 2. Darwin gateway apply does not spawn `pfctl` / replace the file on refusal | `src/firewall/service_darwin.rs` `install_gateway_anchor_refuses_a_pf_operator_before_pfctl` (Darwin-gated by module `cfg`) |
| 3. Successful render stays C004 rule order, IPv4-only NAT | Existing PF renderer / anchor-file order tests remain green |
| 4–5. Absolute `nft` pin; quoting / version / bounds unchanged | `nft_path_selection_accepts_only_pinned_absolute_regular_executables`; architecture guard `the_nft_backend_spawns_exactly_nft_and_never_a_shell`; existing nft unit tests |
| 6. Saturated health budget still admits login; body stays two tokens | `tests/authenticated_api.rs` `a_saturated_health_budget_still_admits_login` |
| 7. Login throttling still before Argon2 | `limiter_before_hashing` still green |
| 8. `cargo test --locked` | §3 below |
| 9. Architecture pages match | `architecture/firewall.md`, `management-http.md`, `privilege-boundary.md`, `reconciliation.md`, `testing-qualification.md` |
| 10. No historical closure edited | Diff confined to S001 plan/registry/closure and product/docs/tests |

## 2. Commits

- Baseline: `2c38726`
- Implementation + docs + this closure: `797e466`
  (`Close S001: refuse PF operator names, pin nft, isolate healthz admission.`)

## 3. Verification commands actually run

On Linux host `linux 6.8.0-147-generic`, 2026-11-16:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

All five completed successfully. `cargo test --locked` reported no failed
suites.

Rootful suites were re-run after the absolute-`nft` pin forced the
PATH-based failure fixtures to be rewritten as pinned-path overlays:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CI=true \
  cargo test --locked --features linux-integration --test durable_restart \
  a_failing_firewall_blocks_the_disable -- --test-threads=1
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CI=true \
  cargo test --locked --features linux-integration --test network_control_e2e \
  three_namespace_wireguard_forwarding_nat_restart_and_preservation \
  -- --test-threads=1
```

Both passed on this host. D2's PATH claim remains closed by the unit test of
path selection; the rootful suites prove live nft still works under the pin
and that fault injection still reaches the shipped disable/apply paths.

Cross-target `linux-integration` clippy was not run: the Zig cross
toolchain (`$HOME/wg-toolchain/zigcc`) is absent on this host. Shared
`InterfaceName` was not tightened globally.

## 4. Security / ownership effects

- Privileged Darwin surface narrower: PF-operator interface names fail closed.
- Privileged Linux surface narrower: only pinned absolute `nft` paths execute.
- `serve` gains no privilege. `/healthz` stays unauthenticated with the same
  two body tokens; shed probes use the existing unavailable status.

## 5. Known limitations

- Darwin apply-path refusal proof is structural + unit-level
  (`InvalidPolicy` before `pfctl::install_anchor`). No live `pfctl` packet
  capture was required by the plan and none was run.
- Health admission uses a rate limit (Package C shape 2), not a second
  worker queue. Capacity is 8/8 (global/peer) with matching refill.

## 6. Unresolved findings

None for S001. C015 and other registry items are unchanged.
