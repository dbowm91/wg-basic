# Operator parity M001 closure — platform-honest setup

Status: closed.

Implementation commit: none. The work is the uncommitted tree on baseline
`a9b0c06af205b20923f7db350a65379cb176e56e`.
Planning baseline: `a9b0c06`.
Plan: `plans/implementation/operator-parity/001-platform-honest-setup.md`.
Disposition: **closed**. An untouched Linux setup still stores an IPv4 NAT
gateway. An untouched macOS setup stores host-only. The page can show the
existing gateway and routed-LAN prerequisites. The product still does not
write Darwin forwarding or `/etc/pf.conf`.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| A historical setup body, with forwarding or masquerade and no `mode`, stays a gateway on every platform | `historical_setup_stays_a_gateway_and_an_unchecked_setup_is_host_only` in `tests/product_management.rs`. The default setup stores a gateway with masquerade. Forwarding false and masquerade false stores host-only. An explicit gateway mode is accepted. |
| An untouched macOS form does not submit the Linux flags | `src/http/assets.rs` asserts `applySetupDefaults`: Linux sets both checks true, every other platform sets both false and clears egress, macOS uses the `en0` placeholder, and an unknown platform shows the banner. The HTML keeps the Linux `checked` attributes and `eth0`. |
| The authenticated prerequisite route names verdicts and does not invent ready | `prerequisites_name_verdicts_and_do_not_invent_a_ready_state` in `src/management/runtime.rs`. `host_platform` comes from the binary. Linux JSON has no attachment. A macOS-shaped projection carries the three attachment sections. `Ready`, `ForwardingDisabled`, `AttachmentMissing`, and a ready routed LAN are named. Filter rules are capped at 128. Conflict and unsupported are named refusals. A connection refusal is `not_observed`, with no verdict and no refusal. |
| No new privileged opcode and no Darwin write path | `RequestOperation` is unchanged. The route uses the existing `PlanNetworkPolicy` and does not call apply. `tests/architecture_guards.rs` passed all 70 tests, including the closed protocol vocabulary and `the_darwin_gateway_owns_one_anchor_and_never_the_hosts_own_configuration`. This change adds no sysctl write and no `/etc/pf.conf` edit. |
| Docs | `architecture/product-management.md` documents the route, the three forwarding states, the macOS attachment lines, and the two setup defaults. `docs/operations-runbook.md` has "First server setup". |

## Verification performed

Commands run on this x86_64 Linux host, all exiting 0:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 44 suites; 684 passed, 0 failed, 3 ignored
cargo +1.89.0 check --all-targets --locked
cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings
git diff --check
```

The three ignored tests are the pre-existing systemd-installation pair and the
Phase 8 upgrade rehearsal.

`$HOME/wg-toolchain/zigcc` is not installed. This host is already
`x86_64-unknown-linux-gnu`, so the Linux-integration clippy used the host
compiler. That is the typecheck the Darwin zig wrapper exists to provide.

The rootful nftables suite was not run. `tests/network_control_e2e.rs` was not
retargeted: its diff adds `preshared_key: None` on two desired peers. The
historical body is the unprivileged product test above. No controlled-host
macOS qualification was run. The embedded page was not driven in a browser;
the shell contract is the source-contains tests in `src/http/assets.rs`.

## Known limitations

The embedded-shell ceiling moved from 36 KiB to 48 KiB total and from 24 KiB
to 28 KiB for one asset. The inventory is 43,491 bytes. The release footprint
test's 64 KiB assertion was not re-run. C015 is unchanged. This closure does
not claim a macOS release.

## Unresolved findings

None.
