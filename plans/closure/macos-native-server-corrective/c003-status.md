# macOS Native Server C003 — Explicit routed-LAN mode without NAT

Disposition: **conditionally closed** (2026-10-22) — the routed-LAN contract is
implemented and qualified on a controlled host with real IPv4 and IPv6 traffic
in both directions through the tunnel, the operator-managed filter is observed
rather than written, and every missing prerequisite has its own named refusal.
The two conditions are the two findings below that belong to the service
lifecycle line (C001/C002) rather than to the routed-LAN contract, and the
third is an operational prerequisite that is now documented.

Date: 2026-10-22.

Source plan: `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md`.
Corrective roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md`
(C003).
Baseline: `plans/macos-native-support@92af9f5`.
Implementation head: `56752b8` — *macos(c003): add the routed-LAN
mode and its Darwin firewall contract*, on top of `92af9f5`.

## 1. What was implemented

The plan asks for an intentionally bounded routing capability: VPN clients reach
administrator-approved downstream LAN subnets, without NAT, without changing
the host default route, and without a routed LAN being mistaken for an
Internet-exit gateway.

1. **A typed mode contract.** `NetworkPolicyMode` is `host_only`,
   `routed_lan`, or `gateway`. `routed_lan` carries the approved destination
   prefixes and the observed egress interface; `gateway` is refused on Darwin
   (it is C004's subject) and `routed_lan` is refused on Linux. The domain
   layer rejects a default route, a destination the tunnel pool cannot carry,
   a missing egress interface, and a prefix family the pool does not hold.
   The state carries the mode in schema version 8
   (`src/state/migrations/008_routed_lan_mode.sql`); Linux keeps its
   `host_only` default.
2. **Forwarding prerequisites.** The product reads `net.inet.ip.forwarding`
   and `net.inet6.ip6.forwarding` and never writes them. A policy that needs a
   family whose forwarding is off is refused with
   `ForwardingDisabled`; it never falls back.
3. **Return-path proof.** The approved destinations must be reachable through
   the declared egress interface by a specific route — never the default route
   — and the tunnel pool must have an observed route scoped to the managed
   device. A missing or ambiguous route is refused with
   `MissingReturnRoute` or `RouteConflict`.
4. **An operator-managed filter.** The product writes no PF state. It observes
   a bounded, read-only view of the operator's anchor
   (`src/firewall/pfctl.rs`), renders the rules the operator has to install
   (`src/firewall/pf.rs`), reports them on the doctor check as structured
   `required_filter_rules`, and refuses with `FilterMissing` or `FilterDrift`
   when the installed anchor is absent or does not match. The rendered policy
   is bidirectional: the pool's traffic to the approved destination *and* the
   approved destination's own traffic back to the pool, each pair bound to the
   managed tunnel device and to the egress interface, per address family.
5. **State and recovery.** The doctor distinguishes `forwarding disabled`,
   `filter missing`, `filter drift`, `missing return route`, `route
   conflict`, `unsupported topology`, and `tunnel unavailable`, each with its
   own remediation. The product refuses stale convergence: a helper that is
   gone, a device that was renumbered, a peer or prefix that was removed, or
   a route that changed all produce a refusal rather than a readiness claim.

## 2. Requirement-to-evidence matrix

Every row is a requirement of `c003-routed-lan-no-nat.md`. The evidence column
names the artifact in the controlled-host run that satisfies it.

| Requirement | Evidence |
|---|---|
| Typed mode contract; `host_only` distinct from explicit `routed_lan`; allowlist of destination prefixes and a specific observed egress interface | `src/domain/state.rs` (`NetworkPolicyMode`, `DesiredNetworkPolicy`, 13 `StateValidationError` variants); migration `008_routed_lan_mode.sql`; schema version 8; `src/state/store/desired.rs`; `src/state/projection.rs`. Unit tests in `src/domain/state.rs`; migration round-trip in `tests/state_store.rs` |
| Reject default routes, overlapping/conflicting foreign routes, spoofed peer sources, unsupported interfaces, ambiguous L2/L3 topology | `src/domain/state.rs` validation; `src/firewall/service_darwin.rs::observe_routes` (`require_destination_route` refuses a default route; a route on another interface is `RouteConflict`; two routes for one pool are ambiguous); the controlled-host negatives "a foreign or ambiguous route covers an approved destination" and "the approved destinations are not reachable through the declared egress interface" |
| Read and surface `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`; require administrator enablement; do not adopt or revert shared settings; refuse ready when missing | `src/firewall/service_darwin.rs::require_forwarding`; the product never writes a sysctl — the run's own `sysctl -w net.inet.ip.forwarding=0` and `net.inet6.ip6.forwarding=0` are the operator's actions. Controlled-host evidence: the verdict "host forwarding is not enabled for a family this policy requires", both before and after the operator's action |
| Require administrator-installed, observed upstream routes back to the VPN pools; do not seize upstream gateway settings; keep managed routes scoped to the managed `utun` | `src/firewall/service_darwin.rs::observe_routes` (the pool's route must exist and be scoped to the managed device); the controlled-host return probes in both families; the operator's routes on the upstream router were installed and removed by the operator only |
| Forwarding bounded to authorized sources and destinations by an operator-managed filter that can be observed and proven effective; refuse rather than advertise routed support | `src/firewall/pf.rs` (`render_routed_policy`, `anchor_content_matches`), `src/firewall/pfctl.rs` (bounded read-only observation); the product wrote no PF state — the operator installed the reported rules with `pfctl`; controlled-host evidence: the verdict "the routed-LAN prerequisites are in place" and the drifted/absent/removed filter refusals |
| The C001 "host-only no firewall needed" branch must not apply here | `src/firewall/service_darwin.rs::plan` — `HostOnly` returns an empty plan, `RoutedLan` runs the observation and refuses unless every prerequisite is proven |
| Refuse stale convergence on peer/prefix removal, netd outage, helper renumbering, uplink change, or routing conflict | The controlled-host helper-restart negative: the reconcile degraded (`the network service refused the request; operator or state change required`) and the doctor refused with "no observed route carries traffic back to the tunnel pool" rather than reporting the previous convergence |
| Doctor distinguishes missing return route, forwarding disabled, filter missing, route conflict, not supported | `src/firewall/policy.rs::RoutedLanVerdict` (eight variants); `src/main.rs::append_routed_lan_check`; `src/doctor.rs` (`required_filter_rules`); the controlled-host run produced each of the named verdicts as its own refusal |
| Disposable administrator-controlled Mac, separate LAN host, real WireGuard peer on Linux, IPv4 **and** IPv6 tunnel peer → utun → approved LAN host → return route → tunnel | The macOS guest (192.168.64.3) is the product's server on a disposable UTM VM; the Linux guest (192.168.65.2) holds the real WireGuard peer in the `wgbpeer` namespace and the LAN host (10.20.20.2 / 2001:db8:20::2) in the `wgblan` namespace; the host Mac is the upstream router between the two segments. Controlled-host evidence: the off-host peer completed a handshake at 1792648171; IPv4 downstream 3/3 received, 0 % loss; IPv6 downstream 3/3 received, 0 % loss; IPv4 return 3/3 received, 0 % loss; IPv6 return 3/3 received, 0 % loss |
| Wrong destination rejected | Controlled-host evidence: the probe to 10.20.21.2 (inside the peer's own `AllowedIPs`, outside the approved prefix) reported "3 packets transmitted, 0 received, 100% packet loss". The peer's allowed range is deliberately wider than the approved prefix so that the server's own filter is what refuses it |
| Spoofed source rejected | Controlled-host evidence: the probe from 10.99.0.9 reported "3 packets transmitted, 0 received, 100% packet loss". The refusal is the tunnel's own allowed-sources check, which drops the packet before it can reach the server's filter |
| Negative tests for no return route, forwarding off, disabled filter, foreign route collision, helper restart | Five distinct refusals in one run: "host forwarding is not enabled for a family this policy requires"; "the operator-managed filter is absent or is not attached"; "the operator-managed filter does not match the rendered policy" (drifted and then removed); "a foreign or ambiguous route covers an approved destination"; "the approved destinations are not reachable through the declared egress interface" (no route to the approved destination); and "no observed route carries traffic back to the tunnel pool" (helper restart) |
| Record upstream route tables, host routing and PF inventory before and after | The run captured `routes before`, `routes after`, `routes IPv6 before`, `routes IPv6 after`, `packet filter before`, `packet filter after`, and `forwarding after` — the product wrote none of them |
| Native arm64 | The controlled-host run is `aarch64-apple-darwin`; ADR-009 retired the Intel target by scope, so this record claims Apple silicon only |
| Routine/MSRV and all Linux rootful suites | §3 below |
| No mock-only routed claim | The evidence is real ICMP over a real WireGuard tunnel between two kernels; no mock, stub, or fixture stands in for the traffic path |
| Stop if the only workable strategy needs uncontrolled PF edits, unbounded sysctl writes, default-route takeover, unqualified filtering, or foreign resource deletion | None was needed. The product writes no PF state, no sysctl, and no route; the operator installed the filter, the forwarding switches, and the upstream routes, and the run's teardown left the host's routing and filter as it found them |

## 3. Commands actually run, and their results

Run on the development host (Apple silicon, macOS 26.6.2) on 2026-10-22, at
baseline `92af9f5` with the C003 changes applied.

```
cargo fmt --all -- --check                                     # OK
cargo check --all-targets --locked                             # OK
cargo clippy --all-targets --locked -- -D warnings             # OK
cargo test --locked                                            # 424 unit tests passed; 0 failed; every integration suite passed
cargo test --locked -p wg-basic-darwin-sys                    # 13 passed; 0 failed
cargo +1.89.0 check --all-targets --locked                     # OK (MSRV)
cargo check --locked --target aarch64-apple-darwin --all-targets   # OK
cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets   # OK
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings   # OK
```

The controlled-host leg:

```
# in the disposable macOS guest, as root
WGB_DARWIN_LIVE=1 WGB_BINARY=/tmp/wg-basic WGB_WIREGUARD_GO=/tmp/wireguard-go \
WGB_PEER_COMMAND=/tmp/wg-basic-routed-peer.sh WGB_PEER_SSH_HOST=192.168.65.2 \
WGB_PEER_SSH_USER=wgqual WGB_PEER_SSH_KEY=/var/root/.ssh/wg-qual-peer \
WGB_EVIDENCE_DIR=/tmp/evidence \
  /tmp/wireguard_darwin_routed --ignored --nocapture --test-threads=1

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
             finished in 103.89s
```

## 4. Real-kernel and network evidence

- The server is the product's own managed deployment on the disposable macOS
  guest: the transactional installer, the launchd `serve` and `netd` roles,
  the privileged helper, the managed `utun0`, the state database at schema
  version 8, and the authenticated management API.
- The peer is a real WireGuard peer in a Linux network namespace on the second
  disposable guest. The handshake was observed (`the off-host peer completed a
  handshake at 1792648171`), so the traffic below crossed a real kernel
  boundary in both directions.
- The downstream LAN host is a separate Linux network namespace. Its only
  path from the peer namespace is the tunnel: the peer host's forwarding
  rules drop the direct namespace-to-namespace path explicitly, so the
  approved traffic has to go peer → tunnel → macOS server → upstream router →
  peer host → LAN host, and the return leg has to come back the same way.
- The upstream router is the host Mac. Its routes for the tunnel pool and the
  LAN prefix, and its `wg-qual` PF anchor, are the operator's; the run
  captured them before and after and the product changed none of them.

## 5. Security and ownership evidence

- The product never writes PF state, a forwarding sysctl, or a host route.
  Every one of those in the run is an operator action, and the run's
  before/after inventories show the product's own footprint: the managed
  `utun0` and its pool routes only.
- The filter is bounded in both directions and in both families: every rule
  names the pool prefix and the approved destination prefix, there is no
  `to any`, and there is no NAT rule. The rendered set is eight rules for the
  qualified dual-stack policy.
- The managed device is re-observed. The filter rules are bound to the
  `utun` the helper currently holds, so a renumbered helper invalidates the
  operator's filter and the product refuses rather than claiming the filter
  covers the tunnel.
- The state lease is exclusive and advisory-lock based; the doctor's
  inspection of it does not trust PID metadata.
- The management service remains unprivileged: the `serve` role runs as
  `_wg-basic-serve` and reaches the kernel only through the authorized netd
  socket.

## 6. Documentation and operations evidence

- `architecture/firewall.md` — the routed-LAN contract, the bidirectional
  rendered policy, the per-family rule rendering, PF's canonical form, and
  the structured rules the operator has to install.
- `architecture/state-store.md` — the schema 8 migration and the mode's
  persistence.
- `architecture/overview.md` — Darwin's routed-LAN support is no longer
  described as refused.
- `docs/operations-runbook.md` — the operator's prerequisites, the exact
  rules to install, the offline-diagnosis sequence (the service must be
  unloaded before the doctor can inspect the state immutably, and the
  database closed cleanly), and the PF anchor's trailing-newline
  requirement.
- `docs/development.md` — the gates and the local netd/serve workflow.

## 7. What the qualification found, and what was corrected

The controlled-host run is what produced the twelve defects below. Each was a
real defect in the implementation or in the leg, each is fixed, and each is
covered by a test that fails without the fix.

| # | Defect | Where | Correction |
|---|---|---|---|
| 1 | PF rules were paired across address families, which PF refuses to load, and the refusal took the whole anchor with it | `src/firewall/pf.rs` | Rules are rendered per address family; `a_routed_policy_pairs_each_destination_with_its_own_family` |
| 2 | The drift verifier could not read PF's canonical output (`inet`/`inet6` and `flags S/SA`), so a correctly installed filter always read as drift | `src/firewall/pf.rs` | `parse_filter_rule` accepts the family keyword and the state flags; `the_pf_canonical_rendering_of_the_reported_rules_is_not_drift` uses the real macOS 26.6.2 output |
| 3 | The doctor's bounded evidence truncated the rule list mid-rule | `src/doctor.rs` | `DoctorCheck.required_filter_rules` carries the rules as structured data |
| 4 | A destination the tunnel pool cannot carry was approved and then silently unreachable | `src/domain/state.rs` | `NetworkPolicyRoutedLanDestinationFamilyUnreachable` refuses it |
| 5 | A route's interface could not be named, so an operator's gateway route read as a foreign route | `crates/darwin-sys/src/ffi.rs` | `interface_name(index)` resolves it through `if_indextoname` |
| 6 | The reconcile's failure reason was computed and discarded | `src/aggregate.rs`, `src/reconcile/model.rs` | `netd.apply_action_failed`, `netd.helper_call_failed`, and `netd.device_patch_rejected` report it |
| 7 | The doctor's immutable inspection refused a cleanly closed database because it keyed on the sidecars' existence | `src/state/diagnostic.rs` | The rule is the WAL's *content*, not its existence; `immutable_inspection_accepts_a_cleanly_closed_database_with_an_empty_log` |
| 8 | A stale process held the helper's listen port, so the helper could not bind and the UAPI `set` was refused | `tests/wireguard_darwin_routed.rs` | The leg asserts the port is free before it starts, and the product logs the helper's errno |
| 9 | **The rendered routed-LAN policy carried only the forward leg.** The approved host could not reach the pool, and the reply to a forwarded packet rested on a state entry the operator's own filter never created | `src/firewall/pf.rs` | The return leg is rendered and bounded exactly like the forward one; `a_routed_policy_carries_the_return_leg_as_well` |
| 10 | **The traffic probes' assertions were vacuous.** `"100% packet loss"` contains `"0% packet loss"`, so a probe in which every packet was lost satisfied a check for a successful one | `tests/wireguard_darwin_routed.rs` | The check is the presence of a reply line (`answered`), which is what the transcript actually proves |
| 11 | The doctor's immutable inspection still refused a cleanly closed database, because the function had a second sidecar check that the first correction had not reached | `src/state/diagnostic.rs` | Both checks use the WAL-content rule |
| 12 | The leg restored the operator's filter from the file it had overwritten with a drifting rule, so the "restored" filter was still drifted | `tests/wireguard_darwin_routed.rs` | The drifting rules go to their own file; the filter is restored from the rules the product reported |

Defects 9 and 10 are the ones that matter most: before them, the leg would
have reported a routed LAN that carried no traffic at all, and would have
called it a pass.

## 8. Unresolved findings, classified

| Finding | Severity | Evidence | Disposition |
|---|---|---|---|
| **F1 — the management service does not terminate within the qualification's bound after `SIGTERM`.** The service logs `serve.stopping outcome=graceful` and then stays alive: the shutdown path joins its worker thread without a bound, so a service that is draining can hold the state lease and the write-ahead log indefinitely. An operator therefore cannot take the service down for offline maintenance by signalling it. | medium (operability) | The controlled-host run: the process was still present 30 s after `launchctl kill SIGTERM`, `lsof` showed it holding `state.db.serve.lock`, and `pkill -9` was required to release the lease | **Corrective required in the service-lifecycle line (C001/C002), not in the routed-LAN contract.** The leg unloads the launchd job for the offline diagnosis, which is the same operation the product's own uninstall performs, and it records the behaviour as evidence |
| **F2 — a killed WireGuard helper is not recovered automatically.** The reconcile degrades with "the network service refused the request; operator or state change required" and the doctor refuses. The refusal is correct — a stale convergence is never claimed — but the tunnel does not come back by itself. | medium (availability) | The controlled-host helper-restart negative | The refusal half is C003's and is met. The recovery half belongs to the helper-crash matrix that C001's closure record already lists as an open qualification item |
| **F3 — the upstream router's route back to the tunnel pool must be a gateway route through the tunnel host's own address.** A link-level route on the bridge makes the host resolve the pool address on the bridge, where it does not exist, and the host caches a rejection; the IPv6 equivalent makes the host resolve the prefix through its own address and loop the frame. | low (operational) | The controlled-host topology: the upstream router's `10.77.0.0/24` had to be routed via the tunnel host's own `en0` address, and `2001:db8:20::/64` via the peer host's link-local | Documented as an operator prerequisite in `docs/operations-runbook.md` |

## 9. Known limitations

- The Darwin Internet-exit gateway mode is still refused. `gateway` is
  C004's subject and is not claimed here.
- The routed LAN forwards **within one address family**. Cross-family rules
  are not rendered, because PF refuses them and a translation would be
  required; a routed LAN never translates.
- The supported Darwin target is Apple silicon alone (ADR-009). No Intel
  measurement is claimed.
- Installation and transactional self-update are not implemented. Phase 10
  remains planned and M001 is ready. Nothing in this record changes M007's
  MUST-NOT-release standing.
- The controlled-host evidence is Apple silicon only. No hosted macOS runner
  can reach the private-LAN peer, so the evidence could only be produced on a
  disposable host.

## 10. Disposition

**Conditionally closed.** The routed-LAN contract is implemented, the
controlled-host run proves real IPv4 and IPv6 traffic in both directions
through the tunnel with the wrong destination and the spoofed source refused,
every missing prerequisite has its own named refusal, and the product writes
no PF state, no forwarding sysctl, and no route.

The conditions are F1 and F2 above. Both are defects in the *service
lifecycle* rather than in the routed-LAN contract, both are classified with
evidence, and both are routed to the line that owns them — C001/C002's
service-lifecycle and helper-crash matrices. C003 does not claim them as
closed, and this record does not treat the routed-LAN contract as anything
other than what the evidence shows.
