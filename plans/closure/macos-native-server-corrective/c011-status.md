# C011 — service lifecycle and helper-recovery correctives: closure record

Milestone: **C011** (C003's corrective).
Class: corrective / invariant.
Date: 2026-10-22.

Source plan: `plans/implementation/macos-native-server/c011-service-lifecycle-and-helper-recovery.md`.
Decision: `plans/adr/010-privileged-helper-supervision.md`.
Corrective roadmap: `plans/subsystems/macos-native-server-corrective-roadmap.md` (C011).
Corrects: `plans/closure/macos-native-server-corrective/c003-status.md` (findings F1, F2, F3).

Baseline: `plans/macos-native-support@5238816`.
Implementation head: `ae153e3` — *macos(c011): bound the service shutdown and recover a lost helper*, on top of `5238816`.

C003's closure record is **not** rewritten. It is a period-accurate record of what
that run observed; this record corrects the findings it left open.

## 1. Disposition

**Conditionally closed.** The three findings are corrected, and the corrective is
evidenced on a controlled host: the management service acts on `SIGTERM` on
every stop in the run, a killed helper is replaced by the authority that
spawned it, the tunnel comes back with its device, address, routes, and peer
policy, and the routed LAN carries real IPv4 and IPv6 traffic again once the
peer's session is re-established.

Two conditions are stated in §9: the evidence is Apple silicon on a disposable
host only, and the recovery restores the *tunnel* rather than the peer's
*session*, so the traffic is down until the peer re-keys. Neither is closed by
this milestone, and nothing here changes M007's MUST-NOT-release standing.

## 2. What the findings turned out to be

F1 and F2 both changed when they were re-read against the code and against a
fresh reproduction on the same controlled host. A third finding — in the
qualification's own assertions — surfaced while the corrective was being
evidenced, and is recorded as F4 in §10.

### F1 — the management service's shutdown

C003 recorded: "the service logs `serve.stopping outcome=graceful` and then
stays alive: the shutdown path joins its worker thread without a bound, so it
keeps holding the state lease and the write-ahead log".

**The observation was a misreading; the code-level claim was true.**

The qualification's own evidence shows three different process identifiers
after three successive stops (27321, 27552, 27843). A service that never
exited would show one identifier throughout.

The service does act on `SIGTERM`. It was reproduced directly on the same
controlled host, with the product installed by its own installer and running
as the unprivileged management identity under launchd:

| Condition | Result |
|---|---|
| installed service, idle | `serve.stopping outcome=graceful`, exit within 1 s, **new pid** (launchd restarted it) |
| the job disabled first, then `SIGTERM` | **still restarted** — a disabled `KeepAlive` job is still restarted |
| two `SIGTERM`s back to back, as the leg sends them | new pid; launchd reports `last exit code = 0` |
| a configured server with a live tunnel and a 144 KB write-ahead log | graceful exit within 1 s, successor started |
| `launchctl bootout` | process gone within 1 s, write-ahead log checkpointed and removed, lease released |

What the qualification saw afterwards was launchd's `KeepAlive` **successor**,
not a hung process. The harness could not tell the two apart: it asserted that
*no* serve process was running, which is false under `KeepAlive`, and its
comment claimed that disabling the job "keeps launchd from restarting it
immediately", which the same reproduction disproves.

The code-level claim was nonetheless a real latent defect, and it is fixed: the
stop request rode the bounded queue, and the queue refuses admissions exactly
when the service is busiest, so a refused stop request would leave the worker
running with the state store open; and the join that followed had no bound.

### F2 — the helper that dies

C003 recorded: the refusal half is C003's and is met; the recovery half
belongs to C001/C002's helper-crash matrix.

**The recovery half was worse than recorded.** The refusal half was met, but
the recovery path was broken as well as absent.

Reproduced on the controlled host with a live tunnel:

1. the helper is killed; the managed `utun` disappears and the helper does not
   come back (checked after 30 s);
2. the **stale receipt survives** in the managed-runtime directory;
3. a service restart does **not** recover it: the startup reconcile fails with
   `netd.apply_action_failed outcome=conflict resource_kind=create_wireguard_link`;
4. moving the stale receipt aside and restarting both roles recovers it
   immediately.

The cause was that the create path treated the *existence* of a receipt as an
ownership claim. A receipt naming a dead helper refused every attempt to
recreate the tunnel, so the installation could not bring it back by a
re-apply, by a restart, or at all — only by an operator deleting the receipt
by hand, which was documented nowhere.

### F3 — the upstream route shape

C003 recorded the requirement and the failure mode, and that documentation
stands. What was missing was a way to *check* the shape, because the failure
is silent and the product cannot observe a router it does not manage.

### What the recovery does and does not restore

The recovery restores everything the product owns — the device, its address,
the routes, the peer policy, and the helper that carries them. It does **not**
restore a peer's *session*: a WireGuard session is a negotiated keypair that
lives in the helper's memory, so a replacement helper starts with no session
with any peer, and a peer whose own session is still valid keeps sending
packets the replacement cannot decrypt. The peer re-keys on the protocol's own
interval and the handshake that follows is answered by the replacement, so the
traffic is down for that window even though the tunnel is already back. §8
records the measurement; §9 records the limitation.

## 3. Requirement-to-evidence matrix

| # | Requirement | Evidence | Where |
|---|---|---|---|
| R1 | The stop request cannot be refused | a saturated queue refuses an admission and still accepts the stop | unit: `a_stop_request_is_never_refused_by_a_full_queue` |
| R2 | A stopped worker discards the backlog rather than working through it | the stop returns without waiting for an unanswered command | unit: `a_stopped_worker_discards_the_backlog_and_closes_the_store` |
| R3 | The wait for the worker thread is bounded | `WORKER_STOP_DEADLINE`; a worker that outlives it is reported as `worker_stuck` and the service still exits | `src/management/worker.rs`, `src/http/serve.rs` |
| R4 | The management service acts on `SIGTERM` | the process that was running before the term is gone within the bound, on every stop in the run (10 stops) | controlled host: "the term was honoured" (10 occurrences) |
| R5 | The job escalates if the service wedges | `ExitTimeOut` in the rendered plist | `src/launchd.rs`, unit: `plist_renders_fixed_keys_and_the_service_identity_without_secrets` |
| R6 | A receipt that cannot be re-proven is not a claim | a stale claim is dropped and the create proceeds | unit: `a_stale_claim_is_dropped_so_the_tunnel_can_be_recreated` (fails with `Conflict` without the fix) |
| R7 | A live claim is still refused | `OwnerClaim::Live` refuses the create | `src/reconcile/backend_darwin.rs` |
| R8 | The helper is replaced when it dies | the privileged authority starts a new helper and the managed device comes back | controlled host: "the helper was replaced: 37938 /usr/local/libexec/wg-basic/wireguard-go utun"; "the managed device after the helper restart: Some(\"utun0\")" |
| R9 | The recovered tunnel carries the policy again | the routed-LAN verdict is "in place" after the recovery | controlled host: "the routed-LAN verdict after the helper restart: the routed-LAN prerequisites are in place" |
| R10 | The recovered tunnel carries real traffic | the peer establishes a **new** handshake with the replacement and the approved downstream host answers through it | controlled host: "the off-host peer completed a new handshake at 1792678700 (the handshake before the kill was 1792678577)"; downstream 3/3 received, 0 % loss |
| R11 | The recovered tunnel is bound by the same policy | an unapproved destination is still not delivered after the recovery | controlled host: "the unapproved destination probe after the recovery" — 3 transmitted, 0 received, 100 % loss |
| R12 | A present interface is retained for a recovery; an absent one is not | the retained state follows the lifecycle | unit: `a_present_interface_is_retained_for_a_recovery` |
| R13 | A recovery that did not converge is not reported as one | only a converged receipt ends the recovery | unit: `only_a_reached_desired_state_counts_as_converged`; `src/reconcile/backend_darwin.rs` |
| R14 | The route to the approved prefix names a gateway | the leg asserts the gateway, not just that traffic flowed | controlled host: `gateway: 192.168.64.1` |
| R15 | The management role keeps no reconciliation loop | the monitor lives in the privileged authority and restores only what it applied | `architecture/startup-recovery.md`, ADR-010 |
| R16 | Linux does not regress | the full gate set, including the Linux cross-build and clippy | §5 |

## 4. What changed

| File | Change |
|---|---|
| `src/management/worker.rs` | the stop request closes the queue instead of taking a slot in it; the worker discards the backlog; the wait for the thread is bounded and polled; `WorkerError::StopTimeout` |
| `src/http/serve.rs` | a worker that outlives its budget is reported as `worker_stuck` and the service still exits |
| `src/http/service.rs` | the new error maps to the same unavailable answer as the other worker failures |
| `src/launchd.rs` | `ExitTimeOut` in the rendered plist |
| `src/reconcile/backend_darwin.rs` | the create path re-proves the claim before it can refuse; the privileged authority supervises the helper it spawned and re-applies the desired interface it applied for it; a recovery that did not converge is retried and then reported as failed |
| `src/reconcile/service_darwin.rs` | the apply goes through the backend, so the applied desired state is retained for a recovery |
| `src/reconcile/model.rs` | `ApplyStatus::converged()` — the absence of an error is not a convergence |
| `src/wireguard/darwin_backend.rs` | `OwnerClaim` and `RuntimeRegistry::claim`, the re-proved classification of a receipt |
| `tests/wireguard_darwin_routed.rs` | the stop sequence compares process identifiers across the term; the helper kill asserts the recovery, the **new** handshake, the traffic, and the still-refused negative; the route to the approved prefix is asserted to name a gateway; the capture across the recovery keeps the tunnel's own transport |
| `architecture/startup-recovery.md`, `architecture/ownership.md`, `architecture/wireguard-control.md`, `architecture/management-http.md` | the recovery contract, the receipt-as-claim rule, the helper's supervised lifecycle, the bounded stop, and the difference between restoring the tunnel and restoring the sessions |
| `docs/operations-runbook.md` | the route-shape check, the recovery events, the unload sequence, and what an operator sees between a recovered tunnel and a re-keyed peer |

## 5. Commands and results

Run on the development host (Apple silicon, macOS 26.6.2) on 2026-10-22, with
the C011 changes applied.

```
cargo fmt --all -- --check                                    clean
cargo check --all-targets --locked                            clean
cargo clippy --all-targets --locked -- -D warnings            clean
cargo test --locked                                           429 unit tests, 0 failed; every integration suite passed
cargo test --locked -p wg-basic-darwin-sys                    13 passed
cargo +1.89.0 check --all-targets --locked                    clean
cargo check --locked --target aarch64-apple-darwin --all-targets   clean
cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets   clean
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings   clean
```

The controlled-host leg, in the disposable macOS guest, as root:

```
# in the disposable macOS guest, as root
WGB_DARWIN_LIVE=1 WGB_BINARY=/tmp/wg-basic WGB_WIREGUARD_GO=/tmp/wireguard-go \
WGB_PEER_COMMAND=/tmp/wg-basic-routed-peer.sh WGB_PEER_SSH_HOST=192.168.65.2 \
WGB_PEER_SSH_USER=wgqual WGB_PEER_SSH_KEY=/var/root/.ssh/wg-qual-peer \
WGB_EVIDENCE_DIR=/tmp/evidence \
  /tmp/wireguard_darwin_routed --ignored --nocapture --test-threads=1

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 536.50s
```

3212 evidence lines. The run took longer than C003's 166 s because it now waits
for the peer's session to be re-established rather than accepting the
handshake the peer already had (§2, §10 F4).

## 6. Kernel and network evidence

The run is on the disposable macOS guest (`aarch64-apple-darwin`,
192.168.64.3) with a real Linux-kernel WireGuard peer (192.168.65.2,
namespace `wgbpeer`) and a downstream LAN host (10.20.20.2 /
2001:db8:20::2, namespace `wgblan`). The host Mac is the upstream router
between the two segments.

**The managed device after the recovery.** The kernel released the old
`utun` when the helper died and the replacement adopted a new one:

```
the managed device after the helper restart: Some("utun0")
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
	inet 10.77.0.1 --> 10.77.0.1 netmask 0xffffffff
	inet6 2001:db8:77::1 --> 2001:db8:77::1 prefixlen 128
```

**The routes.** The pool route is restored on the managed device, and the
approved prefix is reached through the declared egress:

```
10.20.20/24        192.168.64.1       UGSc                  en0
10.77/24           utun0              USc                   utun0
10.77.0.1          10.77.0.1          UH                    utun0
```

The route to the approved prefix names a gateway (`gateway: 192.168.64.1`),
which is the F3 check the runbook now gives the operator.

**The capture across the recovery.** `tcpdump -i any -n -w … 'udp port 51820
or icmp'`, run from before the kill until after the traffic resumed. It is
the evidence that says *where* the packets stopped:

```
07:17:05.258417 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 32
07:17:30.394388 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 32
07:17:55.929114 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 32
07:18:21.212270 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 32
07:18:21.215962 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 148
07:18:21.229741 IP 192.168.64.3.51820 > 192.168.65.2.45990: UDP, length 92
07:18:23.679534 IP 192.168.65.2.45990 > 192.168.64.3.51820: UDP, length 128
07:18:23.683591 IP 10.77.0.2 > 10.20.20.2: ICMP echo request, id 32944, seq 1, length 64
07:18:24.782826 IP 10.77.0.2 > 10.20.20.2: ICMP echo request, id 32944, seq 2, length 64
07:18:25.806904 IP 10.77.0.2 > 10.20.20.2: ICMP echo request, id 32944, seq 3, length 64
```

Read line by line: the peer's 25-second keepalives (32-byte data packets) keep
arriving at the replacement helper and keep being dropped, because the
replacement has no session to decrypt them with; the peer's re-key arrives as
a 148-byte handshake initiation and is answered with a 92-byte handshake
response; and the inner ICMP then traverses the tunnel in both directions.

**The traffic after the recovery.** IPv4 downstream, IPv6 downstream, and the
return path through the upstream route, all through the recovered tunnel:

```
the downstream probe after the recovery:   3 packets transmitted, 3 received, 0% packet loss
the IPv6 downstream probe after the recovery: 3 packets transmitted, 3 received, 0% packet loss
the return probe after the recovery:        3 packets transmitted, 3 received, 0% packet loss
```

**The negative still holds.** The replacement is bound by the same policy, not
by a looser one:

```
the unapproved destination probe after the recovery: 3 packets transmitted, 0 received, 100% packet loss
```

**The product writes no host state.** The filter is the operator's: the leg
installs the rules the product reported, and the run's teardown left the
host's routing and filter as it found them. The product read
`net.inet.ip.forwarding` (reported as `1`) and never wrote it.

## 7. Security and ownership evidence

- **A receipt's existence is not a claim.** The create path re-proves the
  receipt that claims the owner tag — the device is present, the helper is
  alive, the digest matches, and the UAPI socket answers — before it can
  refuse. A receipt that cannot be re-proven is dropped and the tunnel is
  recreated over it; one that does re-prove is refused, so two devices never
  carry the same durable proof. The unit test
  `a_stale_claim_is_dropped_so_the_tunnel_can_be_recreated` fails with
  `Conflict` on the old behaviour.
- **The device carries the durable owner tag**, and the receipt is rewritten
  for the replacement device: the recovery re-adopts exactly one new device
  and records its own identifier, so the old receipt never describes the new
  device.
- **The recovery never adopts what it cannot prove.** The monitor only looks
  at helpers in its own supervision map, and the create path refuses a
  foreign or duplicate owner tag. A device it cannot prove is not touched.
- **Secret handling.** The privileged authority retains the applied desired
  interface, and with it the device's private key, for the lifetime of the
  managed tunnel. ADR-010 §5 records the consequence and the mitigations: the
  `PrivateKey` type redacts and zeroizes, the retained state is never written
  to the store, and it is dropped when the managed tunnel is removed.
- **The client telemetry exposes no key material**: it reports the observed
  endpoint, the last handshake, the handshake age, and the byte counters.
- **The stop releases the lease and drains the write-ahead log.** After each
  term the lease holder list is empty ("the state service lease is free") and
  the write-ahead log is checkpointed (374952 bytes during the run, 4152 bytes
  after the stop), and the doctor's immutable inspection accepts the closed
  database.

## 8. Controlled-host evidence

The controlled-host run is the C003 leg, extended. It runs on the disposable
macOS guest with the product's own installer, the real privileged and
unprivileged roles under launchd, a real Linux-kernel WireGuard peer, and a
downstream LAN host that is reachable only through the tunnel.

**The service acts on the term, on every stop in the run.** Ten stops, each
recording the process that was running before the term and showing it gone
afterwards. Where launchd had already started a successor, the successor is
recorded as a successor with its own identifier:

```
the term was honoured: the process [37209] is gone, [37286] remain
the term was honoured: the process [37317] is gone, [] remain
the term was honoured: the process [37375] is gone, [] remain
```

**The helper is replaced.** The privileged authority starts a new helper and
the managed device comes back:

```
the helper was replaced: 37938 /usr/local/libexec/wg-basic/wireguard-go utun
the managed device after the helper restart: Some("utun0")
the routed-LAN verdict after the helper restart: the routed-LAN prerequisites are in place
```

**The product's own account of the peer, right after the recovery.** The
replacement helper is a new process, so it holds no session and has never seen
a handshake initiation; the product observes exactly that:

```
the client telemetry after the recovery (HTTP 200): {"observed_at_unix_seconds":1792678622,"clients":[{"client_id":"708dfe5a-…","peer_id":"f3dfe2b1-…","enabled":true,"observation":"present","drift":false,"endpoint":null,"latest_handshake_unix_seconds":null,"latest_handshake_age_seconds":null,"rx_bytes":0,"tx_bytes":0}],"unassociated_peer_count":0,"truncated":false}
```

`endpoint` is null and there is no handshake at all: the replacement helper
has neither a session nor a learned peer address. This is the product's own
observation, not the harness's inference.

**The peer re-establishes the session, and the traffic follows.** The handshake
before the kill was 1792678577; the peer re-keyed 120 s later, on the
protocol's own interval, and the new handshake is answered by the replacement
helper:

```
the off-host peer completed a new handshake at 1792678700 (the handshake before the kill was 1792678577), 86.035174417s after the helper was killed
```

86 s after the kill is 120 s after the peer's last handshake minus the 34 s the
pre-kill phases had already taken. The tunnel itself was back long before
that: the device, the address, the routes, and the verdict were in place
within a second of the kill.

## 9. Known limitations

- **The recovery restores the tunnel, not the sessions.** A WireGuard session
  lives in the helper's memory, so a replacement helper starts with no session
  with any peer, and a peer whose own session is still valid keeps sending
  packets the replacement cannot decrypt until the peer re-keys. The traffic
  is therefore down for up to the peer's rekey interval (120 s by default)
  even though the tunnel is already back. The product cannot shorten the
  window: the address a peer is reached at is learned from its handshake
  initiations, which is live telemetry, and the store does not persist live
  telemetry — the schema has no column for an observed endpoint or an observed
  handshake (`the_schema_contains_no_live_telemetry_columns`). This is
  documented in `architecture/startup-recovery.md` and in
  `docs/operations-runbook.md`.
- **The recovery does not reinstall the operator's filter.** The rendered rules
  name the device, and PF binds an interface name to its index when the
  ruleset is loaded, so a replacement device means the rules have to be
  reinstalled — exactly as after any device change. The runbook says so, and
  the leg takes the operator's step for the same reason an operator would.
- **The upstream route shape is the upstream router's**, and the product
  cannot observe it. It stays an operator prerequisite with a documented check.
- **Installation and transactional self-update are not implemented.** Phase 10
  remains planned and M001 is ready. Nothing in this record changes M007's
  MUST-NOT-release standing.
- **The controlled-host evidence is Apple silicon on a disposable host.** No
  hosted macOS runner can reach the private-LAN peer, so the evidence could
  only be produced on a disposable host.

## 10. Severity-rated findings

| Finding | Severity | Evidence | Disposition |
|---|---|---|---|
| **F1 — the management service does not terminate within the qualification's bound after `SIGTERM`.** The service logs `serve.stopping outcome=graceful` and then stays alive: the shutdown path joins its worker thread without a bound, so a service that is draining can hold the state lease and the write-ahead log indefinitely. An operator therefore cannot take the service down for offline maintenance by signalling it. | medium (operability) | The controlled-host run: the process was still present 30 s after `launchctl kill SIGTERM`, `lsof` showed it holding `state.db.serve.lock`, and `pkill -9` was required to release the lease | **Corrected.** The observation was a misreading — the service did exit, and the process seen afterwards was launchd's `KeepAlive` successor — but the code-level claim was a real latent defect and is fixed: the stop request can no longer be refused by a full queue, the worker discards the backlog, the join is bounded, and the job carries `ExitTimeOut`. The qualification's assertion was corrected to compare process identifiers across the term (§2). |
| **F2 — a killed WireGuard helper is not recovered automatically.** The reconcile degrades with "the network service refused the request; operator or state change required" and the doctor refuses. The refusal is correct — a stale convergence is never claimed — but the tunnel does not come back by itself. | medium (availability) | The controlled-host helper-restart negative | **Corrected, and worse than recorded.** The refusal half was met; the recovery half was broken as well as absent, because a receipt naming a dead helper refused every recreate and the installation could not bring its tunnel back at all. The receipt's existence is no longer a claim, and the authority that spawned the helper now supervises it and re-applies the state it applied (§2, ADR-010). |
| **F3 — the upstream router's route back to the tunnel pool must be a gateway route through the tunnel host's own address.** A link-level route on the bridge makes the host resolve the pool address on the bridge, where it does not exist, and the host caches a rejection; the IPv6 equivalent makes the host resolve the prefix through its own address and loop the frame. | low (operational) | The controlled-host topology: the upstream router's `10.77.0.0/24` had to be routed via the tunnel host's own `en0` address, and `2001:db8:20::/64` via the peer host's link-local | **Documented with a check.** The runbook gives the operator the route shape to check, and the qualification asserts that the route it depends on names a gateway rather than an interface. |
| **F4 — the qualification's post-recovery assertions measured the wrong thing.** The leg asserted that the peer "re-handshakes" by asking for a handshake value greater than zero, and the value the peer reports is the timestamp of its last handshake — so the pre-kill handshake satisfied the assertion. The leg also waited 90 s, which is shorter than the protocol's rekey interval, so the traffic was probed before the session could exist. The first three runs of this corrective failed on that assertion while the recovery itself was working: the tunnel was back, the verdict was "in place", and the peer had not yet re-keyed. | medium (qualification integrity) | The three failed runs: the peer's reported handshake was byte-for-byte the same value before and after the kill (1792676996), the product's telemetry showed `endpoint: null` and `latest_handshake_unix_seconds: null`, and the capture showed the peer's keepalives arriving and being dropped | **Corrected.** The assertion now requires a handshake *newer* than the one the peer held before the kill, and the window it allows is the peer's rekey interval. The run that closes this record passes with that assertion, and the capture across the recovery is part of the evidence. This finding is the same class as F1: a qualification that asserts something it cannot measure. |
| **F5 — the traffic is down for up to the peer's rekey interval after a helper replacement.** The recovery restores the tunnel immediately, but a peer's session does not survive the helper that held it, and the peer re-keys on its own schedule. | low (availability) | The capture across the recovery: four 25-second keepalives dropped, then the 148-byte handshake initiation, the 92-byte response, and the traffic | **Accepted and documented; not a product defect.** It is the WireGuard session model, and the product cannot shorten it without persisting live telemetry the store forbids. Documented in `architecture/startup-recovery.md` and `docs/operations-runbook.md`, and observable by an operator through `GET /api/v1/clients/telemetry`. |

## 11. Disposition

**Conditionally closed.** The three findings C003 left open are corrected, and
the corrective is evidenced on a controlled host with real traffic: the
management service acts on `SIGTERM` on every stop in the run, a killed helper
is replaced by the authority that spawned it, the tunnel comes back with its
device, address, routes, and peer policy, the routed LAN carries real IPv4 and
IPv6 traffic again once the peer's session is re-established, and the negative
still refuses.

Two findings are recorded as open and bounded. F4, in the qualification's own
assertions, is corrected and the corrected assertion is what passes. F5, the
rekey window between a recovered tunnel and a re-keyed peer, is a property of
the WireGuard session model: it is documented, it is observable by an
operator, and it is not closed by this milestone.

The conditions are the ones in §9. Nothing in this record claims installation
or transactional self-update, and M007's MUST-NOT-release standing is
unchanged.
