# macOS Native Server C011 — Service Lifecycle and Helper-Recovery Correctives

Status: **conditionally closed** (2026-10-22). The three findings this plan
corrects were recorded in `plans/closure/macos-native-server-corrective/c003-status.md`;
the implementation and the controlled-host evidence are recorded in
`plans/closure/macos-native-server-corrective/c011-status.md`.

Baseline: `plans/macos-native-support@5238816`.

Source: corrective roadmap; C003's closure record (findings F1, F2, F3);
`plans/adr/010-privileged-helper-supervision.md`; ADR-003 (the bounded worker);
ADR-008 (the Darwin platform).

Primary class: corrective / invariant.

## Objective

Close the three findings C003's controlled-host run left open, and close the
one that finding F2 was standing in front of.

- **F1** — the management service's shutdown is bounded and its stop request
  cannot be refused;
- **F2** — a helper that dies is replaced by the authority that spawned it, and
  a receipt that names a dead helper no longer wedges the installation;
- **F3** — the upstream route shape is verifiable, not only documented.

## Non-goals

No change to the Linux line. No reconciliation loop in the management role. No
new protocol operation, store schema, or wire format. No change to the
desired-state store's ownership of the authoritative state. No release
question is closed by this milestone, and M007's MUST-NOT-release standing is
unchanged.

## The findings, and why the previous evidence missed them

### F1 — the management service's shutdown

C003's closure record says the service "logs `serve.stopping outcome=graceful`
and then stays alive: the shutdown path joins its worker thread without a
bound, so it keeps holding the state lease and the write-ahead log".

**The observation was a misreading, and the code-level claim was right.**

The qualification's own evidence shows three different process identifiers
after three successive stops (27321, 27552, 27843). A service that never
exited would show one. The service does act on `SIGTERM`: it logs the graceful
stop, closes the store, and exits in under a second. What the qualification
saw afterwards was launchd's `KeepAlive` **successor**, not a hung process. A
separate check of the same conditions — idle, installed as a daemon, with the
job disabled, with a configured server and a live tunnel — reproduced the
graceful exit every time, and `launchctl bootout` took the process down in
under a second with the write-ahead log checkpointed and the lease released.

The harness is what missed it: the stop sequence asserted that *no* serve
process was running, which cannot distinguish a process that ignored the term
from the successor that launchd started because the term worked. The comment
in that sequence also claimed that disabling the job "keeps launchd from
restarting it immediately", which is false: a disabled job with `KeepAlive` is
still restarted.

The code-level claim was right, though, and it is a real latent defect: the
stop request rode the bounded queue, and the queue refuses admissions exactly
when the service is busiest. A refused stop request leaves the worker running
with the store open, and the join that followed had no bound.

### F2 — the helper that dies

C003's closure record says the refusal half is C003's and is met, and routes
the recovery half to C001's helper-crash matrix.

**The refusal half was met, the recovery half was worse than recorded.** The
tunnel was not merely left down: the installation could not bring it back at
all. A receipt that names a dead helper was treated as an ownership claim, so
every attempt to recreate the tunnel was refused with a conflict. A re-apply
did not recover it, a service restart did not recover it, and the only remedy
was an operator deleting the receipt by hand — a remedy that was documented
nowhere.

### F3 — the upstream route shape

C003's closure record says the requirement is documented and names the failure
mode: a link-level route on the upstream router makes it resolve the pool
address on the bridge, where it does not exist, and the return path never
leaves the router.

The documentation stands. What was missing is a way to *check* the shape: the
failure is silent, and the product cannot observe the routing table of a
router it does not manage.

## Implementation work

1. **Bounded, unrefusable stop.** The stop request closes the worker's queue
   instead of taking a slot in it, so it cannot be refused; the worker
   discards the backlog rather than working through it; and the wait for the
   thread is bounded and polled rather than blocking the runtime. A worker
   that outlives its budget is reported and the service still exits.
2. **launchd exit timeout.** The rendered job carries `ExitTimeOut`, so an
   operator's `launchctl bootout` escalates to a kill instead of waiting on a
   process that will not leave.
3. **A receipt's existence is not a claim.** A create re-proves the receipt
   that claims the owner tag. A receipt that cannot be re-proven is dropped
   and the tunnel is recreated over it; one that does re-prove is refused
   over, so two devices never carry the same durable proof.
4. **Helper supervision in the privileged authority.** `netd` notices that a
   helper it spawned is no longer running and re-applies the desired
   interface it applied for that helper, which recreates the helper, re-adopts
   one new device, and restores the configuration, addresses, and routes. See
   `plans/adr/010-privileged-helper-supervision.md` for the decision, the
   options, and the secret-handling consequence.
5. **Route-shape verification.** The runbook tells the operator how to check
   the shape of the upstream route, and the qualification asserts that the
   route it depends on names a gateway rather than an interface.

## Qualification and security evidence

The controlled-host leg is the C003 leg, extended. It runs on the disposable
macOS guest with the real installer, the real privileged and unprivileged
roles, a real Linux-kernel WireGuard peer, and a downstream LAN host that is
reachable only through the tunnel.

It must show:

- the management service acts on `SIGTERM`: the process that was running
  before the term is gone within the bound, and the service's own log records
  the graceful stop. The successor launchd starts afterwards is recorded as a
  successor, with its own identifier;
- the write-ahead log drains and the lease is released when the service stops,
  and the doctor's immutable inspection accepts the closed database;
- a killed helper is replaced: the privileged authority starts a new helper,
  the managed device comes back (renumbered if the kernel says so), the
  receipt is rewritten for the new device, and the routed LAN is reported
  available again;
- the routed LAN still carries real IPv4 and IPv6 traffic after the recovery,
  and the negatives still refuse: an unapproved destination, a spoofed source,
  a missing filter, a drifted filter, forwarding off, a competing route, and a
  lost return route;
- the route to the approved prefix names a gateway.

The post-recovery traffic assertion waits for a **new** handshake. A handshake
the peer still holds from before the kill is not a session the replacement
helper shares, so a check that only asks for a non-zero handshake would be
satisfied by the stale value and would prove nothing about the replacement.
The window the wait allows is the peer's rekey interval, because the session
is the peer's to re-establish.

Unit coverage must fail without each fix: a saturated queue must not refuse
the stop request; the stopped worker must not work through the backlog; a
receipt naming a dead helper must be dropped rather than refused; a present
interface must be retained for a recovery and an absent one must not be; a
receipt that did not reach the desired state must not be reported as a
converged recovery.

## Known limitations

- The recovery restores the state the privileged authority applied. It does
  not restore state the operator changed on the host afterwards, and it does
  not reinstall the operator's filter: the rendered rules name the device, so
  a renumbered device means the rules have to be reinstalled, exactly as after
  any device change.
- The recovery restores the **tunnel**, not the **sessions**. A WireGuard
  session lives in the helper's memory, so a replacement helper starts with no
  session with any peer, and a peer whose own session is still valid keeps
  sending packets the replacement cannot decrypt. The peer re-keys on the
  protocol's own interval (120 s by default) and the handshake that follows is
  answered by the replacement, so the traffic is down for that window even
  though the device, the address, the routes, and the peer policy are already
  back. The product cannot shorten it: the address a peer is reached at is
  learned from its handshake initiations, which is live telemetry the store
  does not persist.
- The upstream route shape is the upstream router's, and the product cannot
  observe it. It stays an operator prerequisite with a documented check.
- The privileged authority retains the applied desired interface, and with it
  the device's private key, for the lifetime of the managed tunnel. ADR-010
  §5 states the consequence and the mitigations.
