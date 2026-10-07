# wg-basic Planning and Agent-Handoff Process

Status: normative planning governance

wg-basic uses the CodeGG planning convention scaled to a small but security-sensitive network appliance. Stable long-term direction is separated from repository-baseline implementation handoffs and from closure evidence.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative.

## 1. Planning horizons

Long-term planning defines product identity, domain boundaries, security/network ownership invariants, non-goals, and macro ordering.

Interim planning defines bounded implementation work against a repository baseline.

Closure evidence determines whether a milestone actually satisfied its contract.

Implementation evidence may justify revising long-term direction, but implementation agents MUST NOT silently rewrite durable requirements to fit easier mechanics.

## 2. Canonical documents

Canonical long-term documents are:

- `plans/000-long-term-specification.md`;
- `plans/001-terminology-and-domain-model.md`;
- `plans/002-long-term-roadmap.md`;
- this planning-governance document.

Ordinary feature implementation SHOULD NOT edit these unless:

- product direction intentionally changes;
- a contradiction/material omission is demonstrated;
- an accepted ADR requires a canonical update;
- the maintainer explicitly requests long-term revision.

## 3. Architecture decision records

ADRs live under `plans/adr/`.

An ADR is required for a decision that materially changes:

- the privileged trust boundary;
- authoritative state ownership;
- kernel/firewall control strategy;
- public persistence/protocol compatibility;
- release/update authenticity;
- a cross-milestone runtime dependency.

An ADR MUST state context, alternatives, decision, consequences, compatibility/migration effects, and status.

Accepted ADRs are historical records and MUST NOT be rewritten to hide superseded decisions.

## 4. Subsystem roadmaps

A subsystem roadmap owns one coherent workstream.

It MUST define:

- ownership boundary;
- relevant canonical requirements/ADRs;
- invariants and non-goals;
- current repository evidence;
- dependency graph;
- ordered milestones;
- cross-cutting security/failure/recovery concerns;
- required integration evidence;
- risks and deferred work;
- milestone status table.

Roadmaps SHOULD avoid transient line numbers or over-specific implementation mechanics unless those mechanics are themselves contractual.

## 5. Milestone implementation plans

An implementation plan is the primary coding-agent handoff.

Each plan MUST contain:

- repository baseline;
- source subsystem roadmap/milestone;
- canonical requirements and ADRs;
- primary work class;
- objective;
- explicit non-goals;
- current repository evidence;
- invariants;
- expected production changes;
- ordered work packages;
- privilege/security effects;
- persistence/protocol/config compatibility effects;
- failure, cancellation, restart, and contention semantics where applicable;
- focused tests;
- Linux/network-namespace integration evidence where applicable;
- broad verification commands;
- documentation updates;
- acceptance criteria;
- stop conditions;
- closure evidence requirements.

Implementation freedom is desirable when several mechanisms preserve the contract.

## 6. Closure records

Closure records live under `plans/closure/<subsystem>/<NNN>-status.md`.

A closure record MUST include:

- implementation commits or pull request;
- repository baseline/final head;
- requirement-to-evidence matrix;
- exact tests/verification commands actually run and results;
- network-namespace/real-kernel evidence required by the milestone;
- security/ownership evidence where relevant;
- docs/operations evidence;
- known limitations;
- unresolved findings classified by severity;
- disposition: `closed`, `conditionally closed`, `corrective required`, or `blocked`.

Compilation alone is never closure for kernel/network-control milestones.

Do not create closure records before implementation evidence exists.

## 7. Work classification

Every milestone has a primary class:

- **invariant** — a property that must remain true across implementations;
- **capability** — user/operator/integration-visible behavior;
- **infrastructure** — machinery enabling capabilities;
- **polish** — ergonomics/performance/docs/maintainability after correctness.

Security-sensitive corrective work may combine invariant and corrective classifications.

## 8. Dependency types

Milestones declare:

- **hard** — cannot correctly begin before dependency closes;
- **interface** — can proceed against a stable written contract;
- **soft** — parallel work is possible but integration waits;
- **operational** — code can land but deployment/release claim waits for external evidence.

A milestone is `ready` only when all hard dependencies are closed and all interface dependencies are stable.

## 9. Milestone sizing

Prefer one vertical slice an implementation agent can complete coherently: production code, focused tests, integration evidence, docs, and a closure-oriented report.

A milestone is too large when it combines several independently testable ownership boundaries or unresolved architecture decisions.

A milestone is too small when it only renames/reshuffles internals without closing a meaningful contract, unless it is a corrective.

Kernel-facing milestones SHOULD isolate one authority boundary so failures can be reasoned about without simultaneously debugging HTTP, persistence, release tooling, and firewall policy.

## 10. Handoff authority order

Implementation agents resolve conflicts in this order:

1. canonical specification and terminology;
2. accepted ADRs;
3. subsystem roadmap;
4. milestone implementation plan;
5. current repository evidence.

If current evidence contradicts a plan, preserve canonical safety/ownership invariants, record the discrepancy, and make the smallest coherent adjustment. Do not invent broad shell-based fallbacks to complete a checklist.

## 11. Network-control evidence rule

Plans affecting WireGuard, links, addresses, routes, nftables, forwarding, or privilege boundaries MUST identify:

- what is authoritative;
- what wg-basic is allowed to mutate;
- how ownership is proven;
- what happens on partial failure;
- how retry/restart behaves;
- how unrelated host state is proven preserved.

A mocked backend can support unit testing but cannot substitute for Linux namespace and real kernel evidence where the milestone claims working kernel behavior.

## 12. Security rule

No plan may broaden the privileged protocol to arbitrary command execution, arbitrary file writes, arbitrary sysctl paths, raw caller-supplied nftables source, or arbitrary netlink messages merely to simplify implementation.

If a required behavior appears impossible through the typed boundary, stop and revise the design/ADR rather than add a generic escape hatch.

## 13. Corrective passes

A material post-implementation defect receives a new corrective plan.

Corrective plans MUST:

- reference the original plan/closure record;
- enumerate unclosed requirements/defects;
- explain why previous evidence missed them;
- add regression evidence;
- avoid reopening unrelated closed scope.

Historical closure records stay period-accurate.

## 14. Registry

`plans/registry.md` is the compact active planning control surface.

It SHOULD contain only:

- active subsystem roadmaps;
- ready/active/blocked implementation plans;
- active closure/corrective work when it exists;
- immediate blockers and handoff notes;
- recently closed work when useful.

Detailed requirements belong in source plans.

## 15. Documentation authority

Architecture/operator docs describe current implemented behavior.

Plans describe intended or active work.

When an implementation milestone lands, current-behavior docs MUST be updated with the code. Do not change current docs to claim planned behavior before implementation exists.

## 16. Required planning review

Before a plan is marked ready, confirm:

1. durable behavior is unambiguous;
2. authority/ownership is explicit;
3. dependencies are satisfied;
4. privilege changes are bounded;
5. failure/retry/restart semantics are explicit;
6. host-state preservation is testable;
7. secret handling is explicit;
8. protocol/config/storage compatibility is defined;
9. integration evidence is measurable;
10. stop conditions prevent unsafe scope expansion.

## 17. Planning anti-patterns

Avoid:

- one giant implementation plan for the whole appliance;
- treating UI completion as proof of kernel correctness;
- using `wg-quick` shell hooks as an internal typed-control substitute;
- declaring nftables correctness from generated text alone;
- changing host-global sysctls without ownership semantics;
- adding Eggstack dependencies solely for consistency;
- creating release automation before the release contract exists;
- writing closure records from expected rather than observed evidence;
- rewriting historical records after a corrective;
- marking a capability closed because infrastructure compiled.
