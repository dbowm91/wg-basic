# Ownership

## Interface ownership

wg-basic proves that a link is its own before it mutates or destroys it. Proof is a durable **owner tag** written into the kernel as the link's `IFLA_IFALIAS`.

An owner tag is derived only from:

- the owner-tag format version,
- the `InstallationId`,
- the `InterfaceId`.

Its canonical form is `wg-basic:v1:<installation-uuid>:<interface-uuid>` — 85 ASCII characters, well under the 255-byte kernel `IFALIASZ` limit. It contains no user-supplied label or interface name, and it is not a secret. It is a correctness and provenance marker, never an authorization token.

### Classification

For an existing link, observation compares the alias with the expected tag:

| Observed | Result |
|---|---|
| no link | created, then tagged |
| alias is exactly the expected tag | owned; eligible for full reconciliation |
| no alias | conflict |
| tag from this installation, different interface | conflict |
| tag from a different installation | conflict |
| any other alias | conflict |
| expected tag also present on another link | conflict |
| wrong link kind | conflict |

Only an exact match proves ownership. Ownership is **never** inferred from the interface name or from a public key. Durable owner tags strengthen proof of ownership; they do not authorize deleting anything that was not already managed.

### Writing the tag

Linux accepts `IFLA_IFALIAS` in `RTM_NEWLINK` but silently discards it, so creation is followed by an immediate `RTM_SETLINK` inside the same logical mutation.

A crash between those two calls leaves an untagged link. That is deliberate: an untagged same-name WireGuard link is reported as a conflict rather than adopted, so a partially created link requires operator cleanup instead of silent adoption.

### Preserved M004 semantics

Durable ownership does not weaken any existing rule:

- a wrong-kind link is still a conflict;
- only exactly listed addresses and routes are managed, and unlisted resources survive;
- deleting an interface that still carries an unlisted address or route is still refused;
- peer preservation is unchanged.

## Firewall ownership

The only table wg-basic owns is `inet wg_basic`. Its table comment binds to the installation identity:

```text
wg-basic:v1:<installation-uuid>
```

Chain and rule comments build on that marker and additionally bind to the exact desired policy hash, so expression-level drift detection still catches a copied comment concealing changed rules.

- A table carrying another installation's marker is a conflict.
- The historical M005 product-only marker `wg-basic:m005:v1` is recognized specifically and reported as a distinct "legacy table ownership" conflict. It is **never** silently adopted. Because no durable state shipped before Phase 6, an automatic legacy ownership migration is deliberately not provided.
- Unrelated tables are never flushed.

## Aggregate reconciliation

One desired generation is the unit of privileged reconciliation. The aggregate path is the canonical Phase 6 management operation; the lower-level M003–M005 operations remain available and unchanged in meaning.

### Layer ordering

Enabling reconciles the interface layer first and stops if that layer fails or does not verify, so firewall policy is never installed for a link that is not in its desired state.

Disabling removes the owned firewall policy first and stops if that fails, so a partial disable never deletes an interface while leaving a wg-basic firewall table whose semantic target no longer exists.

### One outer lock

A single netd aggregate mutation coordinator spans both layer services. Lower-level service locks remain as defence in depth. Lock order is fixed — outer first, then inner — so the ordering is deadlock-free. The lock exists on its own terms rather than relying on the current sequential socket dispatch, because Phase 7 may change caller and concurrency behavior.

### Generation monotonicity in one netd lifetime

netd keeps ephemeral acceptance state: the active installation identity and the highest accepted generation.

- The first valid aggregate apply establishes the installation identity for the process.
- A different installation identity while the process lives is a conflict.
- A generation lower than the highest accepted is a stale-generation conflict.
- A generation equal to the highest is an allowed idempotent reapply.
- A higher generation is eligible.

The generation is recorded **before** the first privileged mutation, so a delayed older request cannot follow it. Failure or partial failure never lowers the recorded number. This state is deliberately lost on netd restart; durable state and owner tags reestablish truth.

### Receipts

An aggregate receipt carries the installation identity, generation, overall status, per-layer results, which layer failed, and whether a fresh post-apply observation succeeded.

Overall status is mapped truthfully:

| Status | Meaning |
|---|---|
| `NoChange` | neither layer required a mutation |
| `Applied` | every requested layer verified |
| `PartialFailure` | an earlier layer changed state and a later layer failed |
| `FailedBeforeMutation` | nothing changed |
| `VerificationFailed` | a layer mutated but did not verify |

No receipt ever claims a rollback.

## Startup reconciliation

Durable owner identity is stored alongside the desired state, and **automatic application of the durable desired state at startup is implemented**. Every management start opens the store, loads the current desired snapshot and generation, projects it to one installation intent, and applies that generation — unconditionally, because the kernel may have drifted while the service was stopped. Evidence records the attempt; a generation is marked converged only while it is still the current desired generation, so a late completion cannot mark a newer one converged.
## Darwin interface ownership (C001)

The Linux ownership proof is the kernel interface alias. Darwin has no such
field, so the durable proof is the protected managed-runtime receipt
described in `architecture/wireguard-control.md`.

The portable contract is unchanged: `OwnerTag` is still the proof, and the
portable planner still classifies an observation by comparing that proof
against the alias the observation carries. On Darwin the observation carries
the owner tag that the *proven* receipt recorded, and only then. An unproven
receipt, a receipt for another installation, or a second receipt claiming the
same tag all fail closed: the first is observed as absent, the second as a
foreign tag, and the third as a duplicated owner tag. Nothing is adopted by
name similarity.

The receipt lives in `/var/run/wg-basic/managed`, an owner-only directory
inside the root-controlled runtime directory. A receipt that is a symlink, is
not a regular file, is owned by another user, or carries group or other
permissions is refused rather than read.

### A receipt's existence is not a claim

A receipt names the helper that owns a tunnel. The file's existence says
nothing on its own: it is re-proved against the live host before anything is
changed.

That applies to creating a tunnel as well as to observing one. A receipt whose
helper is gone describes nothing that exists, so the tunnel may be recreated
over it and the stale receipt is dropped. A receipt that *does* re-prove is a
live tunnel carrying that owner tag, and a second tunnel over it is refused:
two devices must never carry the same durable proof.

The asymmetry is deliberate. Failing closed is right when a resource might
belong to somebody else, and refusing to recreate a tunnel whose helper died
would leave the installation unable to bring it back at all.

## Darwin PF ownership (C004)

The Darwin host-only and routed-LAN contracts own **no** PF state: the first
refuses everything that would need it, and the second observes the host's
filter without writing it. The gateway contract owns exactly one PF resource:
its own installation-scoped anchor, and the file that anchor is loaded from.

### The anchor file is a managed resource

| Property | Value |
|---|---|
| Anchor name | `wg-basic-v1-<installation-id>`, from the installation identity |
| Anchor file | `/etc/pf.anchors/<anchor>`, from the anchor's own name |
| Ownership marker | the file's first line, written by the product |
| Ownership proof | that marker line, read from the host's state |

The marker is:

```text
# wg-basic-v1 managed anchor for installation <installation-id>
```

The name and the path are both derived, never caller-supplied: there is no
API through which a caller could name another installation's anchor, a path
outside the anchor directory, or a foreign anchor. Two installations on one
host therefore never share an anchor.

The marker is what makes the ownership **provable from the host's state**,
which matters because the product removes resources. It is a comment, so it
changes no rule and no rule digest, and it is the product's own line, written
and recognised by the product. A file that does not carry the marker is not
the product's file: the routed-LAN mode's filter belongs to the administrator
and carries no marker, so the product never removes it and reports it as
residue instead (`routed_lan_filter_residue_observed`). The same rule applies
inside the managed anchor — rules the product did not install are reported as
`managed_anchor_residue_observed` and left alone.

The teardown empties the anchor's rules in both rule classes and rewrites the
file to its marker line alone. The file is deliberately **not** removed: the
administrator's `load anchor` line names it, and a missing file makes the next
`pfctl -f /etc/pf.conf` fail outright, which would break the host's whole
packet-filter configuration rather than this installation's anchor.

### The receipt

The gateway's firewall receipt records the install and the removal as the
action kinds `install_managed_pf_anchor` and `remove_managed_pf_anchor`. The
install kind is the macOS gateway mode's **only** PF write: it names the
installation's own anchor and the installation's own file, and it never loads
the root ruleset and never touches a foreign anchor. The receipt's warnings
carry the residue findings by name, so a receipt says what was left behind
rather than only that something converged.

### The administrator's parent is foreign state

The `anchor`, `nat-anchor`, and `load anchor` lines in the administrator's
`/etc/pf.conf` are the **administrator's**. The product never writes them,
never edits them, and never reorders them; they are the attachment the
product reads to decide whether its own anchor is in effect, in both rule
classes.

A missing or incomplete attachment is therefore a **degraded state with an
actionable error**, not something the product writes itself. The plan's
verdict is `GatewayVerdict::AttachmentMissing` (`attachment_missing`), the
failure it reports is `FirewallFailure::GatewayAttachmentMissing`, and the
refusal it returns is `FirewallError::GatewayAttachmentMissing`; the doctor
names the three lines the administrator has to add and the file that has to
exist before the parent is loaded. The product repairs the administrator's
configuration for nobody.
