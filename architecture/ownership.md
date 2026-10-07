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

M002 provides durable owner identity. **Automatic application of the durable desired state at startup is not implemented yet** — that is Phase 6 M003. Until M003 lands, a netd restart preserves ownership proof but does not itself re-derive kernel state from the database.