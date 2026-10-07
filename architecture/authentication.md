# Local administrator credentials and sessions

This document describes **current implemented behaviour**. Phase 7 is in
progress: M002 has the credential and session primitives, and the authenticated
HTTP perimeter that consumes them is a later milestone. There is **no login route
yet** — see [the management HTTP boundary](management-http.md).

Architecture decisions behind this design are recorded in
[ADR-003](../plans/adr/003-management-http-auth-and-worker-boundary.md); the
stored-state rules are in [the state store](state-store.md).

## What exists today

| Surface | Behaviour |
|---|---|
| `wg-basic admin set-password --password-stdin` | Creates the local administrator, or resets its password and revokes every session |
| `wg-basic admin status` | Prints identity, enabled state, and live session count. Never a credential |
| HTTP | **Nothing.** `/healthz` only; no login, no session cookie, no authenticated route |

The primitives exist and are fully qualified behind the worker; M003 adds the
routes that use them.

## Schema

Migration 2 (`src/state/migrations/002_auth_sessions.sql`) adds two tables.

`admin_principals` holds the local administrator: identity, a unique username,
an Argon2id PHC verifier, an enabled flag, and timestamps. Phase 7 operates
exactly one administrator, but the table is keyed rather than a singleton row so
adding a second operator later is schema-compatible rather than another
production migration.

`admin_sessions` holds server-side sessions: session identity, the principal
foreign key, the session **token digest**, the CSRF token, and the creation and
expiry times. `expires_at > created_at` is a schema constraint, so a session
that would be born expired cannot be written at all.

Both tables are additive. Migration 2 touches no desired-state column, no
ownership marker, and nothing projection reads.

## Passwords

Argon2id, with the management roadmap's minimums as an explicit constant:

| Parameter | Value |
|---|---|
| Algorithm | Argon2id (v0x13) only |
| Memory | 19 MiB (`m = 19456`) |
| Iterations | 2 (`t = 2`) |
| Parallelism | 1 lane (`p = 1`) |

The stored value is the full PHC string, so the algorithm, its parameters, and
the random salt are self-describing. A future parameter increase is not a
migration, and a verifier written under the current policy stays verifiable
afterwards. A verifier that is **not** Argon2id is refused rather than verified,
so stored strength can never depend on which library wrote the row.

The policy is length-only:

- **floor** 12 UTF-8 bytes — long enough for an administrator credential;
- **ceiling** 1024 UTF-8 bytes — input resource control, not a security rule. An
  unbounded password is unbounded Argon2 work.

There are deliberately no composition rules. Requiring "one uppercase, one
symbol" measurably pushes operators toward predictable substitutions and away
from length. The bound is on **bytes**, because bytes are what Argon2id actually
receives: a four-character non-ASCII credential is measured at twelve bytes, and
a three-character one is refused however substantial it looks.

An over-long password is **refused**, never truncated. A silently shortened
credential is not the one the operator chose.

Every policy failure renders as one opaque message, so the policy's shape is not
an oracle.

## Credentials are never stored

A password is hashed and dropped. It is never persisted in any form, never
logged, and never printed. `PasswordVerifier` redacts its own `Debug` and
`Display`, and `PrincipalRecord`'s `Debug` is written by hand so a derived
format can never start printing the verifier if that type is ever replaced.

## Session tokens

On successful authentication:

1. a 256-bit bearer token is drawn from the OS CSPRNG (`getrandom`);
2. it is hashed with SHA-256;
3. a 256-bit CSRF token is drawn independently;
4. the digest, the CSRF token, and a finite expiry are persisted;
5. the raw token and CSRF token are returned to the caller **once**.

**Only the digest is stored.** This is enforced by the type system rather than by
convention: `StateStore::insert_session` takes a `SessionTokenDigest`, and no
method in the persistence layer accepts a `SessionToken`. A stolen database
yields no usable session cookie, because a digest cannot be inverted.

Lookup always hashes the presented token *before* it reaches a query. Expiry is
inclusive: a session is already invalid on its expiry second, and an expired
session is **deleted** on lookup rather than left to rot.

Session lifetime is finite — twelve hours by default — with no remember-me mode.
An unbounded session is a permanent credential.

### The CSRF token is stored in the clear, on purpose

A CSRF token is not a credential. It is only meaningful when a browser echoes it
back in a header alongside the bearer token, and it cannot authenticate alone.
Storing it hashed would add a lookup and buy nothing. This is stated in the
migration file so the next reader does not "fix" it.

## Failure never distinguishes cause

An unknown username, a wrong password, and a disabled principal all return the
same `AuthError::CredentialsRejected`. If they differed, the surface would be a
username oracle — and Argon2id's cost would leak the difference too, because a
refusal that skipped the hash would be dramatically faster.

For the same reason, a storage failure during the lookup that precedes
verification also collapses into `CredentialsRejected`. Failures *after* a
password has verified are reported distinctly (`SessionUnavailable`,
`StorageUnavailable`), because telling a correct password from an incorrect one is
exactly what this type must never do.

A refused login is not an overload: `WorkerError::Rejected.is_refusal()` is true
and `is_overload()` is false, so a caller cannot accidentally retry it — which
would turn a wrong password into unbounded Argon2 work.

## Authentication runs only on the bounded worker

Argon2id at this policy costs ~19 MiB and tens of milliseconds per verification.
That is the work factor that makes an offline attack on a stolen verifier
expensive, and it is far too expensive to run on a Tokio worker thread. Worse,
unbounded concurrent verification is precisely the CPU denial of service the
management roadmap warns about.

So credential verification crosses the same **bounded** MPSC queue as every other
management operation. A login flood is refused with `503` rather than becoming a
backlog of pending hashes. Three architecture guards pin this: the HTTP boundary
may not name `argon2` or `PasswordVerifier` at all; `management::auth` may not
use `tokio::`; and the domain credential module stays pure — no I/O, no database,
no network.

## Password input has no argv or environment path

`wg-basic admin set-password` requires `--password-stdin`. The password is read
from this process's standard input, with exactly one trailing newline trimmed.

- A password in `argv` is readable by every process on the host through
  `/proc/<pid>/cmdline`.
- A password in the environment is inherited by every child process.
- Without the flag the command does nothing, so a password can never arrive by
  accident through a pipe something else happened to provide.

Only the trailing newline a terminal or `echo` adds is removed. Every other byte
is preserved, because a silently altered password is a credential the operator
did not choose and would have to debug by guessing.

## One transaction for reset and revocation

`reset_password_and_revoke_sessions` writes the new verifier and deletes every
session for that principal inside one `IMMEDIATE` transaction. A password change
that failed to revoke sessions would leave a stolen cookie valid after the
operator changed the password specifically to lock the attacker out, so the two
must not be separable.

Provisioning and reset are deliberately the same operation: both set a new
verifier for a username, and both must leave no usable prior session.

## What authentication must never do

It must not touch desired state. A login is not a configuration change, and
reconciling the kernel because someone authenticated would be a serious defect.
No credential or session method writes to `installation`, and none advances
`desired_generation`; this is asserted across the full lifecycle through the
worker.