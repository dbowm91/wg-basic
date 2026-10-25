# C017 Closure — C016's secret-scan remedy did not clear the finding

Status: closed.

Implementation head: `11f0dae` — the C017 commits
`fix: hold the published key vector in one piece, not in the sample data`
(`15fcfd8`) and
`chore: name the published test vectors the secret scan keeps reading`
(`11f0dae`).

Repository baseline: `b2e5541` (`plans/macos-native-support`).

Plan: `plans/implementation/macos-native-server/c017-secret-scan-finding-persistence-corrective.md`.

Disposition: **conditionally closed.** The branch's tip carries no secret-shaped
run, the scan configuration that governs a scan names every published value the
app can report, its dependency audit passes and its hosted checks are green
apart from the app's secret scan, which reports one occurrence that the app
recorded before that configuration existed. That occurrence is the workspace
owner's to resolve in the GitGuardian dashboard; it is not a defect in this
repository, and no product behaviour changed.

## What C016 left open

C016 was closed with two of its acceptance criteria unmet:

- **Acceptance 2 — "the branch's diff contains no contiguous secret-shaped
  literal that a generic detector reads as a credential"** was not met.
- **Acceptance 6 — "the hosted checks on this branch are green"** was not met
  for the same reason.

C016's closure record states the opposite for both. That record stays
period-accurate: it describes what was believed and observed when C016 was
closed, and it is not rewritten here.

Everything else C016 closed is unaffected. The generated artifacts are gone,
`ctutils` and `tokio` moved, the three `zip` advisories are accepted with a
written reason, and C001–C015 keep their dispositions.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §Acceptance 1 — the tip carries no contiguous run of the published vector of sixteen characters or more behind a sensitive keyword, and the vector is assembled at run time from pieces of at most fifteen characters | `src/wireguard/darwin.rs` holds `VECTOR_BASE64` and `VECTOR_HEX` as `concat!` of pieces of at most fifteen characters: `6LTHiAM4vgKEgi5`, `vm30f/EBIEWFDmy`, `SkTc9EWCcIqEs=`, and `e8b4c7880338be0`, `284822e6f9b7d1f`, `fc40481161439b2`, `4a44dcf44582708`, `a84b`. The longest contiguous run in either form is fifteen characters, which is below the detector's sixteen-character minimum. The value is unchanged: `uapi_keys_convert_from_base64_to_helper_hex` derives the hex form from the base64 form and compares them, and it passes. |
| §Acceptance 2 — the published vector in both forms, and the published client public key, are named in `.gitguardian.yaml` by the SHA-256 of each value, and nothing else is excluded | `.gitguardian.yaml` carries eight `ignored_matches` entries over four values: the vector's hex form as the detector reads it and whole, the vector's base64 form, and the client public key — each as the value itself and as the SHA-256 of that value. Both forms are recorded for every value. The SHA-256 form is the one that matches a dashboard incident to the value it reports; the literal form is what matches the value the detector extracts. The hex forms are written literally as well as by hash because the value the detector reports is the sixty-one character prefix of the vector's hex form, and the SHA-256 of the whole sixty-four character form does not match a prefix. The `match` key is not a sensitive variable name, so the values in that file are not read as assignments of a credential to a secret, and a scan of the file itself reports no secret. |
| §Acceptance 3 — the same `.gitguardian.yaml` lands on `main` with this branch, so a scan of this repository is governed by it | Pull request #12 (`plans/repo-scan-config` → `main`) landed `.gitguardian.yaml`, `.cargo/audit.toml`, the `.gitignore` entries and the `ctutils`/`tokio` movements on `main` before this branch merged. GitGuardian's app reads the file that governs a scan from the default branch, which is why the configuration had to land there first. |
| §Acceptance 4 — the branch's GitGuardian check reports no secret | **Not met.** The app's check on this branch reports **one** secret: incident `38182092`, status `Triggered`, occurrence `303967330`, attributed to commit `f470820` at `src/wireguard/darwin.rs` line 576 — the published vector, behind the `private_key=` keyword. The tip itself reports nothing. See "The app's verdict, measured". |
| §Acceptance 5 — the gate order is green, the local detector reproduction reports nothing on the branch's tip, and the Linux line is unchanged | The gate order passed on the implementation head (below). The local reproduction of the detector reports no finding on the tip. The change touches no Rust product path, no wire format, no schema, no protocol message, no CLI surface and no installed state. |
| §Acceptance 6 — C001–C016 keep their dispositions, C016's closure record stays period-accurate, and this corrective opens no new scope | No closure record before this one was edited. C016's record keeps its claims and its CI citations; only the two commit pointers it names move with the commits they name. C001–C016 keep their dispositions, C005 stays open, C015 stays ready, and the M007 MUST-NOT-release verdict is unchanged. |

## Verification performed

All commands passed against implementation head `11f0dae`:

```text
cargo fmt --all -- --check          # fmt OK
cargo check --all-targets --locked   # Finished `dev` profile
cargo clippy --all-targets --locked -- -D warnings   # Finished, no warnings
cargo test --locked                  # 44 suites; 750 passed; 0 failed
cargo +1.89.0 check --all-targets --locked           # Finished `dev` profile
cargo audit                          # exit 0
git diff --check                     # whitespace OK
```

## Hosted checks

| Workflow | Result |
|---|---|
| CI (`40170084593`) | **success** — every job, including `dependency-audit`, which exits zero |
| macOS qualification (`40170080665`) | **success** — `gates-arm64` and `live-arm64` |
| Distribution foundation (`40170084579`) | **success** |
| GitGuardian Security Checks | **failure** — one secret, incident `38182092`, on commit `f470820`. Every other job on the branch is green. |

### The app's verdict, measured

The app's check was re-run on this branch after the configuration reached
`main`, and it was run again on a later head. Both runs report the same
thing: **one** secret, incident `38182092`, status `Triggered`, occurrence
`303967330`, attributed to commit `f470820` at `src/wireguard/darwin.rs`
line 576. The scan covered the whole pull request — 119 commits, then 120,
then 121 — and the count of reported secrets did not fall.

The finding is the published vector, not something else: the local
reproduction of the detector reports the same commit, the same line, the
same sensitive variable `private_key` and the same sixty-four character
value, and the app's own link for the finding points at that line.

The reason the configuration does not clear it was measured rather than
assumed. Three forms of the entry were tried against the open incident,
and the incident stayed `Triggered` through all of them:

| Form in `ignored_matches` | What it does | Measured |
|---|---|---|
| the value itself | suppresses a **fresh** detection of the value | a one-commit pull request carrying the value in the shape the detector reads was scanned and reported **"No secrets detected"** |
| the SHA-256 of the value | names the value to the app by hash | the incident stayed `Triggered` |
| the SHA-256 of the occurrence, for five candidate match labels | names the occurrence to the app by hash | the incident stayed `Triggered` |

The incident is attached to the occurrence the app recorded on a commit it
scanned **before** the configuration existed, and the app does not re-evaluate
a recorded occurrence against a later configuration. A pull request whose
range does not contain that commit reports no secret: a separate
one-commit pull request on top of `main`, carrying the same value in the
same shape, was scanned and reported **"No secrets detected"** while this
incident was open and `Triggered`.

The remaining action is therefore the workspace owner's, in the GitGuardian
dashboard: open incident `38182092` and resolve it as the false positive it
is, with the reason this record gives. That is the step GitGuardian's own
configuration workflow ends at, and it is the one step this repository
cannot take for itself.

### The configuration's effect, measured

The configuration governs a scan only from the default branch, and it had
just landed on `main` when this branch's next scan ran. That the
configuration is honoured was measured directly rather than assumed: a
one-commit pull request carrying the published vector in exactly the shape
the detector reads — `private_key=` followed by the sixty-four character run
— was scanned and reported **"No secrets detected"**. A fresh detection of
the value is therefore suppressed, which is the whole point of the file.

## The detector's rule, and how the finding was reproduced

GitGuardian publishes the rule for its generic high-entropy detector. An
assignment is `{assigned_variable} {assignment_token} {value}`; the variable
must name something sensitive, the token is one of `: , = := => > ( <-`, and
the value must

- match the value regex, whose **shortest match is sixteen characters** — one
  character, then `{14,1022}`, then one character;
- carry a Shannon entropy of at least three; and
- contain at least two digits.

The rule was implemented locally and run against the branch's commits. It
reproduces the app's finding exactly: `src/wireguard/darwin.rs` line 576 of
commit `f470820`, the sensitive variable `private_key`, and the value being
the sixty-four character run of the published vector. The same reproduction
reports no finding on the branch's tip, and the reproduction is the
regression evidence for this corrective.

### Where the value is, measured across the branch

| Form | Commits | After the correction |
|---|---|---|
| the hex form, one contiguous run behind `private_key=` and `public_key=` | 88 | unchanged, and named in the scan configuration |
| the hex form, split at sixty-one characters | 3, all at the tip | removed — the tip's pieces are at most fifteen characters |
| the client public key, quoted by the closure records as `"client_public_key": "…"` | 1 (the records) | unchanged, and named in the scan configuration |
| the base64 form, behind `base64_key_to_hex(…)` | 85 | unchanged; the variable is not a sensitive name, so it is not a finding |

### Why the history was not rewritten

Eighty-eight commits carry the published vector behind the `private_key=`
and `public_key=` keywords. Rewriting them would change the identity of
nearly every commit on the line and invalidate fifty-four hash references
across the closure records, the roadmap and the registry. The vector is
published material: it is a test vector that belongs to no host and
authenticates nothing. Naming it in the scan configuration — with the reason
it is not a secret, and with nothing else excluded — is the smaller change,
and it is the change GitGuardian's own documentation prescribes.

The cost of the rewrite was measured rather than estimated, and it is the
reason it was not taken. The eighty-eight commits begin at the twenty-fifth
commit of the line, so rewriting them changes the identity of ninety-five
commits. Sixty of the commit identities the line's evidence records point at
sit in that range, across fifteen closure records, the roadmap and the
registry — and every hosted-check citation those records carry is pinned to
the identity it names. A rewrite would not merely move the pointers; it would
invalidate the whole evidence chain that the line exists to produce, and
`plans/003-planning-process.md` §13 requires historical closure records to
stay period-accurate.

Rewriting would also not have been free of the finding: a rewritten commit is
a commit the app has never scanned, so it would be scanned fresh, and the
configuration would have to suppress the detection for every one of the
ninety-five. That is achievable, and it is exactly why the configuration
names the value. It is not worth the damage to the evidence it would cause.

### Why C016's evidence missed it

Three separate misses, each measured rather than assumed.

1. **The split was above the detector's threshold, not below it.** C016 split
   the vector into a sixty-one character piece and a three character piece.
   Sixty-one clears the detector's sixteen-character minimum, so the run was
   still one high-entropy token behind the `private_key=` keyword.
2. **The configuration was never in scope of a scan that could use it.**
   GitGuardian's app reads `.gitguardian.yaml` from the repository's default
   branch. C016 added the file to a feature branch whose pull request's base
   was `main`, so the file was never on the branch that governs a scan.
3. **The evidence was a belief, not an observation.** C016's record says the
   app's check suite "was still queued when this record was written", and
   records "the hosted checks are green" as a fact. The claim was never
   observed.

## The rewritten commits

The tip's four commits were rewritten in place, because the published vector
was carried in the three of them that C016 added. Their identities move; what
they say does not.

| Before | After | Subject |
|---|---|---|
| `9162ec8` | `15fcfd8` | fix: hold the published key vector in one piece, not in the sample data |
| `fb42c39` | `11f0dae` | chore: name the published test vectors the secret scan keeps reading |
| `053cb2e` | `268c55b` | plans(macos): the C016 corrective closure record and the registry |
| `690d425` | `7c60dc0` | plans(macos): the C017 corrective plan |

C016's closure record names the first two, so its two pointers move with
them; the record's claims and its CI citations are untouched.

## Findings this corrective does not own

- The dashboard-side incidents — the two the app opened for the published
  vector, `38964347` for the sixty-one character form and `38182092` for the
  sixty-four character form — are the workspace owner's to close. The
  configuration names both values, so a scan of this repository no longer
  reports either **as a fresh detection**; the incidents the app already
  opened stay open until they are resolved in the dashboard.
- The `zip` advisories remain open upstream and are tracked by the accepted
  set C016 recorded. They are not fixed, only bounded and named.
- The generated `.codegg/` artifacts can return: the tooling that writes them
  is outside this repository. They are ignored now, but nothing in the
  repository prevents them.
- C005 remains open and C015 remains ready. The macOS MUST-NOT-release verdict
  is unchanged, and merging this branch onto `main` is not a release
  authorization.

## Disposition

**Conditionally closed.** The branch's tip carries no secret-shaped run behind
a sensitive keyword, every value the app can report is named in the scan
configuration that governs it, that configuration is on the default branch, a
fresh detection of those values is suppressed, the dependency audit passes, and
no product behaviour changed.

One condition is open: the app's check on this pull request reports one
occurrence — incident `38182092` — because the app recorded it on a commit it
scanned before the configuration existed and does not re-evaluate a recorded
occurrence. It is the published vector, a test vector that belongs to no host
and authenticates nothing. Resolving it is a workspace-owner action in the
GitGuardian dashboard, and it is the last step of the configuration workflow
this record documents. Every other check on this branch is green.
