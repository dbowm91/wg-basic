# Product Management M006 — Operator shell sign-in and visibility corrective

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/product-management/006-status.md`.
Baseline: `plans/macos-native-support@b2e5541`.
Source: `plans/implementation/product-management/005-embedded-product-ui-and-phase8-qualification.md`;
`plans/closure/product-management/005-status.md` (implementation head `8b20a7c`).
Canonical requirements and ADRs: ADR-004 (the product mutation, enrollment and
API semantics).
Authority: `plans/003-planning-process.md` §5 (implementation plans), §13
(corrective passes), §14 (registry); `AGENTS.md`.
Primary class: corrective — a material post-implementation defect in the
operator shell.

## 1. The defect, as observed

Two defects, both in the embedded operator shell, both invisible to the
API-level evidence M005 closed on.

### 1.1 The panel could never be signed into

`src/http/assets/index.html` gave its login form's username and password
controls `id` attributes but no `name` attributes. `src/http/assets/app.js`
reads a form with

```js
const form = (id) => Object.fromEntries(new FormData($(id)).entries());
```

`FormData` contains only *named* successful controls, so the login form yielded
an empty entry set. The panel posted `{}` to `/api/v1/login`, the appliance
answered `401`, and the shell displayed "Those credentials were not accepted."
— for every operator, with every password, including the correct one. Observed
directly in a browser against the shipped assets: `FormData keys: []`,
`Serialized body: {}`. The API itself was never at fault: the same credentials
posted to `/api/v1/login` returned `200`.

### 1.2 Elements the shell marks `hidden` were on screen

`src/http/assets/app.css` declares `.inline-form{display:flex}` and
`.help,.note{display:block}`. An author `display` declaration outranks the user
agent's `[hidden]{display:none}`, so three elements the shell marks `hidden`
were rendered regardless of the attribute:

- `#create-form` — the Add-client form was open on every load, and its
  **Cancel** button was a no-op, because the `hidden` attribute it set was
  overridden by the same declaration that styled the form;
- `#empty-clients` — "No clients yet. Add a client to create its first
  connection." rendered beneath a populated client table;
- `#empty-audit` — "No activity recorded yet." rendered beneath a populated
  activity log.

## 2. Why the earlier evidence missed it

M005's closure evidence is an API and HTTP evidence set. It drove setup, the
client lifecycle, export, QR, one-time enrollment, telemetry and audit over
authenticated HTTP, and it asserted *properties of the asset files* — no
external origin, no inline script or style, no browser credential storage, no
secret console logging, and an aggregate byte inventory. Every one of those
assertions is true of the defective shell.

What that evidence never did was **render the shell and submit its own login
form**. The HTTP login test builds its JSON body inside the test, so it
exercised the endpoint and never the page's `FormData` path; the asset guards
read file contents, so they cannot see a cascade outcome.

The `hidden` defect is the same kind of gap. "Is this element visible" is not
a property of the markup. It is a property of the markup *and* the stylesheet,
and it can only be established by rendering the two together.

## 3. The change

### 3.1 The login form names its controls

`index.html`'s login form gives `name="username"` and `name="password"` to its
two controls. Nothing else about the login path changes: the same endpoint,
the same exact-`Origin` rule, the same CSRF-free session cookie, the same
generic failure message.

### 3.2 The hidden attribute wins

`app.css` declares `[hidden]{display:none !important}` ahead of the other
rules. The attribute is the shell's only visibility mechanism — `app.js` sets
it and nothing else — so it has to outrank every author `display` rule. The
`!important` is load-bearing: without it, `.inline-form` and `.note` win on
source order and the defect returns.

### 3.3 Status messages carry a severity, and follow the operator's attention

`app.js`'s `message()` takes a level (`info`, `success`, `warning`, `danger`),
records it as `data-level`, and `app.css` maps each level to a token pair.
The 409 conflict and the 202 pending-enforcement notice are warnings, a failed
save is a danger, and "You have signed out." is informational — previously all
of them rendered in the same red.

The banner also **moves into the client editor** while the editor is open and
returns to its slot in the page when the editor closes. Without that, the
severity split would have been a cosmetic change to a message the operator
still could not see: both the conflict notice and the pending-enforcement
notice are raised from inside the modal, and the banner used to render behind
the dialog's backdrop.

The banner's `role="alert"`/`aria-live="polite"` contradiction is resolved at
the same time: the element is `role="status"`, and a danger-level message
sets `aria-live="assertive"` before its text is written.

### 3.4 The form controls share one visual language

`app.css` styles `select` alongside `input` instead of leaving the route-mode
controls as native user-agent dropdowns, and gives `fieldset`/`legend` the
panel's own border, radius and uppercase muted legend instead of the user
agent's default. This branch carries four such fieldsets and two such selects
that M005 did not have, so the gap is larger here than it was on the M005 head.

## 4. Unclosed requirements and defects this corrective owns

Enumerated from the M005 requirement set:

| M005 requirement | State at the M005 head | Closed by |
|---|---|---|
| §3 Login — reuse the Phase 7 session surface | the surface existed and was unusable | §3.1 |
| §3 Dashboard — enabled/disabled client counts | counts rendered beside "No clients yet" | §3.2 |
| §3 Audit/status — bounded recent mutation history and safe status | history rendered beside "No activity recorded yet" | §3.2 |
| §3 Clients — action controls | the Add-client form was permanently open and Cancel inert | §3.2 |
| §11 Status messages not color-only | one red banner served success, warning and failure alike | §3.3 |
| §4/§5 The 409 and 202 notices are load-bearing | correct wording, rendered behind the modal backdrop | §3.3 |

**Not owned here, and deliberately not reopened** (M005 §13): the remaining
review findings against this shell — the login error message conflating `401`,
`429` and `503`; the setup form's default endpoint reading as a real value; the
absence of a server-settings view after setup; the seven-second poll
rebuilding the client table; the unguarded clipboard write; the unstyled
enrollment page; the unused `.state-ok`/`.state-warn` rules; raw identifiers
and raw durations in the activity list; and the missing table semantics. These
are recorded as findings in the closure record and routed to the
product-management line. None of them is a sign-in or visibility defect, and
this corrective does not reopen M005's closed scope to address them.

## 5. Privilege and security effects

None. The change adds no capability, socket, identity, file ownership, or
protocol operation, and it touches no Rust path.

It adds no inline script and no inline style, so the `default-src 'self'`
content security policy still needs no concession. No secret enters browser
storage: the one-time token stays in the URL fragment, and the configuration
and QR stay in transient page memory. Naming the login controls gives the
browser's own form submission the two values it was always meant to carry; it
adds no credential store, no second authentication surface, and no new path
for a credential to travel. The login request still requires the exact
configured `Origin`, still carries no CSRF token, and still returns the same
generic failure message for a wrong password, a rate-limited attempt, and an
unavailable service.

## 6. Compatibility effects

No wire format, schema, protocol message, CLI surface, or installed state
changes. The management HTTP surface, the client enrollment format, the typed
IPC vocabulary, the desired-state store, and the Linux and Darwin backends are
untouched. The shell remains a buildless, framework-free, compile-time embedded
set of five files with no external origin and no build step.

The aggregate embedded-asset size moves from 34,714 to 36,188 bytes on this
baseline. That baseline had already passed M005's 32 KiB aggregate ceiling
before this corrective (29,811 bytes at M005's head); the growth is the
macOS line's IPv6 and routed-LAN shell additions, not this change's. The
overage is recorded as a finding for the product-management line rather than
reopened here.

## 7. Failure, cancellation, and contention semantics

The login form's failure path is unchanged and still reports one generic
message. A successful login loads the console exactly as before.

The visibility change is a cascade rule, so it has no runtime failure mode: if
the stylesheet ever loses the `[hidden]` declaration, elements the shell marks
hidden become visible again — a presentation defect, not a safety one, and the
regression guard in §8 fails on that state.

The banner's relocation is a DOM move on dialog open and close. It is
idempotent, it preserves the message text across the move, and a dialog closed
by Escape runs the same `close` handler that returns the banner to its slot.
No request, no timer, and no cancellation surface is involved.

## 8. Regression evidence

`tests/architecture_guards.rs` gains
`the_operator_shell_cannot_outrank_its_own_hidden_attribute_or_omit_a_credential_name`,
which asserts that:

- the stylesheet declares a `[hidden]` rule carrying both `display:none` and
  `!important`, so an author `display` rule cannot outrank the attribute; and
- every control in the shell's login form carries a `name` attribute, because
  `FormData` drops unnamed controls and the panel would post an empty body.

The guard was checked against the pre-fix assets, where it **fails** on the
stylesheet assertion, and against the fixed assets, where it passes. It is a
static guard and needs no browser.

The browser evidence is separate and is recorded in the closure record: a real
Chrome submits the shell's own login form and reaches the signed-in dashboard;
the create form is absent until **Add client** is pressed and returns when
**Cancel** is pressed; and the 409 conflict notice renders inside the editor.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

## 10. Documentation updates

- `plans/closure/product-management/006-status.md` (new) — this corrective's
  closure evidence.
- `plans/registry.md` — the product-management row and the closure note.
- `architecture/product-management.md` and `architecture/management-http.md` —
  only if they describe the shell's login or visibility behavior; current
  behavior stays factual.

No operator procedure changes: the shell's flows are the ones M005 documented.

## 11. Acceptance criteria

1. The shell's login form posts its username and password; a correct
   credential reaches the signed-in dashboard.
2. An element the shell marks `hidden` is not rendered, whatever the
   stylesheet's other `display` rules say.
3. The Add-client form is absent until **Add client** is pressed, and **Cancel**
   removes it.
4. The dashboard never shows "No clients yet" beside a populated client table,
   and never shows "No activity recorded yet" beside a populated activity log.
5. The 409 conflict notice and the 202 pending-enforcement notice render
   inside the client editor, where they are raised.
6. A success, a warning and a failure are visually distinct.
7. The route-mode selects and the route fieldsets share the panel's visual
   language.
8. The regression guard fails on the pre-fix assets and passes on these.
9. The gate order is green, and the Linux line is unchanged.
10. The M005 closure record stays period-accurate; this corrective and its
    closure record carry the new evidence.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- the login fix turns out to need anything beyond naming the two controls —
  a new credential path, a change to the login endpoint's policy, or a
  different authentication surface;
- the `[hidden]` rule turns out to hide something the shell needs visible;
- the banner relocation breaks a screen reader announcement or a focus order;
- the stylesheet change widens the content security policy's needs;
- fixing the shell turns out to require a change to a closed Linux contract.

## 13. Closure evidence requirements

`plans/closure/product-management/006-status.md` must record: the
implementation head and baseline, the requirement-to-evidence matrix against
§11, the exact commands and their output, the browser evidence for the login
form, the hidden-element behavior and the dialog-scoped notices, the guard's
failure against the pre-fix assets, the asset byte inventory, the findings that
this corrective does not own, and an explicit disposition. M005's closure
record keeps what it observed and is not rewritten.
