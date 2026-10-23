# Product Management M006 Closure — Operator shell sign-in and visibility corrective

Status: closed.

Implementation commit: `61cb753` — `fix(panel): name the login controls and let
the hidden attribute win`.
Planning baseline: `plans/macos-native-support@3d8a59a`.
Plan: `plans/implementation/product-management/006-operator-shell-sign-in-and-visibility-corrective.md`.
Disposition: **closed**. The operator shell signs in, and the elements it marks
hidden are hidden.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §11.1 The shell's login form posts its username and password | `index.html` gives the login controls `name="username"` and `name="password"`. A real Chrome submits the shell's **own** login form and reaches the signed-in dashboard (`login-done:signed-in`). The rendered DOM carries both names. The endpoint was already correct: the same credentials posted to `/api/v1/login` return `200`. |
| §11.2 A marked-hidden element is not rendered | `app.css` declares `[hidden]{display:none !important}`. The rendered DOM after sign-in carries `<form id="create-form" class="inline-form" hidden="">`, `<p id="empty-clients" class="note" hidden="">` and `<p id="empty-audit" class="note" hidden="">`, and none of the three is visible on screen. |
| §11.3 The Add-client form appears and disappears | **Add client** reveals the form; **Cancel** sets the `hidden` attribute again, and the element is off screen. Before the fix, Cancel was a no-op. |
| §11.4 No empty-state note contradicts a populated view | The dashboard renders the client table and the activity log with no "No clients yet" and no "No activity recorded yet" beside them. |
| §11.5 The 409 and 202 notices render where they are raised | The banner moves into the client editor while the editor is open and returns to its page slot when it closes. A `409` produced by a stale editor renders **inside** the dialog in the warning colour, above the editor's own heading. Before the fix it rendered behind the dialog backdrop. |
| §11.6 Success, warning and failure are visually distinct | `message()` takes a level and the stylesheet maps `info`, `success`, `warning` and `danger` onto token pairs. The conflict and pending-enforcement notices are warnings, a failed save is a danger, and "You have signed out." is informational. |
| §11.7 The route selects and fieldsets share the panel's language | `select` is styled with `input`; `fieldset` and `legend` use the panel's border, radius and uppercase muted legend. This branch carries four fieldsets and two selects that M005 did not have. |
| §11.8 The regression guard fails on the pre-fix assets | `the_operator_shell_cannot_outrank_its_own_hidden_attribute_or_omit_a_credential_name` was run against the pre-fix assets, where it **FAILED** on the stylesheet assertion (`the stylesheet declares how the hidden attribute renders`), and against these assets, where it passes. The architecture guard suite is 69 tests, one more than before. |
| §11.9 The gate order is green, and the Linux line is unchanged | The gate order passed on this head (below). The change touches three asset files and one test file; no Rust source changed, no wire format, schema, protocol message, CLI surface, or installed state changed, and no Linux backend was touched. |
| §11.10 M005's closure record stays period-accurate | `plans/closure/product-management/005-status.md` is unchanged. This record carries the new evidence. |

## Verification performed

All commands passed against implementation head `61cb753`:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 44 suites; 751 passed, 0 failed, 16 ignored
cargo +1.89.0 check --all-targets --locked
git diff --check
```

## Browser evidence

The review host's browser tooling could not type into a password field, so the
shell was driven by Google Chrome in headless mode against the appliance's own
served assets. The driver page is the appliance's own `index.html` with one
extra script appended that operates the appliance's own controls; the script
never re-implements the shell. Requests were forwarded to the appliance over a
local same-origin proxy that rewrites `Host` and `Origin` to the appliance's
canonical origin, because the appliance admits unsafe methods only from that
exact origin.

- **Sign-in.** The driver fills the shell's login form and calls
  `requestSubmit()` on it. The pre-fix shell and the fixed shell were driven
  **side by side on the same origin, through the same proxy, with no injected
  session** — so the only difference between them is the shell itself:

  ```text
  pre-fix shell -> <title>login-done:still-signed-out</title>
  fixed shell   -> <title>login-done:signed-in</title>
  ```

  The endpoint agrees with the diagnosis: `POST /api/v1/login` with an empty
  body answers `401`, and with the correct credentials answers `200`.
- **Hidden elements.** After sign-in, the rendered DOM carries `hidden` on
  `#create-form`, `#empty-clients` and `#empty-audit`, and the rendered screen
  shows the client table and the activity log with no contradicting note.
- **Add and Cancel.** **Add client** reveals the create form; **Cancel**
  removes it again.
- **Dialog-scoped notice.** The driver opens the client editor, bumps the
  generation out of band through the API, then saves from the stale editor.
  The appliance answers `409` and the banner renders **inside** the editor, in
  the warning colour, with the refreshed client list visible behind it.

## Security, ownership, and findings

The shell remains an API client, not a second authority: setup, client state,
credentials, generation checks, enrollment, and telemetry remain worker and
API responsibilities, and nothing in this change touches a privileged path.

No secret enters browser storage. The one-time token stays in the URL
fragment; the configuration and the QR stay in transient page memory and are
cleared when the editor closes. Naming the login controls gives the browser's
own form submission the two values it was always meant to carry; it adds no
credential store, no second authentication surface, and no new path for a
credential to travel. The login request still requires the exact configured
`Origin`, still carries no CSRF token, and still returns the same generic
failure message.

No inline script and no inline style were added, so the `default-src 'self'`
content security policy still needs no concession. The architecture guard that
pins that property still passes.

**Findings this corrective does not own** (recorded here and routed to the
product-management line; none is a sign-in or visibility defect, and M005's
closed scope is not reopened for them):

1. The login failure message is the same for `401`, `429` and `503`. The
   appliance distinguishes them and answers a rate-limited attempt with
   `429` and a `retry-after` header; the shell tells the operator their
   password was not accepted.
2. The setup form's default public endpoint is a `value`, not a placeholder,
   so it reads as a real configured endpoint.
3. There is no server-settings view after the one-shot setup, so the endpoint
   and listen port cannot be changed later from the shell.
4. The seven-second telemetry poll rebuilds the whole client table, which
   destroys keyboard focus during interaction.
5. The one-time link's **Copy link** writes to the clipboard without a guard;
   `navigator.clipboard` is absent on a non-secure origin.
6. The enrollment landing page is unstyled and shares no design language with
   the shell, and it is the surface a recipient actually sees.
7. `.state-ok` and `.state-warn` are declared and never used; the State column
   has no visual treatment and prints the raw observation string.
8. The activity list prints raw resource identifiers and lowercase action
   verbs, and the handshake age is printed in raw seconds.
9. The client table's headers carry no `scope` and the table has no caption;
   at phone width the Actions column sits outside the scroll viewport with no
   affordance.

**One pre-existing overage.** The five embedded assets total 36,188 bytes on
this head, against 34,714 on the baseline and 29,811 at M005's implementation
head. The baseline had already passed M005's 32 KiB aggregate ceiling before
this corrective; the growth is the macOS line's IPv6 and routed-LAN shell
additions, and this change adds 1,474 bytes. No test asserts the ceiling.
Recorded here for the product-management line rather than reopened here.

## Known limitations

The browser evidence in this record was produced on the review host against the
appliance's own embedded assets over a local proxy, not in the appliance's
intended deployment. The static guard, not the browser, is the regression
evidence that will keep running in CI; the browser evidence establishes what
the shell does today.

The rootful suites were not run for this corrective. The change touches no
kernel path, no namespace, and no host state, so no rootful leg bears on it;
the ordinary gate order is the applicable evidence.
