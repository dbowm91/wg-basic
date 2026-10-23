# Product Management M007 — Operator shell QR presentation corrective

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/product-management/007-status.md`.
Baseline: `plans/m006-operator-shell-sign-in-corrective@f7386ac` (itself based
on `plans/macos-native-support@3d8a59a`).
Source: `plans/implementation/product-management/005-embedded-product-ui-and-phase8-qualification.md`;
`plans/closure/product-management/005-status.md` (implementation head `8b20a7c`);
`plans/implementation/product-management/006-operator-shell-sign-in-and-visibility-corrective.md`;
`plans/closure/product-management/006-status.md` (implementation head `61cb753`).
Canonical requirements and ADRs: ADR-004 (the product mutation, enrollment and
API semantics); `plans/000-long-term-specification.md` §1 (the product
definition names "scan a QR code") and §2 goal 4 ("render QR enrollment").
Authority: `plans/003-planning-process.md` §5 (implementation plans), §13
(corrective passes), §14 (registry); `AGENTS.md`.
Primary class: corrective — a material post-implementation defect in the
operator shell's QR artifact presentation.

## 1. The defect, as observed

The shell renders the client editor as a scrollable modal:

```css
dialog{width:min(42rem,calc(100vw - 2rem));max-height:90vh;overflow:auto;...}
```

and places the artifact area — the download link, the QR code and the one-time
link — as the **last child** of that dialog, below the edit form:

```html
<form id="edit-form" class="form-grid"> ... </form>
<div class="artifact-actions"> ... </div>
<div id="artifact" hidden></div>
```

`#artifact` was therefore always rendered *after* the tall edit form, in a
container whose visible height is `90vh`. Pressing **Show QR code** appended the
QR image to that area and nothing moved the operator's attention to it. Measured
in the shipped shell, with the dialog opened and **Show QR code** pressed, and
no scrolling performed by the driver:

| Viewport | Dialog visible height | QR code top | Result |
|---|---|---|---|
| 1280×800 | 720 px | 791 px | the code was **entirely below the visible region** |
| 390×844 @3× | 760 px | 1141 px | the code was **entirely below the visible region** |
| 900×1250 | 1125 px | 791 px | the code was visible but its **bottom edge was cut** by the dialog's lower boundary |
| 1024×560 | 504 px | 1226 px | the code was **entirely below the visible region** |

The consequence is that the shell's headline enrollment flow did not work on a
screen: the operator pressed **Show QR code**, saw no code, and had to guess
that the dialog scrolled. In the taller window the dialog's lower boundary cut
the code, which removes a finder pattern and makes the code unreadable.

The rendering itself was correct. The same SVG, decoded straight from the
`/qr` endpoint, decoded to the exported configuration at every scale down to
one pixel per module, and its content was correct in every field: the private
key derives exactly the public key the API reports for that client, the peer
key is the server's own public key, and the address, routes and endpoint match
the API. The defect was entirely one of *presentation*: a correct code, shown
where the operator could not see it.

It was found by decoding the **rendered pixels** rather than the served file.
The served SVG decoded; the screenshot of the shell did not.

## 2. Why the earlier evidence missed it

M005's closure evidence is an API and HTTP evidence set. It asserted that the
QR endpoint answers `200 image/svg+xml`, that the SVG carries a four-module
quiet zone and integer coordinates, and that the embedded configuration text is
never copied into the SVG as visible text. Every one of those assertions is
true of the defective shell, and they are the right assertions for the artifact
*format*.

What they never did was **render the shell and read the code off the screen**.
"Does this QR decode" is not a property of the SVG; it is a property of the
SVG *and* the page geometry around it. A QR that renders half outside its
container is exactly as well-formed as one that renders whole, and only the
second one can be scanned.

M006 corrected the shell's sign-in and visibility defects and re-established
that the shell renders — but its browser evidence covered the login form, the
`hidden` attribute and the modal-scoped notices, and it did not open the
client editor and render an artifact. The defect was reachable in M006's
evidence set and was not read.

## 3. The change

### 3.1 A rendered artifact is brought into view

`app.js` gains one helper:

```js
function revealArtifact(target) {
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  target.scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
}
```

and every artifact branch calls it once the artifact exists: the configuration
download link, the one-time link, and the QR code. The artifact is scrolled
into the **middle** of the editor's visible area rather than merely nudged
into it, so the code is never flush against the dialog's edge with its quiet
zone half outside. `prefers-reduced-motion` is honoured, so an operator who
asks for reduced motion gets an instant jump instead of an animation.

### 3.2 The QR branch reveals on the image's load

The QR image is fetched asynchronously. Revealing the artifact before the
image has loaded would measure an artifact area that does not yet contain the
code, and the code would still be out of view. The QR branch therefore reveals
on the image's `load` event, and also reveals immediately when the image is
already complete (a cached response).

The reveal is idempotent and has no failure mode: it is a scroll, it changes
no state, it issues no request, and it does not move the artifact's position
in the document.

### 3.3 Nothing else moves

The artifact stays where it is in the document, the editor keeps its layout,
and the banner keeps the modal-scoped placement M006 gave it. A second modal
for the artifact was considered and rejected: M006 moved the banner *into* the
editor so the 409 and 202 notices render where they are raised, and a second
modal above the editor would put those notices behind a new backdrop.

## 4. Unclosed requirements and defects this corrective owns

| Requirement | State at the M006 head | Closed by |
|---|---|---|
| Spec §1 "scan a QR code … and have a working VPN" | the code was correct and unreachable on screen | §3.1 |
| Spec §2 goal 4 "render QR enrollment" | the code rendered below the fold | §3.1 |
| M005 §3 Clients — config and QR export | the export produced a correct artifact that the operator could not see | §3.1 |
| M005 §6 Secret artifact UX | the artifact area existed but was off-screen | §3.1, §3.2 |

**Not owned here, and deliberately not reopened:** the remaining review
findings recorded in the M006 closure record that are neither sign-in,
visibility, nor artifact-presentation defects — the login error message
conflating `401`, `429` and `503`; the setup form's default endpoint reading as
a real value; the absence of a server-settings view after setup; the
seven-second poll rebuilding the client table; the unguarded clipboard write;
the unstyled enrollment page; the unused `.state-ok`/`.state-warn` rules; raw
identifiers and raw durations in the activity list; and the missing table
semantics. They stay routed to the product-management line.

## 5. Privilege and security effects

None. The change adds no capability, socket, identity, file ownership, or
protocol operation, and it touches no Rust path.

The QR code still carries the client's private key, exactly as before: the
artifact is unchanged, only its position on the screen changes. The code stays
in transient page memory, is never written to `localStorage` or
`sessionStorage`, and is never logged. The reveal is a scroll of an element the
operator just asked for; it discloses nothing that was not already on the
page. The content security policy needs no concession — the change adds no
inline script and no inline style.

## 6. Compatibility effects

No wire format, schema, protocol message, CLI surface, or installed state
changes. The management HTTP surface, the client enrollment format, the typed
IPC vocabulary, the desired-state store, and the Linux and Darwin backends are
untouched. The shell remains a buildless, framework-free, compile-time embedded
set of five files with no external origin and no build step.

The embedded asset inventory grows by the size of the helper and its four call
sites; the aggregate is recorded in the closure record.

## 7. Failure, cancellation, and contention semantics

The reveal has no failure mode: if the artifact area is already in view, the
scroll is a no-op; if the operator scrolls away afterwards, the code is still
there. If the QR image fails to load, the existing `error` handler removes the
image and reports "QR export is unavailable." and the reveal never runs, so
nothing scrolls to an empty area.

The reveal is not tied to the polling cycle and introduces no request, timer,
or cancellation surface. It does not change the artifact's lifecycle: closing
the editor still clears the artifact DOM and revokes the object URL, as M005
required.

## 8. Regression evidence

`tests/architecture_guards.rs` gains
`the_operator_shell_must_bring_a_rendered_artifact_into_view`, which asserts
that:

- the artifact path calls a reveal helper, so an artifact rendered into the
  editor's last child is brought into view; and
- the reveal scrolls with `block: "center"`, so the whole code is on screen
  rather than flush against the editor's edge; and
- the QR branch waits for the image's `load` event, so the reveal measures an
  artifact area that already contains the code.

The guard was checked against the pre-fix assets, where it **fails** on all
three assertions, and against these assets, where it passes. It is a static
guard and needs no browser.

The browser evidence is separate and is recorded in the closure record: a real
Chrome opens the shell, opens a client, presses **Show QR code**, and the
rendered code is measured against the editor's visible region and decoded from
the captured pixels.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

## 10. Documentation updates

- `plans/closure/product-management/007-status.md` (new) — this corrective's
  closure evidence.
- `plans/registry.md` — the product-management row and the closure note.

No operator procedure changes and no architecture document changes: current
behavior stays factual, and the artifact's behavior after this corrective is
the behavior the architecture documents already describe.

## 11. Acceptance criteria

1. Pressing **Show QR code** brings the code into the editor's visible area
   without the operator scrolling.
2. The code's bounding box lies wholly inside the editor's visible region and
   wholly inside the viewport, at every viewport the qualification uses.
3. The code read from the operator's screen decodes to the exported
   configuration, byte for byte.
4. The configuration download and the one-time link are revealed the same way.
5. An operator who asks for reduced motion gets no scroll animation.
6. The regression guard fails on the pre-fix assets and passes on these.
7. The gate order is green, and the Linux line is unchanged.
8. The M005 and M006 closure records stay period-accurate; this corrective and
   its closure record carry the new evidence.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- the reveal turns out to need a second modal or a layout change to the editor
  form, which would reopen the banner placement M006 established;
- the reveal turns out to break the focus order or a screen reader
  announcement;
- the scroll turns out to be unreliable across the browsers the shell claims
  to support, in which case the artifact area's position in the document is
  reconsidered instead;
- fixing this turns out to require a change to a closed Linux contract.

## 13. Closure evidence requirements

`plans/closure/product-management/007-status.md` must record: the
implementation head and baseline, the requirement-to-evidence matrix against
§11, the exact commands and their output, the browser evidence per viewport
(the measured geometry, before and after the fix, and the decode of the
captured pixels), the guard's failure against the pre-fix assets, the asset byte
inventory, the findings that this corrective does not own, and an explicit
disposition. The M005 and M006 closure records keep what they observed and are
not rewritten.
