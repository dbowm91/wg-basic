# Product Management M007 Closure — Operator shell QR presentation corrective

Status: closed.

Implementation commit: `f70730c` — `fix(panel): bring a rendered artifact into view`.
Planning baseline: `plans/m006-operator-shell-sign-in-corrective@f7386ac` (itself based on
`plans/macos-native-support@3d8a59a`).
Plan: `plans/implementation/product-management/007-operator-shell-qr-presentation-corrective.md`.
Disposition: **closed**. The client editor brings a rendered artifact into its visible
area, and the QR code an operator is told to scan is on screen and readable.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §11.1 Pressing **Show QR code** brings the code into the editor's visible area without the operator scrolling | `app.js` gains `revealArtifact()`, which scrolls the artifact into the middle of the editor's visible region. Measured in the shipped shell with the driver performing **no** scrolling of its own: the dialog's own scroll position moves from `0` to `452` px at 1280×800, to `453.5` px at 1280×800 @2×, to `724.3` px at 390×844 @3×, to `47` px at 900×1250 and to `668` px at 1024×560. |
| §11.2 The code's bounding box lies wholly inside the editor's visible region and inside the viewport | Measured after the reveal, with no manual scrolling: the code's box is `y 378.6–730.6` inside a dialog visible at `y 40–760` (1280×800); `y 378–730` inside `40–760` (1280×800 @2×); `y 459–772` inside `42–802` (390×844 @3×); `y 806–1158` inside `62–1188` (900×1250); `y 151–503` inside `28–532` (1024×560). `fullyInsideDialog` and `fullyInsideViewport` are true in every case. |
| §11.3 The code read from the operator's screen decodes to the exported configuration, byte for byte | The captured pixels of the rendered code decode to 217 characters identical to `/api/v1/clients/<id>/config`. The same capture at 1280×800 @2× and at 390×844 @3× decodes identically. |
| §11.4 The configuration download and the one-time link are revealed the same way | The three artifact branches were driven in the shipped shell: `qr` (an `IMG.qr-image`), `config` (an `A`) and `share` (a `P`). Each one scrolls the editor (`0 → 530`, `153 → 177`, `153 → 331`) and each artifact's box lies wholly inside the dialog's visible region. |
| §11.5 An operator who asks for reduced motion gets no scroll animation | `revealArtifact()` reads `prefers-reduced-motion` and passes `behavior: "auto"` instead of `"smooth"` when the operator has asked for reduced motion. Measured in the shipped shell by emulating the media feature and sampling the editor's scroll position every animation frame: with reduced motion the scroll jumps `0 → 530` in a single frame (2 distinct positions), and by default the same scroll eases through 23 distinct positions and settles on the same 530. |
| §11.6 The regression guard fails on the pre-fix assets and passes on these | `the_operator_shell_must_bring_a_rendered_artifact_into_view` was run against the pre-fix assets, where it **FAILED** on all three assertions (no reveal call in the artifact path, no centered scroll, no wait for the image's `load`), and against these assets, where it passes. The architecture guard suite is 70 tests, one more than before. |
| §11.7 The gate order is green, and the Linux line is unchanged | The gate order passed on this head (below). The change touches one asset file and one test file; no Rust source changed, no wire format, schema, protocol message, CLI surface, or installed state changed, and no Linux backend was touched. |
| §11.8 The M005 and M006 closure records stay period-accurate | `plans/closure/product-management/005-status.md` and `plans/closure/product-management/006-status.md` are unchanged. This record carries the new evidence. |

## Verification performed

All commands passed against implementation head `f70730c`:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                         # 44 suites; 752 passed, 0 failed, 16 ignored
cargo +1.89.0 check --all-targets --locked
git diff --check
```

## Browser evidence

The defect was found by reading the code **off the operator's screen** rather than
off the served file, and the fix is qualified the same way.

The appliance's own served assets are driven by Google Chrome in headless mode over
the DevTools protocol: the driver opens the shell, opens the first client, presses
**Show QR code**, and then measures. The driver **never scrolls the editor itself**,
so the geometry below is the shell's own doing.

### Before the fix — the code was off screen

| Viewport | Dialog visible height | Code top | Outcome |
|---|---|---|---|
| 1280×800 | 720 px | 791 px | entirely below the visible region |
| 390×844 @3× | 760 px | 1141 px | entirely below the visible region |
| 900×1250 | 1125 px | 791 px | visible, but the bottom edge was cut by the dialog |
| 1024×560 | 504 px | 1226 px | entirely below the visible region |

The rendered pixels of that 900×1250 capture **did not decode**: the visible part of
the code was missing its lower rows, including a finder pattern. The same SVG, taken
straight from `/api/v1/clients/<id>/qr` and rasterized, decoded to the configuration
at every scale down to one pixel per module. The code was correct and the presentation
was not.

### After the fix — the code is on screen and decodes

| Viewport | Editor scroll | Code box | Dialog visible box | Inside | Decodes |
|---|---|---|---|---|---|
| 1280×800 | 0 → 452 | y 378.6–730.6 | y 40–760 | yes | yes |
| 1280×800 @2× | 0 → 453.5 | y 378–730 | y 40–760 | yes | yes |
| 390×844 @3× | 0 → 724.3 | y 459–772 | y 42–802 | yes | yes |
| 900×1250 | 0 → 47 | y 806–1158 | y 62–1188 | yes | yes |
| 1024×560 | 0 → 668 | y 151–503 | y 28–532 | yes | yes |

The capture at 1280×800 decodes to 217 characters that are byte-for-byte identical to
`/api/v1/clients/<id>/config`, and the captures at 1280×800 @2× and 390×844 @3×
decode identically.

### The reveal respects reduced motion

The editor's scroll position was sampled every animation frame after the code was
produced, with the media feature emulated in both states:

```text
reduced-motion: samples 0, 0, 530, 530, 530, ...   2 distinct positions, final 530
default:        samples 0, 2, 11, 30, 69, 142, ... 23 distinct positions, final 530
```

An operator who has asked for reduced motion gets the code on screen in one frame;
everyone else gets the eased scroll. Both settle in the same place.

### The artifact format was already correct, and was verified separately
The QR payload is the raw `wg-quick` configuration, byte-identical to the
`/config` download. The official WireGuard applications accept exactly that:

- **Android** — `TunnelListFragment.kt` hands the scanned string to
  `TunnelImporter.importTunnel(…, configText)`, which calls `Config.parse` on it.
- **iOS** — `QRScanViewController.swift` calls
  `TunnelConfiguration(fromWgQuickConfig: code, called: "Scanned")`.

A code search for the `wireguard://` URI scheme returns no hits in either
application repository, so the scanners do not expect that form; they parse the
wg-quick configuration text, which is what this shell encodes. The macOS
application has no camera scanner and imports files only.

The payload's content was checked against the API: the private key in the code
derives exactly the public key the API reports for that client (X25519 with
RFC 7748 clamping, cross-checked against the repository's own known vector in
`src/domain/keys.rs`), the peer key is the server's own public key from
`/api/v1/server`, and the address, routes and endpoint match the API.

## The regression guard

`tests/architecture_guards.rs` gains
`the_operator_shell_must_bring_a_rendered_artifact_into_view`. It asserts that the
artifact path calls a reveal helper, that the reveal scrolls with `block: "center"`,
and that the QR branch waits for the image's `load` event.

Its three assertions were evaluated against the pre-fix assets and failed there, and
against these assets and passed. It is a static guard and needs no browser; the
browser evidence above is the part that could not be reduced to a file assertion,
and is the reason the defect survived two closure records.

## Asset byte inventory

| File | Bytes |
|---|---|
| `src/http/assets/app.css` | 4,884 |
| `src/http/assets/app.js` | 21,494 |
| `src/http/assets/index.html` | 8,533 |
| `src/http/assets/enroll.html` | 355 |
| `src/http/assets/enroll.js` | 1,353 |
| **aggregate** | **36,619** |

The aggregate moves from 36,188 to 36,619 bytes: +431 bytes for the reveal helper
and its four call sites. The aggregate already exceeded M005's 32 KiB ceiling before
this corrective (29,811 bytes at M005's head); that overage is a recorded finding for
the product-management line and is not reopened here.

## Findings this corrective does not own

These remain routed to the product-management line exactly as the M006 closure
record left them, and none of them is an artifact-presentation defect: the login
error message conflating `401`, `429` and `503`; the setup form's default endpoint
reading as a real value; the absence of a server-settings view after setup; the
seven-second poll rebuilding the client table; the unguarded clipboard write; the
unstyled enrollment page; the unused `.state-ok`/`.state-warn` rules; raw identifiers
and raw durations in the activity list; and the missing table semantics.

One observation from the same review is recorded and not acted on: the QR code is
rendered without a caption naming the client it belongs to. The editor's own
context carries that identity, so it is a polish item rather than a defect, and it
belongs with the other presentation findings rather than here.

## Disposition

**Closed.** The shell's QR artifact is now presented where the operator can see it
and scan it, at every viewport qualified, and the rendered code decodes to the
exported configuration. The regression guard fails on the pre-fix assets, the gate
order is green, and no closed Linux contract was reopened.
