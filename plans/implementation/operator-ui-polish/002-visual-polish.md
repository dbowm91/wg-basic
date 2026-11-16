# Operator UI polish M002 — Visual polish pass

Status: planned (hard dependency: M001 closed)

Repository baseline: set at UI M001 closure head when this plan becomes ready.

Source roadmap: `plans/subsystems/operator-ui-polish-roadmap.md` M002

Canonical requirements: long-term spec §3 (wg-easy as UX reference); UI polish roadmap.

Primary work class: polish

Hard dependencies: operator-ui-polish M001 closed.

## Objective

Improve clarity and density of the existing operator shell (setup, clients, telemetry, audit, account/login once present) so it feels closer to wg-easy without adding a SPA framework or third-party design system.

## Explicit non-goals

- No sparklines (M003).
- No i18n, Gravatar, or bulk multi-select (deferred).
- No new product API semantics.
- No screenshot-driven pixel parity with wg-easy.

## Current repository evidence

- Functional single-page shell with sections, tables, dialogs, banners.
- After M001: theme switcher and raised ceilings.

## Invariants

- Same-origin buildless assets only.
- Existing generation CAS / pending messaging remains explicit.
- Secret artifacts still load only on explicit action and clear on dialog close.
- Stay under the M001 ceilings (or raise with justification in this milestone’s closure if unavoidable).

## Expected production changes

1. Typography/spacing/hierarchy cleanup using existing CSS variables.
2. Clearer empty states for no clients / no telemetry / no audit.
3. Client table readability (filters already exist — improve layout/actions wrapping).
4. Login and account pages share the polished chrome.
5. Responsive tweaks under the existing `40rem` breakpoint without horizontal dead ends for primary actions.

## Ordered work packages

1. CSS token and layout pass.
2. HTML structure tweaks for empty states and section headings.
3. Minimal JS only where needed for empty-state rendering.
4. Visual check against light and dark themes.

## Privilege and security effects

None.

## Persistence, protocol, and configuration compatibility

Assets only.

## Failure, cancellation, restart, and contention

N/A beyond ordinary UI error banners already present.

## Focused tests

- Inventory/ceiling still pass.
- No third-party URLs.
- Existing shell contract tests (if any) updated for renamed selectors carefully.

## Linux and network-namespace integration evidence

None.

## Broad verification commands

Ordinary gates.

## Documentation updates

Only if operator-facing screenshots or runbook UI steps change; prefer minimal doc churn.

## Acceptance criteria

1. Primary operator flows remain complete in both Light and Dark.
2. Empty states are understandable without console errors.
3. Asset ceilings hold.

## Stop conditions

- Introducing a CSS/JS framework from a CDN or npm bundler without a new ADR.
- Regressing CSRF/session flows while rearranging forms.

## Closure evidence requirements

Before/after size numbers; note any selector renames that affect tests.
