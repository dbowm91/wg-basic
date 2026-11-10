# Operator parity roadmap

Status: closed 2026-11-10. M001–M004 closed. Deferred items in §10 remain deferred. C015 is unchanged. No macOS release.

Date: 2026-11-10

Repository baseline: `a9b0c06af205b20923f7db350a65379cb176e56e` (`main`).

Canonical references:

- `plans/000-long-term-specification.md` §§1–3 and §23 (wg-easy is the user-experience reference; matching every wg-easy feature is not required; shell hooks are out of scope)
- `plans/003-planning-process.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/007-ipv6-forwarding-ownership.md`
- `plans/adr/008-macos-headless-platform-backends.md`
- `plans/adr/009-apple-silicon-only-darwin-target.md`

Related work this roadmap does not own:

- `plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md` is already **ready**. It is the plan that makes `network disable` remove the managed `utun`. This roadmap must not restate it.
- macOS release qualification stays with C005 / M007. Nothing here authorizes a Darwin release or changes the must-not-release standing.
- Linux nftables gateway behavior is closed. This roadmap must not replace it.

## 1. Purpose

wg-easy's operator loop is: open the page, keep the defaults, add a client, scan a QR code, and have a working VPN, then see that client and turn it off later.

On this repository that loop is one embedded UI and one product API on both target systems. Linux already finishes it: the pre-filled setup asks for IPv4 forwarding and masquerade, and nftables applies that gateway. Apple silicon does not. The same checkboxes select a gateway the Darwin service will not finish, because host forwarding is only read and the packet filter is written only inside one anchor after an administrator has attached that anchor. The form also offers Linux names (`wg0`, `eth0`) on both hosts.

A second, smaller gap is shared. The client page can set a name, addresses, DNS, keepalive, and routes. It cannot set the three wg-easy client controls that stay inside this product's existing model: an expiry that disables the client, a preshared key the server generates, and a client MTU that is only a line in the exported config. The peer row has had a `preshared_key` column since schema 1, and export already prints one, but every create stores none and no route can change that.

This roadmap closes those two gaps. It does not make a Mac apply NAT by itself.

## 2. Ownership boundary

Owns:

- the embedded setup form's platform defaults and the authenticated read that tells the page which host it is on;
- a session-authenticated, read-only projection of network prerequisites the firewall plan and `operator_attachment` already compute;
- optional client expiry, enforced by the unprivileged management worker through the existing disable path;
- server-generated client preshared keys;
- an optional client MTU rendered only into the standard config and QR.

Does not own:

- writing Darwin forwarding sysctls, `/etc/pf.conf`, or any foreign anchor;
- enabling or disabling PF;
- the Linux nftables apply path, except to keep today's setup body meaning a gateway;
- `network disable` removing a `utun` (C015);
- a macOS release;
- server-interface MTU, which would change link reconciliation on both platforms;
- traffic history, charts, or a Prometheus scrape (live telemetry stays non-durable);
- hooks, AmneziaWG, per-client firewall rules, OIDC, TOTP, gravatar, translations, a browser password change, or a LAN routed behind a client.

## 3. Invariants

1. SQLite desired state stays authoritative. A prerequisite projection is an observation. It is never a second desired state.
2. Only `netd` touches the network, and only through the typed operations that already exist. This roadmap adds no privileged opcode, no sysctl path, no PF source, and no shell.
3. On Darwin the product still does not write forwarding and still does not edit `/etc/pf.conf`. Gateway and routed LAN still refuse until their existing prerequisites hold.
4. On Linux, a setup body that sets IPv4 forwarding or masquerade and omits `mode` still derives a gateway, and nftables still applies it.
5. A routed LAN remains refused on every platform other than macOS.
6. Disable, whether an operator clicked it or an expiry fired, removes the peer from projected kernel intent and keeps the address reservation. The API still distinguishes a durable commit from confirmed enforcement.
7. Private keys and preshared keys stay out of client summaries, audit rows, logs, and telemetry. They appear only in an explicit config or QR response.
8. Schema migrations stay append-only. DesiredGeneration does not advance because a migration ran.
9. There is no periodic reconciliation poll. An expiry wake is a single sleep until the next stored deadline, and it is absent when no client has a future deadline.

## 4. Why the Mac cannot gain Linux's default NAT inside this roadmap

ADR-008 and the Darwin firewall contract already decided this. Global forwarding is host-wide and shared with the rest of the machine. Apple TN3165 says PF is not a product API. C004's gateway writes one installation anchor with `pfctl -a <anchor> -f <file>` and stops there. The parent lines (`nat-anchor`, `anchor`, `load anchor`) are the administrator's, and appending all three to the end of `/etc/pf.conf` is known to make the main ruleset fail to load.

Automatic parity would mean the product sets `net.inet.ip.forwarding` and edits the parent ruleset. That is a different ownership decision. It needs its own ADR, a measured parent-edit procedure, and a reversal story for a file the product does not own today. Until that ADR exists, an implementation that writes either one is a stop, not a creative completion of M001.

What this roadmap does instead is make the first save on a Mac a mode the host can enforce (host-only), and show the existing gateway and routed-LAN prerequisites in the page that asks for them. An administrator who wants the internet VPN follows those lines. The product still applies the anchor once the parent is attached, which is the C004 behavior.

## 5. Current repository evidence

- `GET /api/v1/network-prerequisites` projects the existing network-policy plan. `host_platform` comes from the binary. Forwarding is `enabled`, `disabled`, or `not_observed`. macOS replies include the three attachment lines. Linux replies omit that object. The route does not apply.
- An omitted setup `mode` still derives the policy. The embedded page starts from the prerequisite route when the form has not been edited. Linux leaves IPv4 forwarding and masquerade checked and egress at `eth0`. macOS clears both and the egress value. The historical body, forwarding or masquerade with no `mode`, stays a gateway.
- Schema head is version 10. Schema 9 adds nullable `client_product_settings.expires_at`. Schema 10 adds nullable `mtu` from 1280 through 9000. Neither migration advances desired generation.
- A due client is disabled by the existing disable path. The worker sleeps until the next stored deadline and does not sleep when none is stored.
- Create accepts `preshared_key` only as `"generate"`. Update accepts `"generate"` or `"clear"`. The summary carries `preshared_key_configured` and not the key. Both wire encoders project set and clear. The column has existed since schema 1.
- Export writes `MTU = <n>` after `Address` and before `DNS` when a client MTU is stored. The server link MTU is unchanged.
- C015 records that macOS `network disable` commits and then returns `Degraded(BackendRefused)`, leaving the `utun` in place. That defect stays on C015's plan.
- Closures: `plans/closure/operator-parity/001-status.md` through `004-status.md`.

## 6. Dependency graph

```text
closed Phase 8 product API and UI
closed Darwin gateway and routed-LAN observations (C003, C004, C007)
        |
        v
M001  platform-honest setup and prerequisite projection     [closed 2026-11-10]
        |
        v
M002  client expiration                                      [closed 2026-11-10]
        |
        v
M003  server-generated preshared keys                        [closed 2026-11-10]
        |
        v
M004  client MTU in the exported config                      [closed 2026-11-10]

C015  macOS interface teardown                               [ready, separate line]
```

M001 does not depend on C015. M002–M004 were sequenced because each one extends the client mutation and the same embedded page, and M002 and M004 each append a schema version. That sequence is closed.

C015 may be implemented in parallel. It touches the reconcile planner, not this UI contract.

## 7. Milestones

| Milestone | Class | Status | Plan |
|---|---|---|---|
| M001 platform-honest setup | capability | **closed** 2026-11-10 | `plans/implementation/operator-parity/001-platform-honest-setup.md` |
| M002 client expiration | capability | **closed** 2026-11-10 | `plans/implementation/operator-parity/002-client-expiration.md` |
| M003 preshared keys | capability / secret handling | **closed** 2026-11-10 | `plans/implementation/operator-parity/003-client-preshared-keys.md` |
| M004 client MTU | capability | **closed** 2026-11-10 | `plans/implementation/operator-parity/004-client-mtu.md` |

## 8. Cross-cutting concerns

- **Privilege.** Reads of forwarding and PF stay inside the Darwin firewall service's existing `plan` path. The new HTTP route only projects that plan. It does not grow the UDS vocabulary.
- **Secrets.** M003 is the only milestone that handles a new secret. The others must not log setup bodies, config text, or keys while they edit the client page.
- **Compatibility.** M001 is additive JSON. M002 is schema 9. M004 is schema 10. An old binary refuses a newer schema, which is the current opener rule. Linux setup bodies from existing clients stay valid.
- **Failure.** A missing `netd` makes the prerequisite projection say the host was not observed. It does not invent "forwarding is off" and it does not block host-only setup.
- **Preservation.** No milestone flushes foreign firewall, route, or sysctl state.

## 9. Integration evidence

M001's Linux evidence is the historical setup body, which the unprivileged product test still stores as a gateway. The rootful nftables suite was not re-run and was not retargeted. Darwin evidence is a host-free plan assertion plus the prerequisite projection; it does not claim new packet traffic. M002–M004 are product-state milestones. Their kernel effect is the peer projection that already exists (a disabled client disappears; a preshared key is a field on the peer patch). They do not add a traffic topology. M003's set and clear are asserted on both the Linux and Darwin peer encoders. The commands and the limits are in the four closure records.

## 10. Deferred, with reasons

| wg-easy surface | Disposition |
|---|---|
| Product writes Darwin forwarding or `/etc/pf.conf` | Stop. Requires a new ADR. Contradicts ADR-008 and the measured parent-ruleset order. |
| Hooks | Forbidden by the long-term spec. NAT stays a typed policy. |
| Charts, Prometheus, JSON metrics | Live telemetry is non-durable by the Phase 8 invariant. A history store is a different subsystem. |
| 2FA, OIDC, browser password change | Phase 7 kept administrator bootstrap on the local CLI. A change needs an auth review, not this roadmap. |
| Server AllowedIPs for a LAN behind a client | Changes peer prefix ownership and the overlap rule. Not the road-warrior loop. |
| Server interface MTU | Changes link apply on Linux and `utun` on Darwin. Out of M004 on purpose. |
| AmneziaWG, per-client firewall, gravatar, i18n, dark mode | Outside the spec's simplicity bound. |
| macOS release, Intel Macs | ADR-009 and M007. Not advanced by operator-page work. |

## 11. Risks

- An implementer "helps" a Mac by enabling forwarding. M001's stop condition exists for that.
- The shared HTML file grows platform branches that silently change the Linux default. M001 requires a regression test of the historical JSON body, not a screenshot of the form.
- Expiry becomes a poll loop. M002 allows one deadline sleep and nothing else.
- A preshared key leaks into the client list JSON. M003's tests read the summary and assert the key's absence.
