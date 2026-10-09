# Domain model

`src/domain/` is the pure value-type layer. It owns validation, parsing, and
secret handling for everything upper layers persist, project, and reconcile —
and nothing else. See [overview](overview.md) for where it sits,
[state-store](state-store.md) for persistence/projection, and
[ownership](ownership.md) for owner-tag proof rules.

## Role and boundaries

- Pure computation only: parse, validate, derive, compare, redact.
- **Does not do:** no I/O, no SQLite/`rusqlite`, no netlink (`nl-wireguard` /
  `rtnetlink`), no `nft` subprocess, no HTTP/EggServe, no UDS protocol work,
  no clock reads, no env/argv key transport.
- Dependency direction is one-way: `src/state/` depends on `crate::domain`
  only, never the reverse. The auth submodule documents this explicitly ("no
  I/O … knows nothing about SQLite"); the intent submodule is documented as
  "pure vocabulary" kept outside any Linux gate so the unprivileged side can
  persist it without a network backend.
- External crates used here are value-level only: `serde`, `uuid`, `ipnet`,
  `base64`, `x25519-dalek`, `zeroize`, `argon2`/`password-hash`, `sha2`,
  `getrandom` (CSPRNG draws for tokens/keys).

## Submodule map

| Submodule | Owns | Key types |
|---|---|---|
| `identifiers.rs` | typed UUID identities | `InterfaceId`, `PeerId`, `ClientId`, `PrincipalId`, `SessionId` |
| `interface_name.rs` | Linux link-name validation | `InterfaceName`, `InterfaceNameError` |
| `network.rs` | prefix values, client-address uniqueness | `NetworkPrefix`, `ClientRoutePolicy`, `NetworkValidationError` |
| `secret.rs` | key wrappers, redaction, zeroize | `PublicKey`, `PrivateKey`, `PresharedKey`, `KeyError` |
| `keys.rs` | pure X25519 generation/derivation | `WireGuardKeyPair`, `generate_keypair`, `derive_public_key` |
| `auth.rs` | password policy, Argon2id, session/CSRF tokens | `PasswordVerifier`, `SessionToken`, `SessionTokenDigest`, `CsrfToken`, `AuthError`, `PasswordPolicyError` |
| `generation.rs` | installation identity, monotonic generation | `InstallationId`, `DesiredGeneration` |
| `owner.rs` | durable ownership tags | `OwnerTag`, `OwnerTagError`, `AliasMatch` |
| `intent.rs` | operator-wants vocabulary | `OwnershipDeclaration`, `LinkLifecycle`, `ResourcePresence`, `DesiredAddress`, `ManagedRoute` |
| `state.rs` | desired/observed shells + snapshot validation | `DesiredPeer`, `DesiredClient`, `DesiredInterface`, `DesiredNetworkPolicy`, `DesiredState`, `ObservedInterface`, `StateValidationError`, `validate_desired_state` |

`mod.rs` only re-exports; `keys.rs` notes key generation lives in `domain`
(rather than behind the `wireguard` platform gate) so the unprivileged service
can mint identities with no backend present, and `generation.rs` notes the
privileged side derives/verifies owner tags without opening the database.

## Validation rules

### Identifiers (`identifiers.rs`, `generation.rs`)

- `InterfaceId`, `PeerId`, `ClientId`, `PrincipalId`, `SessionId`, and
  `InstallationId` are `Uuid` (v4) newtypes: `Copy`, ordered, `serde`
  transparent, `Display`/`FromStr` via `Uuid::parse_str`. Distinct types despite
  identical representation — a `PeerId` never unifies with a `ClientId`.
- `InstallationId::new()` is random per store creation, stable across
  reopen/backup/restore, and deliberately not derived from hostname, path, MAC,
  or public key. Non-secret: a provenance marker, never an authorization token.

### Interface names (`interface_name.rs`)

`InterfaceName::new` enforces the Linux `IFNAMSIZ` bound (15 bytes + NUL):

| Rule | Error |
|---|---|
| empty | `Empty` |
| byte length > 15 | `TooLong` |
| NUL, ASCII control, `/`, `:`, or ASCII whitespace anywhere | `InvalidCharacter` |

Serde goes through `TryFrom<String>` / `Into<String>`, so deserialization
validates. `"wg0"` and 15-char names pass; 16-char names and
`"bad/name"`, `"bad:name"`, `"bad name"` fail.

### Prefixes and client addresses (`network.rs`)

- `NetworkPrefix(IpNet)` normalizes on construction: `new()` calls `trunc()`,
  so `"10.8.0.7/24"` parses to `"10.8.0.0/24"`. Helpers: `network()`,
  `contains(IpAddr)`, `family_matches(IpAddr)`.
- `ClientRoutePolicy { prefixes: Vec<NetworkPrefix> }` is client-side routing
  intent, kept separate from server-side peer `AllowedIPs`. Validation accepts
  at most 64 unique unicast prefixes, including the explicit family defaults
  `0.0.0.0/0` and `::/0`; IPv6 client routes require an IPv6 server pool and
  address assigned to that client. Address assignment never selects routes.
- `validate_unique_client_addresses` requires every assignment to be a host
  prefix (`/32` for v4, `/128` for v6) and rejects a repeated address:
  `ClientAddressMustBeHostPrefix` / `DuplicateClientAddress(IpAddr)`.

### Keys and secrets (`secret.rs`, `keys.rs`)

- `validate_key` requires standard-base64 decoding to exactly 32 bytes
  (44-char base64 form); otherwise `KeyError`
  (`"WireGuard key must be a 44-character base64 value"`). All three wrappers
  validate on `new` **and** on `Deserialize`.
- `PublicKey` is non-secret: `Debug` prints the value, `expose()` returns it.
- `PrivateKey` / `PresharedKey` are secret-bearing: `Debug` and `Display`
  render `[REDACTED]`, `Drop` zeroizes the inner string, access is via
  `expose_secret()`. Serde still transmits the raw string (the store is
  secret-bearing by design — see [state-store](state-store.md)).
- `WireGuardKeyPair { private_key, public_key }` redacts only the private half
  in `Debug`. `generate_keypair()` draws a random `StaticSecret`, encodes both
  halves, and zeroizes the intermediate bytes; `derive_public_key(&PrivateKey)`
  recomputes the X25519 public half. Pure arithmetic, no Linux dependency.

### Auth (`auth.rs`)

- Password policy is length-only on UTF-8 bytes: `MIN_PASSWORD_BYTES = 12`,
  `MAX_PASSWORD_BYTES = 1024`. `check_password_policy(&[u8])` checks byte
  bounds first, then requires valid UTF-8. `PasswordPolicyError`
  (`TooShort` / `TooLong` / `NotUtf8`) renders one opaque
  `operator_message()` for all variants so the policy shape is not an oracle.
- Argon2id is the only accepted algorithm (`m=19456 KiB`, `t=2`, `p=1`,
  via `argon2_params()`). `PasswordVerifier::hash` uses a fresh OS-CSPRNG salt
  per call; `parse` validates the PHC string at the boundary;
  `verify` returns `false` for wrong password, malformed hash, or non-Argon2id
  algorithm. `ARGON2ID_PHC_PREFIX = "$argon2id$"`. `Debug`/`Display` redacted.
  `TIMING_EQUALISER_VERIFIER` is a fixed verifier used only to equalize the
  cost of a failed lookup; it must never be stored or returned.
- `SessionToken` is a 256-bit OS-CSPRNG bearer (43-char unpadded base64url),
  handed out via `expose_once()` exactly once and zeroized on drop. Only its
  SHA-256 hex digest (`SessionTokenDigest`, 64 hex chars) is persisted;
  lookups hash first via `digest_of`. `SessionTokenDigest::parse` requires
  64 hex chars; comparison is `constant_time_eq`. The digest type itself is
  not a secret wrapper but still has no formatting accessor — only
  `expose_for_storage()`.
- `CsrfToken` is also 256-bit and redacted/zeroized, but persisted **in the
  clear**: it is not a credential, only meaningful alongside the bearer.
  `parse` rejects empty input.
- `AuthError` never distinguishes unknown-user from wrong-password
  (`CredentialsRejected` covers unknown principal, disabled principal, and
  wrong password). `SessionInvalid` likewise covers unknown/revoked/expired
  sessions and storage failure during lookup, so a lookup cannot probe service
  health.

### Generation (`generation.rs`)

- `DesiredGeneration(u64)` starts at `INITIAL_DESIRED_GENERATION = 1` and
  advances by exactly one per committed mutation; it never moves backward and
  a failed apply never rolls it back or reuses a value. Ceiling is
  `MAX_DESIRED_GENERATION = i64::MAX` (SQLite storage bound); `next()` returns
  `None` at the ceiling — no wraparound.
- `new(u64)` rejects `0` and anything past the ceiling; `from_storage(i64)`
  rejects `<= 0`; `to_storage()` binds the `i64`. A generation identifies a
  committed snapshot, not an apply attempt: re-committing identical payload
  still advances it. Compare-and-swap enforcement lives in the store, not here
  (see [state-store](state-store.md)).

### Owner tags (`owner.rs`)

- `OwnerTag { installation_id, interface_id }` renders canonically as
  `wg-basic:v1:<installation-uuid>:<interface-uuid>` — fixed 85 ASCII chars,
  under the `MAX_OWNER_TAG_LENGTH = 255` kernel `IFALIASZ` bound. Derived only
  from format version + the two IDs; never from a name or label; not a secret.
- `FromStr` errors: `TooLong`, `UnknownFormat` (bad prefix or extra `:` part),
  `Incomplete` (fewer than two parts), `InvalidIdentity` (non-UUID part).
- `matches()` requires both halves to match; `classify(Option<&str>)` maps an
  observed alias to `AliasMatch::Owned | Absent | ForeignInterface |
  ForeignInstallation | Unrelated`. Only `Owned` `proves_ownership()`; every
  other case `is_conflict()`. Ownership is never inferred from interface name
  or public key. Full proof table lives in [ownership](ownership.md).

### Intent vs persisted-state shells (`intent.rs`, `state.rs`)

- `intent.rs` is pure "what the operator wants": `OwnershipDeclaration`
  (`Managed` / `ObserveOnly`), `LinkLifecycle` (`Present` / `Absent`),
  `ResourcePresence` (`Present` / `Absent`) — all `snake_case` serde —
  plus `DesiredAddress { address: IpNet, presence }` and `ManagedRoute
  { destination: NetworkPrefix, gateway: Option<IpAddr>, presence }`.
  Deliberately separate from what the kernel currently reports.
- `state.rs` composes those into durable shells:
  - `DesiredPeer`: id, `PublicKey`, optional retained `PrivateKey` (only when
    wg-basic generated or was given it), optional `PresharedKey`,
    server-side `allowed_ips`, keepalive, endpoint.
  - `DesiredClient`: id, `peer_id`, required IPv4 host-prefix
    `assigned_address`, optional IPv6 host-prefix `assigned_ipv6_address`, both
    inside matching interface tunnel prefixes and covered by that peer's
    server-side AllowedIPs; client-side `route_policy` remains separate.
  - `DesiredInterface`: id, name, ownership, lifecycle, `admin_up:
    Option<bool>`, server `PrivateKey`, `listen_port`, `manage_all_peers`,
    `tunnel_prefixes`, exactly-managed `addresses`/`routes`, `peers`,
    `clients`.
  - `DesiredNetworkPolicy` (`deny_unknown_fields`): owning
    `wireguard_interface`, `ipv4_forwarding_required`, `egress_interface`,
    `source_prefixes`, `masquerade`. At most one per snapshot.
  - `DesiredState { interfaces, client_routes, network_policy: Option<_> }`.
  - `ObservedInterface { name, addresses, listen_port }` — the kernel-observed
    shape, kept distinct from desired shells.
- `DesiredInterface::validate()` (per interface) and
  `validate_desired_state()` (whole snapshot, incl. cross-interface rules):

| Rule | Error |
|---|---|
| `listen_port == Some(0)` | `InvalidListenPort` |
| `Present` without `admin_up` / `Absent` with `admin_up` | `AdminUpRequiredForPresentLink` / `AdminUpNotAllowedForAbsentLink` |
| repeated peer public key | `DuplicatePeerKey` |
| client address not `/32`/`/128` | `ClientAddressMustBeHostPrefix` |
| client address outside `tunnel_prefixes` | `ClientAddressOutsideTunnel` |
| client references unknown peer | `ClientPeerMissing` |
| client address not covered by its peer's `allowed_ips` | `ClientAddressNotAllowedForPeer` |
| repeated client address | `DuplicateClientAddress` |
| repeated interface name (snapshot) | `DuplicateInterfaceName` |
| repeated peer/client id (snapshot-global) | `DuplicatePeerId` / `DuplicateClientId` |
| policy references unknown interface / empty prefixes / non-IPv4 prefix | `NetworkPolicyUnknownInterface` / `NetworkPolicyEmptySourcePrefixes` / `NetworkPolicyNonIpv4Prefix` |

## How upper layers consume it

- `src/state/model.rs` pairs domain types with commit metadata without adding
  validation: `InstallationMetadata { installation_id, desired_generation,
  created_at, updated_at }`, `PersistedDesiredState` / `CommittedDesiredState
  { generation, state: DesiredState }`. `AttemptDisposition` stores outcome
  **categories** only (never kernel error strings or secrets);
  `ConvergenceRecord` tracks attempted/converged generations plus timestamp
  and outcome category. Row structs in `src/state/store/` decode into these
  and never `Debug`-render secret material.
- `src/state/projection.rs` is the pure `DesiredState + InstallationId (+
  ClientVisibility) → ResolvedNetworkIntent` function. It preserves snapshot
  order (deterministic), requires a listen port for present links
  (`MissingListenPort`), maps a present/absent lifecycle to
  `Some`/`None` WireGuard configuration, re-validates policy prefixes
  (`EmptyNetworkPolicyPrefixes` / `NonIpv4PolicyPrefix`), translates domain
  intent enums into the kernel-facing `reconcile`/`firewall` enums, derives
  each interface's `OwnerTag::new(installation_id, interface.id)`, and
  withholds disabled clients' peers via an explicit `ClientVisibility` peer
  set — never by reading product state inside the projector. All projection
  errors are state-validation errors raised before any privileged call.
