mod auth;
mod generation;
mod identifiers;
mod intent;
mod interface_name;
mod keys;
mod network;
mod owner;
mod secret;
mod state;

pub use auth::{
    argon2_params, check_password_policy, AuthError, CsrfToken, PasswordPolicyError,
    PasswordVerifier, SessionToken, SessionTokenDigest, ARGON2ID_PHC_PREFIX, ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, CSRF_TOKEN_BITS, MAX_PASSWORD_BYTES, MIN_PASSWORD_BYTES,
    SESSION_TOKEN_BITS, TIMING_EQUALISER_VERIFIER,
};
pub use generation::{
    DesiredGeneration, InstallationId, INITIAL_DESIRED_GENERATION, MAX_DESIRED_GENERATION,
};
pub use identifiers::{ClientId, InterfaceId, PeerId, PrincipalId, SessionId};
pub use intent::{
    DesiredAddress, LinkLifecycle, ManagedRoute, OwnershipDeclaration, ResourcePresence,
};
pub use interface_name::InterfaceName;
// Key generation is pure X25519 arithmetic with no Linux dependency, so it lives
// in `domain` rather than behind the `wireguard` module's platform gate: the
// unprivileged product service generates server and client identities and must
// be able to do so without a network backend present.
pub use keys::{derive_public_key, generate_keypair, WireGuardKeyPair};
pub use network::{validate_unique_client_addresses, ClientRoutePolicy, NetworkPrefix};
pub use owner::{AliasMatch, OwnerTag, OwnerTagError, MAX_OWNER_TAG_LENGTH};
pub use secret::{KeyError, PresharedKey, PrivateKey, PublicKey};
pub use state::{
    validate_desired_state, DesiredClient, DesiredInterface, DesiredNetworkPolicy, DesiredPeer,
    DesiredState, ObservedInterface, StateValidationError,
};
