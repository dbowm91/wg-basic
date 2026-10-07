mod generation;
mod identifiers;
mod intent;
mod interface_name;
mod network;
mod owner;
mod secret;
mod state;

pub use generation::{
    DesiredGeneration, InstallationId, INITIAL_DESIRED_GENERATION, MAX_DESIRED_GENERATION,
};
pub use identifiers::{ClientId, InterfaceId, PeerId};
pub use intent::{
    DesiredAddress, LinkLifecycle, ManagedRoute, OwnershipDeclaration, ResourcePresence,
};
pub use interface_name::InterfaceName;
pub use network::{validate_unique_client_addresses, ClientRoutePolicy, NetworkPrefix};
pub use owner::{AliasMatch, OwnerTag, OwnerTagError, MAX_OWNER_TAG_LENGTH};
pub use secret::{KeyError, PresharedKey, PrivateKey, PublicKey};
pub use state::{
    validate_desired_state, DesiredClient, DesiredInterface, DesiredNetworkPolicy, DesiredPeer,
    DesiredState, ObservedInterface, StateValidationError,
};
