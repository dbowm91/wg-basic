mod identifiers;
mod intent;
mod interface_name;
mod network;
mod secret;
mod state;

pub use identifiers::{ClientId, InterfaceId, PeerId};
pub use intent::{
    DesiredAddress, LinkLifecycle, ManagedRoute, OwnershipDeclaration, ResourcePresence,
};
pub use interface_name::InterfaceName;
pub use network::{validate_unique_client_addresses, ClientRoutePolicy, NetworkPrefix};
pub use secret::{KeyError, PresharedKey, PrivateKey, PublicKey};
pub use state::{
    validate_desired_state, DesiredClient, DesiredInterface, DesiredNetworkPolicy, DesiredPeer,
    DesiredState, ObservedInterface, StateValidationError,
};
