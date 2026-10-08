//! Phase 8 product management.
//!
//! The application layer that sits between the HTTP surface and durable state.
//! It exists so that configuration-mutating routes never touch SQLite, never
//! generate key material, and never decide for themselves what "committed"
//! means. Everything here is callable without HTTP in sight -- which is what
//! lets M001 qualify product behaviour before M002 exposes any of it.

pub mod allocator;
pub mod enrollment;
pub mod export;
pub mod model;
pub mod service;

pub use allocator::{AddressRequest, AllocationContext, AllocationError};
pub use enrollment::{
    CreatedEnrollmentLink, EnrollmentToken, EnrollmentTokenError, DEFAULT_ENROLLMENT_TTL_SECONDS,
    MAX_ENROLLMENT_TTL_SECONDS,
};
pub use export::{
    render_config, render_qr_svg, ArtifactError, ClientConfigMaterial, SecretArtifact,
};
pub use model::{
    AdvertisedEndpoint, AdvertisedEndpointError, AuditAction, AuditEvent, AuditEventId,
    AuditOutcome, AuditResourceKind, ClientEnabled, ClientLabel, ClientLabelError,
    ClientProductSettings, DegradedCategory, EnforcementState, EnrollmentCapabilityId,
    ProductClient, ProductMutationReceipt, ProductServer, MAX_ADVERTISED_HOST_BYTES,
    MAX_CLIENT_LABEL_BYTES,
};
pub use service::{
    ClientCreateCommand, ClientDeleteCommand, ClientUpdateCommand, ProductError, ProductService,
    ServerSetupCommand, SetClientEnabledCommand, SetupResult,
};
