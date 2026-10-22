//! Typed, bounded forwarding and firewall ownership.
//!
//! Ownership is split into units:
//!
//! - [`policy`] holds the typed caller-supplied policy and its validation
//!   (portable);
//! - [`planner`] turns an observation into a deterministic action plan
//!   (portable, pure);
//! - [`nft`] owns every Linux process, filesystem, and rendering boundary
//!   (Linux only; Darwin gains its PF backend in M005, never by reusing this
//!   module's owner-table claims);
//! - [`service`] serializes application and reports the receipt (Linux
//!   backend);
//! - [`pfctl`] reads the host's packet filter without changing it (Darwin
//!   only, strictly read-only);
//! - [`service_darwin`] owns the Darwin host-only (C001) and routed-LAN (C003)
//!   contracts: it refuses any policy it cannot prove, and never writes PF
//!   state, forwarding sysctls, or host routes.
//!
//! On Linux `nft` is invoked directly with internally rendered input. No caller
//! can supply nft source, and the sole owned table is `inet wg_basic`. Do not
//! copy these owner-table claims into PF: M005 anchors must actually be
//! reachable by parent filter/NAT rules.

#[cfg(target_os = "linux")]
mod nft;
/// Darwin PF/NAT anchor model and advanced-admin policy (M005 policy scope;
/// pure rendering/verification, no `pfctl` execution yet).
mod pf;
#[cfg(target_os = "macos")]
mod pfctl;
mod planner;
mod policy;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "macos")]
mod service_darwin;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod service_other;

pub use pf::{
    anchor_content_matches, anchor_name, attachment_verified, observe_attachments, render_policy,
    render_routed_policy, rules_digest, teardown_order, Attachment, AttachmentObservation, PfError,
    PfRuleSet, RequiredAttachments, ANCHOR_PREFIX, IPV4_FORWARDING_SYSCTL, IPV6_FORWARDING_SYSCTL,
};

pub use policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError, FirewallFailure,
    FirewallPlanSummary, FirewallWarning, Ipv4Forwarding, Ipv6Forwarding, NatMode,
    RoutedLanVerdict,
};
#[cfg(target_os = "linux")]
pub use service::FirewallService;
#[cfg(target_os = "macos")]
pub use service_darwin::FirewallService;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use service_other::FirewallService;
