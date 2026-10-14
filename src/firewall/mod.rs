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
//! - [`service`] serializes application and reports the receipt (Linux backend;
//!   Darwin stub in M001 fails closed as unsupported).
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
mod planner;
mod policy;
#[cfg(target_os = "linux")]
mod service;
#[cfg(not(target_os = "linux"))]
mod service_darwin;

pub use pf::{
    anchor_name, attachment_verified, render_policy, rules_digest, teardown_order, PfError,
    PfRuleSet, ANCHOR_PREFIX, IPV4_FORWARDING_SYSCTL, IPV6_FORWARDING_SYSCTL,
};

pub use policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError, FirewallFailure,
    FirewallPlanSummary, FirewallWarning, Ipv4Forwarding, Ipv6Forwarding, NatMode,
};
#[cfg(target_os = "linux")]
pub use service::FirewallService;
#[cfg(not(target_os = "linux"))]
pub use service_darwin::FirewallService;
