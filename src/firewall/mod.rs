//! Typed, bounded Linux forwarding and nftables ownership.
//!
//! Ownership is split into four units:
//!
//! - [`policy`] holds the typed caller-supplied policy and its validation;
//! - [`planner`] turns an observation into a deterministic action plan;
//! - [`nft`] owns every process, filesystem, and rendering boundary;
//! - [`service`] serializes application and reports the receipt.
//!
//! `nft` is invoked directly with internally rendered input. No caller can supply
//! nft source, and the sole owned table is `inet wg_basic`.

mod nft;
mod planner;
mod policy;
mod service;

pub use policy::{
    DesiredNetworkPolicy, FirewallActionKind, FirewallApplyReceipt, FirewallError, FirewallFailure,
    FirewallPlanSummary, FirewallWarning, Ipv4Forwarding, NatMode,
};
pub use service::FirewallService;
