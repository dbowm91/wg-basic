#![forbid(unsafe_code)]
// M001 Darwin notes: portable planning/observation types exist on Darwin but
// are not yet wired to Darwin backends (M004/M005). Allow dead code on Darwin
// only so `clippy -D warnings` stays green while Linux keeps strict liveness;
// M004/M005 remove these allows as Darwin backends consume the planners.
#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, unused_imports, clippy::default_constructed_unit_structs)
)]

// M001 (macOS portability foundation): the control-plane, product,
// authentication, state, release-parsing, and HTTP layers are portable and
// compile on Darwin. Linux-only kernel backends (netlink, nft process, UDS
// peer credentials, procfs capability probes) live behind
// `#[cfg(target_os = "linux")]` inside their owning modules; Darwin builds
// compile typed stubs that fail closed as unsupported rather than pretending
// convergence.
pub mod aggregate;
pub mod distribution;
pub mod doctor;
pub mod domain;
pub mod error;
pub mod firewall;
pub mod http;
/// Darwin launchd installation, artifact provenance, and recovery (M006
/// installation scope; pure layout/receipt logic, no live system mutation).
pub mod launchd;
pub mod management;
pub mod operational;
pub mod platform;
pub mod product;
pub mod protocol;
pub mod reconcile;
pub mod release;
pub mod state;
pub mod update;
pub mod wireguard;
