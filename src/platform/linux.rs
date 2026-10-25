//! Linux platform facts. Behaviour on Linux is unchanged by M001.

/// Linux deployment facts (canonical, already qualified).
pub const OS_NAME: &str = "linux";
/// Minimum kernel/interface assumptions are those already qualified by
/// Phases 1–11; M001 introduces no new Linux requirement.
pub const QUALIFIED: bool = true;
