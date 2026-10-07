//! The bounded, single-slot coalescing rule.
//!
//! This module answers one question — "what should the runtime do next?" — and
//! holds no store handle, no socket, and no clock, so the coalescing rule can be
//! qualified on its own.

use crate::domain::DesiredGeneration;

/// A bounded, single-slot coordinator.
///
/// Several writes before an apply begins coalesce to the latest generation.
/// Once an apply begins, a newer generation waits, and after completion the
/// latest state is reconciled immediately. There is no unbounded per-write task
/// and no background scheduler.
#[derive(Debug, Default)]
pub struct ReconcileCoordinator {
    pending: Option<DesiredGeneration>,
    applying: bool,
}

/// What the coordinator decided to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorAction {
    /// No work: either nothing is pending or an apply is already running.
    Idle,
    /// Apply this generation.
    Apply(DesiredGeneration),
}

impl ReconcileCoordinator {
    /// Notes that `generation` needs reconciling.
    ///
    /// Repeated calls before an apply starts collapse into one: only the latest
    /// generation is retained.
    pub fn enqueue(&mut self, generation: DesiredGeneration) {
        self.pending = Some(generation);
    }

    /// Claims the pending generation, if one exists and no apply is running.
    pub fn next_action(&mut self) -> CoordinatorAction {
        if self.applying {
            return CoordinatorAction::Idle;
        }
        match self.pending.take() {
            Some(generation) => {
                self.applying = true;
                CoordinatorAction::Apply(generation)
            }
            None => CoordinatorAction::Idle,
        }
    }

    /// Ends the running apply.
    pub fn finish(&mut self) {
        self.applying = false;
    }

    pub fn is_idle(&self) -> bool {
        !self.applying && self.pending.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DesiredGeneration;

    #[test]
    fn the_coordinator_coalesces_writes_before_an_apply_starts() {
        let mut coordinator = ReconcileCoordinator::default();
        coordinator.enqueue(DesiredGeneration::new(1).unwrap());
        coordinator.enqueue(DesiredGeneration::new(2).unwrap());
        coordinator.enqueue(DesiredGeneration::new(3).unwrap());

        match coordinator.next_action() {
            CoordinatorAction::Apply(generation) => {
                assert_eq!(
                    generation,
                    DesiredGeneration::new(3).unwrap(),
                    "several writes before an apply must collapse to the latest generation"
                );
            }
            CoordinatorAction::Idle => panic!("an apply should be claimable"),
        }
    }

    #[test]
    fn a_newer_generation_waits_while_an_apply_is_running() {
        let mut coordinator = ReconcileCoordinator::default();
        coordinator.enqueue(DesiredGeneration::new(1).unwrap());
        assert!(matches!(
            coordinator.next_action(),
            CoordinatorAction::Apply(_)
        ));

        coordinator.enqueue(DesiredGeneration::new(2).unwrap());
        assert_eq!(
            coordinator.next_action(),
            CoordinatorAction::Idle,
            "a newer generation must wait for the running apply"
        );

        coordinator.finish();
        assert!(matches!(
            coordinator.next_action(),
            CoordinatorAction::Apply(_)
        ));
    }

    #[test]
    fn an_idle_coordinator_does_no_work() {
        let mut coordinator = ReconcileCoordinator::default();
        assert_eq!(coordinator.next_action(), CoordinatorAction::Idle);
        assert!(coordinator.is_idle());
    }
}
