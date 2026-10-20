//! Serialized application of a planned reconciliation and receipt reporting.
//!
//! One installation-wide lock serializes observe/plan/apply/verify sequences.

use super::apply::{apply_with_backend, plan_with_backend};
use super::linux::LinuxNetworkBackend;
use super::model::{ApplyReceipt, DesiredManagedInterface, ReconcileError, ReconcilePlanSummary};
use std::sync::Mutex;

/// One installation-wide lock serializes observe/plan/apply/verify sequences.
/// The socket service also handles requests sequentially, so this lock makes
/// the invariant hold for in-process callers that use this controller directly.
pub struct ReconciliationService {
    backend: LinuxNetworkBackend,
    mutation_lock: Mutex<()>,
}

impl Default for ReconciliationService {
    fn default() -> Self {
        Self::new(LinuxNetworkBackend::default())
    }
}

impl ReconciliationService {
    pub fn new(backend: LinuxNetworkBackend) -> Self {
        Self {
            backend,
            mutation_lock: Mutex::new(()),
        }
    }

    pub fn plan(
        &self,
        desired: &DesiredManagedInterface,
    ) -> Result<ReconcilePlanSummary, ReconcileError> {
        desired.validate()?;
        plan_with_backend(desired, &self.backend)
    }

    pub fn apply(&self, desired: &DesiredManagedInterface) -> Result<ApplyReceipt, ReconcileError> {
        desired.validate()?;
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| ReconcileError::BackendFailure)?;
        apply_with_backend(desired, &self.backend)
    }
}

#[cfg(test)]
mod tests {
    use super::super::apply::ReconcileBackend;
    use super::super::model::{
        ApplyStatus, DesiredAddress, DesiredManagedInterface, LinkLifecycle,
        ObservedManagedInterface, OwnershipDeclaration, ResourcePresence,
    };
    use super::*;
    use crate::domain::{InstallationId, InterfaceId, InterfaceName, OwnerTag};
    use crate::reconcile::model::ObservedLinkKind;
    use crate::reconcile::Mutation;
    use std::sync::Mutex as StdMutex;

    /// One stable tag for the whole module: ownership is proven by an exact
    /// match between the desired tag and the alias observed on the link.
    fn owner_tag() -> OwnerTag {
        OwnerTag::new(
            "00000000-0000-4000-8000-0000000000a1"
                .parse::<InstallationId>()
                .unwrap(),
            "00000000-0000-4000-8000-0000000000b2"
                .parse::<InterfaceId>()
                .unwrap(),
        )
    }

    fn name() -> InterfaceName {
        "wg-test".parse().unwrap()
    }

    fn desired() -> DesiredManagedInterface {
        DesiredManagedInterface {
            interface: name(),
            owner_tag: owner_tag(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            wireguard: None,
            addresses: vec![DesiredAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: Vec::new(),
        }
    }

    fn observed() -> ObservedManagedInterface {
        ObservedManagedInterface {
            interface: name(),
            ifindex: Some(7),
            link_kind: Some(ObservedLinkKind::WireGuard),
            admin_up: Some(false),
            addresses: Vec::new(),
            routes: Vec::new(),
            unsupported_route_count: 0,
            interface_alias: Some(owner_tag().as_str()),
            duplicate_owner_tag: false,
            wireguard: None,
        }
    }

    #[derive(Debug)]
    struct FakeBackend {
        state: StdMutex<ObservedManagedInterface>,
        fail_once_at: usize,
        applied: StdMutex<usize>,
    }

    impl ReconcileBackend for FakeBackend {
        fn observe(
            &self,
            _: &InterfaceName,
            _: &OwnerTag,
        ) -> Result<ObservedManagedInterface, ReconcileError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| ReconcileError::BackendFailure)
        }

        fn apply(&self, _: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError> {
            let mut applied = self
                .applied
                .lock()
                .map_err(|_| ReconcileError::BackendFailure)?;
            *applied += 1;
            if *applied == self.fail_once_at {
                return Err(ReconcileError::BackendFailure);
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| ReconcileError::BackendFailure)?;
            match mutation {
                Mutation::AddAddress(address) => state.addresses.push(address),
                Mutation::SetLinkUp(up) => state.admin_up = Some(up),
                _ => return Err(ReconcileError::BackendFailure),
            }
            Ok(())
        }
    }

    #[test]
    fn partial_apply_is_observed_and_retry_converges() {
        let wanted = DesiredManagedInterface {
            routes: Vec::new(),
            ..desired()
        };
        let backend = FakeBackend {
            state: StdMutex::new(observed()),
            fail_once_at: 2,
            applied: StdMutex::new(0),
        };
        let first = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(first.status, ApplyStatus::PartialFailure);
        assert_eq!(first.completed_actions, 1);
        assert_eq!(first.observed_after.as_ref().unwrap().addresses.len(), 1);

        let retry = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(retry.status, ApplyStatus::Applied);
        assert_eq!(retry.completed_actions, 1);
        let no_op = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(no_op.status, ApplyStatus::NoChange);
    }
}
