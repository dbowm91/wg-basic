//! Generation-aware aggregate network reconciliation.
//!
//! One desired generation is the unit of privileged reconciliation. This module
//! owns:
//!
//! - [`InstallationNetworkIntent`], the typed application-to-netd payload;
//! - [`AggregateCoordinator`], which serializes aggregate applies, enforces
//!   in-process generation monotonicity, and orders the interface and firewall
//!   layers.
//!
//! It is database-free: the management side projects intent and sends it, and
//! this module revalidates everything it is given.
//!
//! # Ordering
//!
//! Enabling reconciles the interface layer first and stops if it fails or does
//! not verify, so a firewall policy is never installed for a link that is not
//! there. Disabling removes the firewall policy first and stops if that fails,
//! so a partial disable never deletes an interface while leaving a wg-basic
//! firewall table whose semantic target no longer exists.
//!
//! # Concurrency
//!
//! One outer mutation lock spans both layer services. Lower-level locks remain
//! as defence in depth, but lock order is fixed: outer first, then inner, so
//! the ordering is deadlock-free. The lock is not merely a convenience of the
//! current sequential socket dispatch, because Phase 7 may change that.

use crate::{
    domain::{DesiredGeneration, InstallationId, InterfaceId, LinkLifecycle, OwnerTag},
    firewall::{DesiredNetworkPolicy, FirewallApplyReceipt, FirewallPlanSummary, FirewallService},
    reconcile::{
        ApplyReceipt, ApplyStatus, DesiredManagedInterface, ReconcileError, ReconcilePlanSummary,
        ReconciliationService,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Which layer an aggregate operation acts on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateLayer {
    Interface,
    Firewall,
}

/// Why an aggregate intent was refused before any privileged work happened.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IntentError {
    #[error("desired generation must be greater than zero")]
    GenerationOutOfRange,

    #[error("desired interface does not belong to the stated installation identity")]
    OwnerIdentityMismatch,

    #[error("the stated interface id does not match the desired interface owner tag")]
    InterfaceIdentityMismatch,

    #[error("desired interface is invalid: {0}")]
    InvalidInterface(#[from] ReconcileError),
}

/// One installation's network intent at one desired generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationNetworkIntent {
    pub installation_id: InstallationId,
    pub generation: DesiredGeneration,
    pub interface_id: InterfaceId,
    pub desired_interface: DesiredManagedInterface,
    pub network_policy: Option<DesiredNetworkPolicy>,
}

impl InstallationNetworkIntent {
    /// Builds the intent for one generation of one interface.
    pub fn new(
        installation_id: InstallationId,
        generation: DesiredGeneration,
        interface_id: InterfaceId,
        desired_interface: DesiredManagedInterface,
        network_policy: Option<DesiredNetworkPolicy>,
    ) -> Self {
        Self {
            installation_id,
            generation,
            interface_id,
            desired_interface,
            network_policy,
        }
    }

    /// The owner tag this intent implies.
    pub fn owner_tag(&self) -> OwnerTag {
        OwnerTag::new(self.installation_id, self.interface_id)
    }

    /// Whether this intent asks for the interface to exist.
    pub fn is_present(&self) -> bool {
        self.desired_interface.lifecycle == LinkLifecycle::Present
    }

    /// Revalidates everything that arrived over the wire.
    ///
    /// This runs before any privileged call, so an invalid intent can never
    /// cause partial kernel mutation.
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.generation.to_storage() <= 0 {
            return Err(IntentError::GenerationOutOfRange);
        }
        let tag = &self.desired_interface.owner_tag;
        if tag.installation_id() != self.installation_id {
            return Err(IntentError::OwnerIdentityMismatch);
        }
        if tag.interface_id() != self.interface_id {
            return Err(IntentError::InterfaceIdentityMismatch);
        }
        self.desired_interface
            .validate()
            .map_err(IntentError::InvalidInterface)
    }
}

/// The ordered, per-layer plan for one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationNetworkPlan {
    pub installation_id: InstallationId,
    pub generation: DesiredGeneration,
    /// True when this generation enables rather than disables.
    pub enabling: bool,
    pub interface_plan: ReconcilePlanSummary,
    pub firewall_plan: FirewallPlanSummary,
}

/// The truthful overall outcome of an aggregate apply.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateStatus {
    /// Neither layer required a mutation.
    NoChange,
    /// Every requested layer verified after mutation.
    Applied,
    /// An earlier layer changed state and a later layer failed.
    PartialFailure,
    /// Nothing changed.
    FailedBeforeMutation,
    /// A layer mutated but did not verify.
    VerificationFailed,
}

/// The result of one aggregate apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationNetworkReceipt {
    pub installation_id: InstallationId,
    pub generation: DesiredGeneration,
    pub status: AggregateStatus,
    pub interface: ApplyReceipt,
    pub firewall: FirewallApplyReceipt,
    /// Which layer failed, when one did.
    pub failed_layer: Option<AggregateLayer>,
    /// Whether a fresh post-apply observation succeeded.
    pub observed_after: bool,
}

impl InstallationNetworkReceipt {
    /// Maps a layer status into the overall status.
    ///
    /// `NoChange` requires both layers to need nothing. A failure after an
    /// earlier layer already changed state is a partial failure, never a
    /// rollback: this code does not claim rollback anywhere.
    fn overall(
        interface: &ApplyReceipt,
        firewall: &FirewallApplyReceipt,
        failed_layer: Option<AggregateLayer>,
    ) -> AggregateStatus {
        match failed_layer {
            Some(AggregateLayer::Firewall) => match interface.status {
                ApplyStatus::NoChange => AggregateStatus::FailedBeforeMutation,
                ApplyStatus::VerificationFailed => AggregateStatus::VerificationFailed,
                _ => AggregateStatus::PartialFailure,
            },
            Some(AggregateLayer::Interface) => match interface.status {
                ApplyStatus::VerificationFailed => AggregateStatus::VerificationFailed,
                ApplyStatus::NoChange => AggregateStatus::FailedBeforeMutation,
                _ => AggregateStatus::PartialFailure,
            },
            None => match (interface.status, firewall.status) {
                (ApplyStatus::NoChange, crate::reconcile::ApplyStatus::NoChange) => {
                    AggregateStatus::NoChange
                }
                _ => AggregateStatus::Applied,
            },
        }
    }
}

/// In-process acceptance state, deliberately lost on netd restart.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Accepted {
    installation_id: Option<InstallationId>,
    generation: Option<DesiredGeneration>,
}

/// Why a generation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GenerationRejection {
    #[error("a different installation identity is already active in this netd process")]
    InstallationMismatch,
    #[error("desired generation {requested} is older than the highest accepted {highest}")]
    Stale { requested: u64, highest: u64 },
}

/// The single netd aggregate mutation coordinator.
pub struct AggregateCoordinator {
    reconciliation: ReconciliationService,
    firewall: FirewallService,
    /// One installation-wide lock spans both layer services.
    mutation_lock: Mutex<()>,
    accepted: Mutex<Accepted>,
}

impl std::fmt::Debug for AggregateCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateCoordinator")
            .finish_non_exhaustive()
    }
}

impl Default for AggregateCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregateCoordinator {
    pub fn new() -> Self {
        Self::with_services(ReconciliationService::default(), FirewallService::default())
    }

    pub fn with_services(reconciliation: ReconciliationService, firewall: FirewallService) -> Self {
        Self {
            reconciliation,
            firewall,
            mutation_lock: Mutex::new(()),
            accepted: Mutex::new(Accepted::default()),
        }
    }

    /// Plans every layer of one generation without mutating anything.
    pub fn plan(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<InstallationNetworkPlan, PlanRejection> {
        intent.validate().map_err(PlanRejection::InvalidIntent)?;
        self.check_accepted(intent)
            .map_err(PlanRejection::GenerationRejected)?;

        let interface_plan = self
            .reconciliation
            .plan(&intent.desired_interface)
            .map_err(PlanRejection::Interface)?;

        // For a disable, the firewall layer is planned first so the receipt
        // mirrors the order in which the layers would actually be applied.
        let firewall_plan = match self.firewall.plan(
            intent.installation_id,
            &intent.desired_interface.interface,
            intent
                .network_policy
                .as_ref()
                .filter(|_| intent.is_present()),
        ) {
            Ok(plan) => plan,
            Err(error) => return Err(PlanRejection::Firewall(error)),
        };

        Ok(InstallationNetworkPlan {
            installation_id: intent.installation_id,
            generation: intent.generation,
            enabling: intent.is_present(),
            interface_plan,
            firewall_plan,
        })
    }

    /// Applies every layer of one generation in a fixed order.
    pub fn apply(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<InstallationNetworkReceipt, ApplyRejection> {
        intent.validate().map_err(ApplyRejection::InvalidIntent)?;

        // The outer lock is taken before any layer lock, so ordering is fixed.
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| ApplyRejection::Interface(ReconcileError::BackendFailure))?;

        self.accept_generation(intent)
            .map_err(ApplyRejection::GenerationRejected)?;

        let (interface_receipt, firewall_receipt, failed_layer) = if intent.is_present() {
            self.apply_enabling(intent)?
        } else {
            self.apply_disabling(intent)?
        };

        let status = InstallationNetworkReceipt::overall(
            &interface_receipt,
            &firewall_receipt,
            failed_layer,
        );
        let observed_after = interface_receipt.observed_after.is_some();

        Ok(InstallationNetworkReceipt {
            installation_id: intent.installation_id,
            generation: intent.generation,
            status,
            interface: interface_receipt,
            firewall: firewall_receipt,
            failed_layer,
            observed_after,
        })
    }

    /// Enable path: interface first, then firewall.
    fn apply_enabling(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<(ApplyReceipt, FirewallApplyReceipt, Option<AggregateLayer>), ApplyRejection> {
        let interface = self
            .reconciliation
            .apply(&intent.desired_interface)
            .map_err(ApplyRejection::Interface)?;

        if interface.status != ApplyStatus::Applied && interface.status != ApplyStatus::NoChange {
            // The interface layer did not verify, so no firewall policy is
            // installed for a link that is not in the desired state.
            return Err(ApplyRejection::InterfaceLayerIncomplete {
                receipt: Box::new(interface),
            });
        }

        let firewall = match self.firewall.apply(
            intent.installation_id,
            &intent.desired_interface.interface,
            intent.network_policy.as_ref(),
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return Err(ApplyRejection::FirewallDuringApply {
                    interface: Box::new(interface),
                    error,
                })
            }
        };

        let failed_layer = if firewall.status != crate::reconcile::ApplyStatus::Applied
            && firewall.status != crate::reconcile::ApplyStatus::NoChange
        {
            Some(AggregateLayer::Firewall)
        } else {
            None
        };

        Ok((interface, firewall, failed_layer))
    }

    /// Disable path: firewall first, then interface teardown.
    fn apply_disabling(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<(ApplyReceipt, FirewallApplyReceipt, Option<AggregateLayer>), ApplyRejection> {
        // Removing the owned policy first is what prevents a partial disable
        // from deleting the interface while leaving a wg-basic firewall table
        // whose semantic target no longer exists.
        let firewall = self
            .firewall
            .apply(
                intent.installation_id,
                &intent.desired_interface.interface,
                None,
            )
            .map_err(ApplyRejection::Firewall)?;

        if firewall.status != crate::reconcile::ApplyStatus::Applied
            && firewall.status != crate::reconcile::ApplyStatus::NoChange
        {
            // The interface is deliberately left intact.
            return Err(ApplyRejection::FirewallLayerIncomplete {
                firewall: Box::new(firewall),
            });
        }

        let interface = self
            .reconciliation
            .apply(&intent.desired_interface)
            .map_err(ApplyRejection::Interface)?;

        let failed_layer = if interface.status != ApplyStatus::Applied
            && interface.status != ApplyStatus::NoChange
        {
            Some(AggregateLayer::Interface)
        } else {
            None
        };

        Ok((interface, firewall, failed_layer))
    }

    /// Reads the acceptance state without mutating it.
    fn check_accepted(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<(), GenerationRejection> {
        let accepted = self
            .accepted
            .lock()
            .map_err(|_| GenerationRejection::InstallationMismatch)?;
        check_against(&accepted, intent)
    }

    /// Records the generation as accepted.
    ///
    /// The generation is recorded *before* the first privileged mutation, so a
    /// delayed older request cannot follow it. Failure or partial failure never
    /// reduces the recorded number, and an equal-generation retry stays allowed.
    fn accept_generation(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<(), GenerationRejection> {
        let mut accepted = self
            .accepted
            .lock()
            .map_err(|_| GenerationRejection::InstallationMismatch)?;
        check_against(&accepted, intent)?;
        accepted.installation_id = Some(intent.installation_id);
        accepted.generation = Some(
            accepted
                .generation
                .map_or(intent.generation, |highest| highest.max(intent.generation)),
        );
        Ok(())
    }
}

/// Pure acceptance rule, so it can be tested without a coordinator.
fn check_against(
    accepted: &Accepted,
    intent: &InstallationNetworkIntent,
) -> Result<(), GenerationRejection> {
    if let Some(active) = accepted.installation_id {
        if active != intent.installation_id {
            return Err(GenerationRejection::InstallationMismatch);
        }
    }
    if let Some(highest) = accepted.generation {
        // Strictly older is refused; equal is an allowed idempotent reapply.
        if intent.generation.to_storage() < highest.to_storage() {
            return Err(GenerationRejection::Stale {
                requested: intent.generation.to_storage() as u64,
                highest: highest.to_storage() as u64,
            });
        }
    }
    Ok(())
}

/// Why an aggregate plan was refused.
#[derive(Debug, thiserror::Error)]
pub enum PlanRejection {
    #[error(transparent)]
    InvalidIntent(#[from] IntentError),
    #[error(transparent)]
    GenerationRejected(#[from] GenerationRejection),
    #[error(transparent)]
    Interface(#[from] ReconcileError),
    #[error(transparent)]
    Firewall(#[from] crate::firewall::FirewallError),
}

/// Why an aggregate apply was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApplyRejection {
    #[error(transparent)]
    InvalidIntent(#[from] IntentError),
    #[error(transparent)]
    GenerationRejected(#[from] GenerationRejection),
    #[error(transparent)]
    Interface(#[from] ReconcileError),

    #[error("the interface layer did not complete, so the firewall layer was not attempted")]
    InterfaceLayerIncomplete { receipt: Box<ApplyReceipt> },

    #[error(transparent)]
    Firewall(#[from] crate::firewall::FirewallError),

    #[error("the firewall layer failed during enable after the interface changed")]
    FirewallDuringApply {
        interface: Box<ApplyReceipt>,
        #[source]
        error: crate::firewall::FirewallError,
    },

    #[error("the firewall layer did not complete, so the interface was left intact")]
    FirewallLayerIncomplete { firewall: Box<FirewallApplyReceipt> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{NetworkPrefix, PrivateKey},
        firewall::{Ipv4Forwarding, Ipv6Forwarding, NatMode},
        reconcile::{DesiredManagedPeer, DesiredWireGuardConfiguration, OwnershipDeclaration},
    };

    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PEER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn installation() -> InstallationId {
        "00000000-0000-4000-8000-0000000000a1".parse().unwrap()
    }

    fn generation(value: u64) -> DesiredGeneration {
        DesiredGeneration::new(value).unwrap()
    }

    fn present_intent() -> InstallationNetworkIntent {
        let installation = installation();
        let interface_id = InterfaceId::new();
        InstallationNetworkIntent::new(
            installation,
            generation(1),
            interface_id,
            DesiredManagedInterface {
                interface: "wg0".parse().unwrap(),
                ownership: OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Present,
                admin_up: Some(true),
                owner_tag: OwnerTag::new(installation, interface_id),
                wireguard: Some(DesiredWireGuardConfiguration {
                    private_key: PrivateKey::new(KEY.into()).unwrap(),
                    listen_port: 51820,
                    peers: vec![DesiredManagedPeer {
                        public_key: crate::domain::PublicKey::new(PEER.into()).unwrap(),
                        allowed_ips: vec![NetworkPrefix::new("10.8.0.2/32".parse().unwrap())],
                        persistent_keepalive_seconds: None,
                        endpoint: None,
                    }],
                    manage_all_peers: true,
                }),
                addresses: vec![crate::reconcile::DesiredAddress {
                    address: "10.8.0.1/24".parse().unwrap(),
                    presence: crate::reconcile::ResourcePresence::Present,
                }],
                routes: Vec::new(),
            },
            Some(DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::Required,
                ipv6_forwarding: Ipv6Forwarding::NotRequired,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
                nat: NatMode::Masquerade,
            }),
        )
    }

    fn absent_intent() -> InstallationNetworkIntent {
        let installation = installation();
        let interface_id = InterfaceId::new();
        InstallationNetworkIntent::new(
            installation,
            generation(1),
            interface_id,
            DesiredManagedInterface {
                interface: "wg0".parse().unwrap(),
                ownership: OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Absent,
                admin_up: None,
                owner_tag: OwnerTag::new(installation, interface_id),
                wireguard: None,
                addresses: Vec::new(),
                routes: Vec::new(),
            },
            None,
        )
    }

    #[test]
    fn a_valid_intent_reports_the_owner_tag_it_implies() {
        let intent = present_intent();
        assert!(intent.validate().is_ok());
        assert_eq!(
            intent.owner_tag(),
            intent.desired_interface.owner_tag,
            "netd derives the tag from the intent identity rather than trusting a caller label"
        );
        assert!(intent.is_present());
        assert!(!absent_intent().is_present());
    }

    #[test]
    fn an_owner_tag_from_another_installation_is_refused_before_privileged_work() {
        let mut intent = present_intent();
        intent.desired_interface.owner_tag =
            OwnerTag::new(InstallationId::new(), intent.interface_id);
        assert!(matches!(
            intent.validate(),
            Err(IntentError::OwnerIdentityMismatch)
        ));
    }

    #[test]
    fn an_owner_tag_from_another_interface_is_refused() {
        let mut intent = present_intent();
        intent.desired_interface.owner_tag =
            OwnerTag::new(intent.installation_id, InterfaceId::new());
        assert!(matches!(
            intent.validate(),
            Err(IntentError::InterfaceIdentityMismatch)
        ));
    }

    #[test]
    fn generation_bounds_are_validated() {
        let intent = present_intent();
        // DesiredGeneration cannot represent zero or a negative value at all,
        // so the guard exists for values that bypass its constructor.
        assert!(DesiredGeneration::from_storage(0).is_none());
        assert!(intent.validate().is_ok());
    }

    #[test]
    fn an_invalid_interface_is_refused_before_any_privileged_call() {
        let mut intent = present_intent();
        intent.desired_interface.admin_up = None;
        assert!(matches!(
            intent.validate(),
            Err(IntentError::InvalidInterface(
                ReconcileError::InvalidDesiredState
            ))
        ));
    }

    #[test]
    fn the_first_generation_establishes_the_installation_identity() {
        let accepted = Accepted::default();
        let intent = present_intent();
        assert!(check_against(&accepted, &intent).is_ok());
    }

    #[test]
    fn a_higher_generation_is_eligible_and_equal_is_idempotent() {
        let accepted = Accepted {
            installation_id: Some(installation()),
            generation: Some(generation(5)),
        };

        let newer = InstallationNetworkIntent {
            generation: generation(6),
            ..present_intent()
        };
        assert!(check_against(&accepted, &newer).is_ok());

        let same = InstallationNetworkIntent {
            generation: generation(5),
            ..present_intent()
        };
        assert!(
            check_against(&accepted, &same).is_ok(),
            "an equal generation must remain an allowed idempotent reapply"
        );
    }

    #[test]
    fn a_lower_generation_is_rejected_as_stale() {
        let accepted = Accepted {
            installation_id: Some(installation()),
            generation: Some(generation(5)),
        };
        let older = InstallationNetworkIntent {
            generation: generation(4),
            ..present_intent()
        };
        assert!(matches!(
            check_against(&accepted, &older),
            Err(GenerationRejection::Stale {
                requested: 4,
                highest: 5
            })
        ));
    }

    #[test]
    fn a_different_installation_identity_is_rejected_while_the_process_lives() {
        let accepted = Accepted {
            installation_id: Some(installation()),
            generation: Some(generation(1)),
        };
        let foreign = InstallationNetworkIntent {
            installation_id: InstallationId::new(),
            ..present_intent()
        };
        assert!(matches!(
            check_against(&accepted, &foreign),
            Err(GenerationRejection::InstallationMismatch)
        ));
    }

    #[test]
    fn acceptance_records_the_generation_before_mutation_and_never_lowers_it() {
        let coordinator = AggregateCoordinator::new();
        let first = InstallationNetworkIntent {
            generation: generation(2),
            ..present_intent()
        };

        // A stale writer is refused once a generation has been accepted.
        coordinator
            .accept_generation(&first)
            .expect("first generation is accepted");

        let older = InstallationNetworkIntent {
            generation: generation(1),
            ..present_intent()
        };
        assert!(coordinator.accept_generation(&older).is_err());

        // An equal retry is accepted, and a later generation raises the bar.
        coordinator
            .accept_generation(&first)
            .expect("equal retry allowed");
        let newer = InstallationNetworkIntent {
            generation: generation(9),
            ..present_intent()
        };
        coordinator
            .accept_generation(&newer)
            .expect("higher generation allowed");

        let between = InstallationNetworkIntent {
            generation: generation(7),
            ..present_intent()
        };
        assert!(matches!(
            coordinator.accept_generation(&between),
            Err(GenerationRejection::Stale {
                requested: 7,
                highest: 9
            })
        ));
    }

    #[test]
    fn absence_of_a_layer_status_is_reported_truthfully() {
        // NoChange requires both layers to need nothing.
        let interface_changed = ApplyReceipt {
            interface: "wg0".parse().unwrap(),
            status: ApplyStatus::Applied,
            planned_actions: Vec::new(),
            completed_actions: 1,
            failed_action: None,
            failure: None,
            observed_after: None,
        };
        let firewall_changed = FirewallApplyReceipt {
            wireguard_interface: "wg0".parse().unwrap(),
            status: crate::reconcile::ApplyStatus::Applied,
            actions: Vec::new(),
            forwarding_changed: true,
            table_changed: true,
            failure: None,
            warnings: Vec::new(),
        };
        assert_eq!(
            InstallationNetworkReceipt::overall(&interface_changed, &firewall_changed, None),
            AggregateStatus::Applied
        );
        assert_eq!(
            InstallationNetworkReceipt::overall(
                &interface_changed,
                &firewall_changed,
                Some(AggregateLayer::Firewall)
            ),
            AggregateStatus::PartialFailure,
            "an earlier layer already changed state, so this is not a clean failure"
        );
    }
}
