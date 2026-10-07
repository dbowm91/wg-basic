//! The management failure taxonomy and the single retry rule.
//!
//! One enum describes how an operation failed, and one `classify` decides
//! whether that failure may be retried. Keeping both together is the point: a
//! second call site cannot invent its own notion of "retryable" and quietly
//! disagree with the first.

use crate::{
    protocol::ProtocolError,
    state::{AttemptDisposition, StateError},
};

/// How a management operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error(transparent)]
    State(#[from] StateError),

    #[error("the desired state cannot be projected into network intent: {0}")]
    Projection(ProjectionFailure),

    #[error("this installation currently manages no interface, so there is nothing to reconcile")]
    NothingToReconcile,

    #[error("could not contact the authorized network service")]
    BackendUnavailable,

    #[error("an earlier network layer changed state and a later one failed; a fresh attempt may converge")]
    PartialFailure,

    #[error("the network service refused the request; operator or state change required")]
    Conflict,

    #[error("the network service rejected this caller")]
    Unauthorized,

    #[error("the network service refused the request; operator or state change required")]
    Rejected,

    #[error("the network service returned an unexpected response")]
    UnexpectedResponse,

    #[error("could not start the dedicated management worker thread")]
    WorkerStartFailed,
}

/// A projection problem, reported as a category rather than a message.
///
/// Carrying only a category keeps diagnostics free of state content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProjectionFailure {
    #[error("durable state does not project into a valid network intent")]
    Invalid,
    #[error("projected owner tag does not match the durable interface identity")]
    OwnerTagMismatch,
}

impl From<crate::state::ProjectionError> for ProjectionFailure {
    fn from(_: crate::state::ProjectionError) -> Self {
        Self::Invalid
    }
}

/// The retry decision implied by a management error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// netd was unreachable; a bounded retry may help.
    BackendUnavailable,
    /// An earlier layer changed state and a later one failed; a bounded retry may
    /// help.
    PartialFailure,
    /// Ownership or state conflict; an operator or state change is required.
    Conflict,
    /// netd refused the request; an operator or state change is required.
    Refused,
    /// Anything else; surfaced without retrying.
    Other,
}

impl ManagementError {
    /// Classifies an error for retry policy and health projection.
    pub fn classify(&self) -> FailureClass {
        match self {
            Self::BackendUnavailable => FailureClass::BackendUnavailable,
            Self::PartialFailure => FailureClass::PartialFailure,
            Self::Conflict => FailureClass::Conflict,
            Self::Unauthorized | Self::Rejected => FailureClass::Refused,
            _ => FailureClass::Other,
        }
    }

    /// The stored evidence category this failure corresponds to.
    ///
    /// Used when a failure has to be reported as a category rather than a
    /// message. Errors with no honest category become
    /// [`AttemptDisposition::Rejected`] only when the network service was the
    /// refusing party; anything that is a local state or thread problem reports
    /// `None` so a caller never invents convergence evidence for it.
    pub fn evidence_category(&self) -> Option<AttemptDisposition> {
        Some(match self {
            Self::BackendUnavailable => AttemptDisposition::BackendUnavailable,
            Self::PartialFailure => AttemptDisposition::PartialFailure,
            Self::Conflict => AttemptDisposition::StateConflict,
            Self::Unauthorized => AttemptDisposition::Unauthorized,
            Self::Rejected | Self::UnexpectedResponse => AttemptDisposition::Rejected,
            Self::State(_)
            | Self::Projection(_)
            | Self::NothingToReconcile
            | Self::WorkerStartFailed => return None,
        })
    }

    /// Whether this failure means the service has no usable authoritative state.
    ///
    /// A database, path, migration, or projection failure is fatal: there is
    /// nothing to administer. A netd outage, refusal, or ownership conflict is
    /// not, because the operator needs the management surface in order to
    /// diagnose and fix it.
    pub fn is_fatal_without_authority(&self) -> bool {
        matches!(
            self,
            Self::State(_) | Self::Projection(_) | Self::WorkerStartFailed
        )
    }
}

/// Maps a transport error onto a retry decision.
///
/// When the error came from a netd reply, the [`ProtocolError`] is preserved as
/// the payload and classification is exact. Only genuine transport failures —
/// a missing or refused connection, which is normal while netd starts — fall
/// back to the lossy [`std::io::ErrorKind`].
///
/// Collapsing every failure into "unavailable" would both retry genuine
/// ownership conflicts and record a misleading health category.
pub(super) fn classify_io(error: std::io::Error) -> ManagementError {
    use std::io::ErrorKind as Kind;
    if let Some(protocol_error) = error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<ProtocolError>())
    {
        return classify_protocol(*protocol_error);
    }
    match error.kind() {
        Kind::NotFound
        | Kind::ConnectionRefused
        | Kind::ConnectionReset
        | Kind::ConnectionAborted
        | Kind::BrokenPipe
        | Kind::TimedOut
        | Kind::Interrupted
        | Kind::WouldBlock => ManagementError::BackendUnavailable,
        Kind::PermissionDenied => ManagementError::Unauthorized,
        _ => ManagementError::Rejected,
    }
}

/// Classifies a refusal netd actually returned.
pub(super) fn classify_protocol(error: ProtocolError) -> ManagementError {
    match error {
        ProtocolError::Conflict => ManagementError::Conflict,
        ProtocolError::Unauthorized | ProtocolError::PermissionDenied => {
            ManagementError::Unauthorized
        }
        // netd uses BackendFailure to report that an earlier layer already
        // mutated state and a later layer failed. A fresh attempt is expected
        // to converge, so this stays retryable under a bound.
        ProtocolError::BackendFailure => ManagementError::PartialFailure,
        ProtocolError::UnsupportedVersion
        | ProtocolError::MalformedRequest
        | ProtocolError::InternalFailure
        | ProtocolError::InvalidInput
        | ProtocolError::NotFound
        | ProtocolError::UnsupportedBackend
        | ProtocolError::KernelRejected => ManagementError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AttemptDisposition;

    #[test]
    fn transient_transport_errors_are_treated_as_backend_unavailable() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::TimedOut,
        ] {
            let error = classify_io(std::io::Error::new(kind, "x"));
            assert_eq!(
                error.classify(),
                FailureClass::BackendUnavailable,
                "{kind:?}"
            );
        }
        assert_eq!(
            ManagementError::Conflict.classify(),
            FailureClass::Conflict,
            "ownership conflicts must not be retried"
        );
    }

    #[test]
    fn refusals_are_not_mistaken_for_an_unavailable_backend() {
        for (error, expected) in [
            (ProtocolError::Conflict, FailureClass::Conflict),
            (ProtocolError::Unauthorized, FailureClass::Refused),
            (ProtocolError::PermissionDenied, FailureClass::Refused),
            (ProtocolError::UnsupportedBackend, FailureClass::Refused),
            (ProtocolError::MalformedRequest, FailureClass::Refused),
            (ProtocolError::InternalFailure, FailureClass::Refused),
            (ProtocolError::InvalidInput, FailureClass::Refused),
            (ProtocolError::KernelRejected, FailureClass::Refused),
            // A partial apply stays retryable under a bound.
            (ProtocolError::BackendFailure, FailureClass::PartialFailure),
        ] {
            let classified = classify_protocol(error).classify();
            assert_eq!(classified, expected, "{error:?}");
            assert_ne!(
                classified,
                FailureClass::BackendUnavailable,
                "{error:?} must not be retried as a transient outage"
            );
        }
    }

    /// The client keeps the wire refusal as the io error payload, so an exact
    /// classification survives the transport boundary.
    #[test]
    fn a_preserved_protocol_error_outranks_the_transport_kind() {
        let wrapped = std::io::Error::other(ProtocolError::BackendFailure);
        assert_eq!(
            classify_io(wrapped).classify(),
            FailureClass::PartialFailure,
            "a partial apply must not be confused with a hard refusal"
        );
    }

    #[test]
    fn attempt_dispositions_are_categories_not_messages() {
        for disposition in [
            AttemptDisposition::Converged,
            AttemptDisposition::PartialFailure,
            AttemptDisposition::VerificationFailed,
            AttemptDisposition::FailedBeforeMutation,
            AttemptDisposition::Superseded,
            AttemptDisposition::StateConflict,
            AttemptDisposition::BackendUnavailable,
            AttemptDisposition::Unauthorized,
            AttemptDisposition::Rejected,
        ] {
            let rendered = disposition.as_str();
            assert!(!rendered.is_empty());
            assert_eq!(
                AttemptDisposition::parse_category(rendered),
                Some(disposition)
            );
        }
        assert_eq!(
            AttemptDisposition::parse_category("secret-looking-string"),
            None
        );
    }
}
