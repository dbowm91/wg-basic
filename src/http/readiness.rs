//! Readiness: the four states an operator has to be able to tell apart.
//!
//! # Why this is a type and not a log line
//!
//! A management service has four genuinely different situations, and an operator
//! responds to each differently:
//!
//! 1. **The process is alive** — the listener is bound and answering. Nothing
//!    needs doing.
//! 2. **A dependency is unhealthy** — the listener is bound and answering, but
//!    the database, netd, or the network convergence is not what it should be.
//!    The surface must stay up, because diagnosing and fixing this *is* what the
//!    surface is for. Restarting the process does not help; nothing has crashed.
//! 3. **The state is unusable** — the database cannot be opened, the path is
//!    wrong, or a migration cannot be applied. There is no authoritative state to
//!    administer, so the process exits without ever binding a listener. A live
//!    surface here would be a lie: it would accept credentials for an appliance
//!    whose state nobody can vouch for.
//! 4. **Detailed management health** — the full projection, renderable only to a
//!    caller who has proven a session.
//!
//! Collapsing 1 and 2 is the classic liveness/readiness confusion; collapsing 2
//! into 3 is how a netd outage becomes a service that crash-loops; collapsing any
//! of them into 4 without a session is a disclosure. [`Readiness`] exists so the
//! four are one exhaustive decision instead of four ad-hoc booleans.
//!
//! # The public projection is deliberately lossy
//!
//! [`Readiness::public_token`] returns `ok` or `degraded` and nothing else. The
//! *reasons* are carried in the type but reach only two places: the operator's
//! log at startup ([`Readiness::describe`]), and the authenticated
//! `/api/v1/health` route, which renders
//! [`ManagementHealth`](crate::management::ManagementHealth) rather than this
//! type. There is deliberately no third way to read the reasons, so a future
//! route cannot accidentally expose them.
//!
//! `/healthz` therefore cannot be widened by editing [`Readiness`] — adding a
//! reason changes what the operator log says and nothing about what an
//! unauthenticated caller receives. That is the M003 carry-forward: the public
//! contract is `ok` or `degraded`, full stop.

use crate::management::{ManagementHealth, StartupReconcile};

/// A dependency whose health the service can observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Dependency {
    /// The authoritative state database.
    Database,
    /// The authorized local netd socket.
    Backend,
    /// Whether the network matches the current desired generation.
    Convergence,
}

impl Dependency {
    /// A stable operator-facing name for one dependency.
    ///
    /// Fixed words rather than the value's `Debug`, so the log line an operator
    /// greps for does not change when an internal type is renamed.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "state database",
            Self::Backend => "network backend",
            Self::Convergence => "network convergence",
        }
    }
}

/// The service's readiness, with the reasons an operator needs kept apart from
/// what an anonymous caller is told.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// Bound, answering, and every observable dependency is healthy.
    Ready,
    /// Bound and answering, but at least one dependency is not healthy.
    ///
    /// Empty in no case: a `Degraded` with no reason could not be rendered, and
    /// [`Readiness::degraded_with`] refuses to build one.
    Degraded {
        /// Every unhealthy dependency, deduplicated and ordered.
        unhealthy: Vec<Dependency>,
    },
    /// The state could not be opened, so the process exits without binding.
    ///
    /// Not observable over HTTP by construction — there is no listener — which is
    /// why [`Readiness::public_token`] has no answer for it.
    Fatal {
        /// The dependency that made the run impossible.
        dependency: Dependency,
    },
}

impl Readiness {
    /// Builds a degraded state, deduplicating and ordering the reasons.
    ///
    /// Returns [`Readiness::Ready`] for an empty list rather than constructing a
    /// degraded state with nothing to say, so "degraded" always means something
    /// is wrong and can always be explained.
    pub fn degraded_with(unhealthy: impl IntoIterator<Item = Dependency>) -> Self {
        let mut unhealthy: Vec<Dependency> = unhealthy.into_iter().collect();
        unhealthy.sort();
        unhealthy.dedup();
        if unhealthy.is_empty() {
            return Self::Ready;
        }
        Self::Degraded { unhealthy }
    }

    /// Reads readiness out of a live management health snapshot.
    ///
    /// The only function that derives runtime readiness, so the `/healthz` answer
    /// and the authenticated answer cannot disagree about whether the appliance
    /// is healthy.
    pub fn from_health(health: &ManagementHealth) -> Self {
        if health.is_healthy() {
            return Self::Ready;
        }
        Self::degraded_with(
            [
                (!health.database_healthy).then_some(Dependency::Database),
                (!health.netd_reachable).then_some(Dependency::Backend),
                (health.convergence != crate::management::ConvergenceState::Converged)
                    .then_some(Dependency::Convergence),
            ]
            .into_iter()
            .flatten(),
        )
    }

    /// Reads readiness out of what the mandatory startup reconcile concluded.
    ///
    /// This answers a *different* question from [`Readiness::from_health`], and
    /// the difference is load-bearing:
    ///
    /// * startup asks "did the mandatory startup work succeed?" — a reconcile
    ///   that came back degraded means the network is not converged;
    /// * live asks "is the appliance healthy right now?" — which also asks
    ///   whether the database and the backend answer at all.
    ///
    /// So a fresh install with nothing to apply and no netd listening is
    /// [`Readiness::Ready`] at startup and [`Readiness::Degraded`] on
    /// `/healthz`. That is not a contradiction: there was genuinely nothing to
    /// converge, and there is genuinely no evidence netd ever answered.
    ///
    /// The database is healthy by construction at this point: reaching this
    /// function means [`crate::management::spawn`] already opened it. A failure
    /// there never reaches readiness at all — the process exits as
    /// [`Readiness::Fatal`] before a listener exists.
    pub fn from_startup(reconcile: StartupReconcile) -> Self {
        if reconcile.is_degraded() {
            Self::degraded_with([Dependency::Convergence])
        } else {
            Self::Ready
        }
    }

    /// The two tokens an unauthenticated caller may see.
    ///
    /// `None` for [`Readiness::Fatal`], which cannot be observed over HTTP at
    /// all. Returning `None` rather than inventing a third token is the point:
    /// there is no fatal HTTP state to render, because the process is gone.
    pub fn public_token(&self) -> Option<&'static str> {
        match self {
            Self::Ready => Some("ok"),
            Self::Degraded { .. } => Some("degraded"),
            Self::Fatal { .. } => None,
        }
    }

    /// Whether the service is bound and answering.
    pub fn is_serving(&self) -> bool {
        !matches!(self, Self::Fatal { .. })
    }

    /// Whether at least one dependency is unhealthy.
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    /// The unhealthy dependencies, for a caller that is allowed to know.
    ///
    /// Empty for [`Readiness::Ready`] and [`Readiness::Fatal`]; the fatal case
    /// names its single dependency through [`Readiness::dependency`] instead, so
    /// this accessor cannot be used to read a fatal run's reason by accident.
    pub fn unhealthy(&self) -> &[Dependency] {
        match self {
            Self::Degraded { unhealthy } => unhealthy,
            _ => &[],
        }
    }

    /// The one dependency that decided this state, if the state names exactly one.
    ///
    /// Both [`Readiness::Fatal`] and a single-reason [`Readiness::Degraded`] have
    /// one; [`Readiness::Ready`] has none, and a multi-reason degradation has no
    /// single cause to report.
    pub fn dependency(&self) -> Option<Dependency> {
        match self {
            Self::Fatal { dependency } => Some(*dependency),
            Self::Degraded { unhealthy } if unhealthy.len() == 1 => Some(unhealthy[0]),
            _ => None,
        }
    }

    /// One operator-readable line, for the startup log.
    ///
    /// This is the *only* place the reasons are rendered, and it renders to a log
    /// line an operator reads, not to a response body.
    pub fn describe(&self) -> String {
        match self {
            Self::Ready => "ready".to_owned(),
            Self::Degraded { unhealthy } => format!(
                "degraded: {}",
                unhealthy
                    .iter()
                    .map(|dependency| dependency.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Fatal { dependency } => {
                format!("fatal: the {} could not be opened", dependency.as_str())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DesiredGeneration, InstallationId};
    use crate::management::{AttemptDisposition, ConvergenceState};

    fn healthy() -> ManagementHealth {
        ManagementHealth {
            database_healthy: true,
            netd_reachable: true,
            installation_id: Some(InstallationId::new()),
            current_desired_generation: DesiredGeneration::new(2),
            last_converged_generation: DesiredGeneration::new(2),
            convergence: ConvergenceState::Converged,
            last_failure_category: None,
        }
    }

    #[test]
    fn an_unhealthy_dependency_is_degraded_not_fatal() {
        // The plan's central distinction: the listener may be up while netd is
        // unavailable or conflicted. Serving is what lets anyone diagnose it.
        let mut health = healthy();
        health.netd_reachable = false;
        let readiness = Readiness::from_health(&health);
        assert!(readiness.is_serving(), "a backend outage must still serve");
        assert!(readiness.is_degraded());
        assert_eq!(readiness.public_token(), Some("degraded"));
        assert_eq!(readiness.dependency(), Some(Dependency::Backend));
        assert_eq!(readiness.describe(), "degraded: network backend");
    }

    #[test]
    fn every_unhealthy_dependency_is_reported_and_none_is_invented() {
        let mut health = healthy();
        health.database_healthy = false;
        health.netd_reachable = false;
        health.convergence = ConvergenceState::Failed;
        let readiness = Readiness::from_health(&health);
        assert_eq!(
            readiness.unhealthy(),
            &[
                Dependency::Database,
                Dependency::Backend,
                Dependency::Convergence
            ],
            "all three must be named, in a stable order"
        );
        // The public answer is still the single token.
        assert_eq!(readiness.public_token(), Some("degraded"));
        assert_eq!(
            readiness.dependency(),
            None,
            "three reasons have no single cause to report"
        );
    }

    #[test]
    fn a_failure_in_one_dependency_does_not_claim_the_others_are_wrong() {
        let mut health = healthy();
        health.convergence = ConvergenceState::Pending;
        let readiness = Readiness::from_health(&health);
        assert_eq!(readiness.unhealthy(), &[Dependency::Convergence]);
        assert!(readiness
            .describe()
            .starts_with("degraded: network convergence"));
    }

    #[test]
    fn a_fatal_state_has_no_public_answer_and_is_not_serving() {
        // A fatal state is unreachable over HTTP by construction, so there is
        // nothing to render. Returning a third token here would invent an HTTP
        // state the process never actually serves.
        let readiness = Readiness::Fatal {
            dependency: Dependency::Database,
        };
        assert!(!readiness.is_serving());
        assert!(!readiness.is_degraded());
        assert_eq!(readiness.public_token(), None);
        assert_eq!(readiness.dependency(), Some(Dependency::Database));
        assert!(readiness
            .describe()
            .starts_with("fatal: the state database"));
    }

    #[test]
    fn a_degraded_state_always_has_a_reason() {
        // An empty degradation could not be explained to an operator, and a
        // caller asking for one of the two tokens would have no way to say which.
        assert_eq!(
            Readiness::degraded_with([]),
            Readiness::Ready,
            "no reasons is not degraded, it is ready"
        );
        let repeated = Readiness::degraded_with([Dependency::Backend, Dependency::Backend]);
        assert_eq!(repeated.unhealthy(), &[Dependency::Backend]);
    }

    #[test]
    fn the_startup_reconcile_only_ever_moves_convergence() {
        // Reaching startup means the database is already open, so the reconcile
        // can never be evidence about anything else.
        assert_eq!(
            Readiness::from_startup(StartupReconcile::NothingToApply),
            Readiness::Ready
        );
        let converged = StartupReconcile::Converged {
            generation: DesiredGeneration::new(1).unwrap(),
        };
        assert_eq!(
            Readiness::from_startup(converged),
            Readiness::Ready,
            "a converged reconcile is a healthy startup: {converged:?}"
        );
        let degraded = Readiness::from_startup(StartupReconcile::Degraded {
            category: AttemptDisposition::BackendUnavailable,
        });
        assert_eq!(degraded.unhealthy(), &[Dependency::Convergence]);
        assert!(degraded.is_serving());
    }

    #[test]
    fn the_public_projection_is_exactly_two_tokens() {
        // The M003 carry-forward, asserted: whatever the reason, an anonymous
        // caller sees `ok` or `degraded` and nothing else.
        let mut states = vec![Readiness::Ready];
        for dependency in [
            Dependency::Database,
            Dependency::Backend,
            Dependency::Convergence,
        ] {
            states.push(Readiness::degraded_with([dependency]));
            states.push(Readiness::Fatal { dependency });
        }
        states.push(Readiness::degraded_with([
            Dependency::Database,
            Dependency::Backend,
            Dependency::Convergence,
        ]));
        let mut tokens: Vec<&str> = states.iter().filter_map(Readiness::public_token).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens, vec!["degraded", "ok"]);
    }

    #[test]
    fn the_anonymous_answer_does_not_depend_on_the_reason() {
        // The load-bearing property behind "do not make `/healthz` reveal why":
        // every possible reason, individually and all together, produces the
        // *same* token. If adding a reason could change it, the token would be
        // an oracle for which dependency is down.
        let mut tokens: Vec<&str> = Vec::new();
        for dependency in [
            Dependency::Database,
            Dependency::Backend,
            Dependency::Convergence,
        ] {
            let single = Readiness::degraded_with([dependency]);
            assert_eq!(
                single.public_token(),
                Readiness::degraded_with([
                    Dependency::Database,
                    Dependency::Backend,
                    Dependency::Convergence
                ])
                .public_token(),
                "one reason and three reasons must not be distinguishable: {dependency:?}"
            );
            tokens.push(single.public_token().expect("a degraded state is serving"));
        }
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(
            tokens,
            vec!["degraded"],
            "every degraded state answers the same token"
        );

        // And no reason wording is a substring of the token itself, so the token
        // cannot be a format of one.
        for dependency in [
            Dependency::Database,
            Dependency::Backend,
            Dependency::Convergence,
        ] {
            let token = Readiness::degraded_with([dependency])
                .public_token()
                .expect("a degraded state is serving");
            assert!(
                !token.contains(dependency.as_str()),
                "{token:?} leaks the reason {}",
                dependency.as_str()
            );
        }
    }
}
