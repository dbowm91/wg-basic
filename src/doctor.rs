//! Read-only operator diagnostics shared by the `doctor` command and tests.
//!
//! A report contains only bounded, product-owned descriptions. Backend errors
//! are classified at their boundary and are never copied into this model.

use serde::{Deserialize, Serialize};

const MAX_TEXT: usize = 240;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorDisposition {
    Pass,
    Warn,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCheckId {
    State,
    Sqlite,
    Netd,
    ServiceLease,
    HttpPolicy,
    Forwarding,
    NetworkOwnership,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    pub id: DoctorCheckId,
    pub disposition: DoctorDisposition,
    pub summary: String,
    pub evidence: String,
    pub remediation: String,
}

impl DoctorCheck {
    pub fn new(
        id: DoctorCheckId,
        disposition: DoctorDisposition,
        summary: impl Into<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            id,
            disposition,
            summary: bounded(summary.into()),
            evidence: bounded(evidence.into()),
            remediation: bounded(remediation.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub version: String,
    pub overall: DoctorDisposition,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub fn new(checks: Vec<DoctorCheck>) -> Self {
        let overall = checks
            .iter()
            .fold(DoctorDisposition::Pass, |current, check| {
                let rank = |value| match value {
                    DoctorDisposition::Pass => 0,
                    DoctorDisposition::Warn => 1,
                    DoctorDisposition::Unknown => 2,
                    DoctorDisposition::Fail => 3,
                };
                if rank(check.disposition) > rank(current) {
                    check.disposition
                } else {
                    current
                }
            });
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            overall,
            checks,
        }
    }

    /// Exit status contract: clean=0, attention=1, required failure=2.
    pub fn exit_code(&self) -> i32 {
        match self.overall {
            DoctorDisposition::Pass => 0,
            DoctorDisposition::Warn | DoctorDisposition::Unknown => 1,
            DoctorDisposition::Fail => 2,
        }
    }

    pub fn render_human(&self) -> String {
        let mut output = format!("wg-basic doctor: {:?}\n", self.overall);
        for check in &self.checks {
            output.push_str(&format!(
                "{:?} {:?}: {}\n  evidence: {}\n  next: {}\n",
                check.disposition, check.id, check.summary, check.evidence, check.remediation
            ));
        }
        output
    }
}

fn bounded(value: String) -> String {
    value.chars().take(MAX_TEXT).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_aggregates_disposition_and_caps_text() {
        let report = DoctorReport::new(vec![DoctorCheck::new(
            DoctorCheckId::Netd,
            DoctorDisposition::Unknown,
            "x".repeat(500),
            "bounded evidence",
            "start netd",
        )]);
        assert_eq!(report.overall, DoctorDisposition::Unknown);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.checks[0].summary.len(), MAX_TEXT);
    }

    #[test]
    fn required_failure_has_exit_code_two() {
        let report = DoctorReport::new(vec![DoctorCheck::new(
            DoctorCheckId::State,
            DoctorDisposition::Fail,
            "invalid",
            "integrity check failed",
            "restore a verified backup",
        )]);
        assert_eq!(report.exit_code(), 2);
    }
}
