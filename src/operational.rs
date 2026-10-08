//! Small, project-owned operational event output.
//!
//! Events are bounded values, not formatted backend errors. They are written
//! only to stderr; command results and machine-readable command output stay on
//! stdout. The process supervisor owns retention.

use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFormat {
    Human,
    Json,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);
static LAST_REJECTION_EVENT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_RATE_LIMIT_EVENT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub fn set_format(format: LogFormat) {
    FORMAT.store(u8::from(format == LogFormat::Json), Ordering::Relaxed);
}

pub fn command_failure(message: &str) {
    if FORMAT.load(Ordering::Relaxed) == 1 {
        emit(
            "command.failed",
            Severity::Error,
            "operator",
            "command",
            "failed",
            None,
            None,
            None,
        );
    } else {
        eprintln!("wg-basic: {message}");
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

#[derive(Serialize)]
struct Event<'a> {
    timestamp_unix_ms: u128,
    event_code: &'a str,
    severity: Severity,
    role: &'a str,
    operation: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    desired_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)] // The fields are the deliberately closed event schema.
pub fn emit<'a>(
    event_code: &'static str,
    severity: Severity,
    role: &'static str,
    operation: &'static str,
    outcome: &'static str,
    resource: Option<(&'a str, &'a str)>,
    desired_generation: Option<u64>,
    stage: Option<&'static str>,
) {
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let rate_limit = match event_code {
        "netd.request_rejected" => Some(&LAST_REJECTION_EVENT_MS),
        "security.rate_limited" => Some(&LAST_RATE_LIMIT_EVENT_MS),
        _ => None,
    };
    if let Some(last_event) = rate_limit {
        let now = timestamp_unix_ms.min(u64::MAX as u128) as u64;
        let previous = last_event.load(Ordering::Relaxed);
        if now.saturating_sub(previous) < 1_000
            || last_event
                .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
    }
    let event = Event {
        timestamp_unix_ms,
        event_code,
        severity,
        role,
        operation,
        outcome,
        resource_kind: resource.map(|value| value.0),
        resource_id: resource.map(|value| value.1),
        desired_generation,
        stage,
    };
    if FORMAT.load(Ordering::Relaxed) == 1 {
        if let Ok(encoded) = serde_json::to_string(&event) {
            eprintln!("{encoded}");
        }
    } else {
        let severity = match severity {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        };
        eprintln!(
            "{severity} {role} {event_code} operation={operation} outcome={outcome}{}{}{}{}",
            event
                .resource_kind
                .map(|value| format!(" resource_kind={value}"))
                .unwrap_or_default(),
            event
                .resource_id
                .map(|value| format!(" resource_id={value}"))
                .unwrap_or_default(),
            event
                .desired_generation
                .map(|value| format!(" generation={value}"))
                .unwrap_or_default(),
            event
                .stage
                .map(|value| format!(" stage={value}"))
                .unwrap_or_default(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_is_one_bounded_line_with_stable_fields() {
        let event = Event {
            timestamp_unix_ms: 1_800_000_000_123,
            event_code: "serve.started",
            severity: Severity::Info,
            role: "serve",
            operation: "startup",
            outcome: "ready",
            resource_kind: None,
            resource_id: None,
            desired_generation: Some(9),
            stage: Some("reconcile"),
        };
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains('\n'));
        assert!(!encoded.contains('\x1b'));
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded["event_code"], "serve.started");
        assert_eq!(decoded["desired_generation"], 9);
    }
}
