//! Conversion: Schemathesis raw types → Rust verdict types
//!
//! All classification logic lives here.
//! Python just dumps; Rust decides severity, failure type, and verdict.

use std::collections::HashMap;

use crate::schema::{RawFailure, RawInteraction, SchemathesisOutput};
use crate::verdict::{Failure, FailureType, RequestSnapshot, ResponseSnapshot, Severity};

/// Convert Schemathesis output to classified failures.
///
/// Joins `RawFailure` with `RawInteraction` data (by case_id)
/// to produce fully classified `Failure` values with request/response snapshots.
#[must_use]
pub fn classify_failures(output: &SchemathesisOutput) -> Vec<Failure> {
    // Build lookup: case_id → interaction (for request/response data)
    let interaction_map: HashMap<&str, &RawInteraction> = output
        .interactions
        .iter()
        .filter_map(|i| i.case.id.as_deref().map(|id| (id, i)))
        .collect();

    output
        .failures
        .iter()
        .enumerate()
        .map(|(idx, raw)| convert_one(raw, idx, &interaction_map))
        .collect()
}

/// Convert a single `RawFailure` → `Failure`.
fn convert_one(
    raw: &RawFailure,
    idx: usize,
    interactions: &HashMap<&str, &RawInteraction>,
) -> Failure {
    let failure_type = classify_type(&raw.failure_type, raw.status_code);
    let severity = map_severity(&raw.severity, failure_type);

    // Parse operation "POST /api/users" → (method, path)
    let (method, path) = parse_operation(&raw.operation);

    let id = raw.case_id.clone().unwrap_or_else(|| format!("f{idx}"));

    // Look up interaction by case_id for request/response snapshots
    let interaction = raw
        .case_id
        .as_deref()
        .and_then(|cid| interactions.get(cid))
        .copied();

    let request = interaction
        .map(request_from_interaction)
        .unwrap_or_else(|| default_request(&method, &path));

    let response = interaction.map(response_from_interaction);

    let mut failure = Failure {
        id,
        method,
        path,
        status_code: raw
            .status_code
            .or_else(|| interaction.map(|i| i.response.status_code))
            .unwrap_or(0),
        expected_status: None,
        failure_type,
        severity,
        request,
        response,
        context: HashMap::new(),
    };

    add_context(&mut failure, raw);
    failure
}

/// Map Schemathesis failure type name → our `FailureType`.
fn classify_type(type_name: &str, status_code: Option<u16>) -> FailureType {
    match type_name {
        "ServerError" => FailureType::ServerError,
        "ResponseTimeExceeded" => FailureType::Timeout,
        "MalformedJson" | "SchemaViolation" => FailureType::SchemaViolation,
        "StatusCodeConformance" => FailureType::StatusCodeConformance,
        "NegativeTestAccepted" => FailureType::NegativeTestAccepted,
        "ContentTypeMismatch" => FailureType::ContentTypeMismatch,
        // Unknown types: fall back to status-code classification
        _ => status_code.map_or(FailureType::UnexpectedError, |sc| match sc {
            408 | 504 => FailureType::Timeout,
            500..=599 => FailureType::ServerError,
            401 | 403 => FailureType::AuthError,
            429 => FailureType::RateLimit,
            _ => FailureType::UnexpectedError,
        }),
    }
}

/// Map Schemathesis severity string → our `Severity`.
///
/// Schemathesis: critical / high / medium / low
/// Ours:         Critical / Error / Warning / Info
fn map_severity(raw_severity: &str, failure_type: FailureType) -> Severity {
    match raw_severity {
        "critical" => Severity::Critical,
        "high" => Severity::Error,
        "medium" => Severity::Warning,
        "low" => Severity::Info,
        // Unknown: use type-based default
        _ => failure_type.default_severity(),
    }
}

/// Parse "POST /api/users" → ("POST", "/api/users")
fn parse_operation(operation: &str) -> (String, String) {
    operation
        .split_once(' ')
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .unwrap_or_else(|| ("UNKNOWN".to_string(), operation.to_string()))
}

fn default_request(method: &str, path: &str) -> RequestSnapshot {
    RequestSnapshot {
        method: method.to_string(),
        url: path.to_string(),
        headers: HashMap::new(),
        body: None,
    }
}

fn request_from_interaction(interaction: &RawInteraction) -> RequestSnapshot {
    let case = &interaction.case;

    let headers = case.headers.clone().unwrap_or_default();

    let body = case.body.as_ref().map(|b| {
        if b.is_string() {
            b.as_str().unwrap_or_default().to_string()
        } else {
            serde_json::to_string(b).unwrap_or_default()
        }
    });

    // Build URL from path + path_parameters
    let mut url = case.path.clone();
    if let Some(ref params) = case.path_parameters {
        for (key, val) in params {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            url = url.replace(&format!("{{{key}}}"), &val_str);
        }
    }

    RequestSnapshot {
        method: case.method.clone(),
        url,
        headers,
        body,
    }
}

fn response_from_interaction(interaction: &RawInteraction) -> ResponseSnapshot {
    let resp = &interaction.response;
    ResponseSnapshot {
        status_code: resp.status_code,
        headers: HashMap::new(),
        body: resp.body.clone(),
        latency_ms: (resp.elapsed * 1000.0).max(0.0) as u64,
    }
}

/// Add Schemathesis-specific context to failure.
fn add_context(failure: &mut Failure, raw: &RawFailure) {
    failure
        .context
        .insert("schemathesis_type".to_string(), raw.failure_type.clone());
    failure
        .context
        .insert("title".to_string(), raw.title.clone());

    if !raw.message.is_empty() {
        failure
            .context
            .insert("message".to_string(), raw.message.clone());
    }

    // ResponseTimeExceeded specific
    if let Some(elapsed) = raw.elapsed {
        failure
            .context
            .insert("elapsed_s".to_string(), format!("{elapsed:.3}"));
    }
    if let Some(deadline) = raw.deadline {
        failure
            .context
            .insert("deadline_s".to_string(), format!("{deadline:.3}"));
    }

    // MalformedJson specific
    if let Some(ref msg) = raw.validation_message {
        failure
            .context
            .insert("validation_message".to_string(), msg.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{RawCase, RawResponse};

    fn server_error_failure() -> RawFailure {
        RawFailure {
            failure_type: "ServerError".to_string(),
            operation: "POST /api/users".to_string(),
            title: "Server error".to_string(),
            message: "500 Internal Server Error".to_string(),
            case_id: Some("case1".to_string()),
            severity: "critical".to_string(),
            status_code: Some(500),
            elapsed: None,
            deadline: None,
            validation_message: None,
            document: None,
            position: None,
            lineno: None,
            colno: None,
        }
    }

    fn timeout_failure() -> RawFailure {
        RawFailure {
            failure_type: "ResponseTimeExceeded".to_string(),
            operation: "GET /health".to_string(),
            title: "Response time limit exceeded".to_string(),
            message: "Took 5.2s, limit 1.0s".to_string(),
            case_id: None,
            severity: "medium".to_string(),
            status_code: None,
            elapsed: Some(5.2),
            deadline: Some(1.0),
            validation_message: None,
            document: None,
            position: None,
            lineno: None,
            colno: None,
        }
    }

    fn malformed_json_failure() -> RawFailure {
        RawFailure {
            failure_type: "MalformedJson".to_string(),
            operation: "GET /api/data".to_string(),
            title: "Malformed JSON".to_string(),
            message: "Invalid JSON response".to_string(),
            case_id: Some("case2".to_string()),
            severity: "high".to_string(),
            status_code: Some(200),
            elapsed: None,
            deadline: None,
            validation_message: Some("Expecting value".to_string()),
            document: Some("{bad}".to_string()),
            position: Some(1),
            lineno: Some(1),
            colno: Some(2),
        }
    }

    fn sample_interaction(case_id: &str) -> RawInteraction {
        RawInteraction {
            case: RawCase {
                method: "POST".to_string(),
                path: "/api/users".to_string(),
                id: Some(case_id.to_string()),
                path_parameters: None,
                headers: Some(HashMap::from([(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )])),
                query: None,
                body: Some(serde_json::json!({"name": "test"})),
                media_type: Some("application/json".to_string()),
            },
            response: RawResponse {
                status_code: 500,
                elapsed: 0.123,
                message: "Internal Server Error".to_string(),
                content_length: 42,
                body: Some("Internal Server Error".to_string()),
            },
            operation: "POST /api/users".to_string(),
            failures: vec![],
        }
    }

    #[test]
    fn classify_server_error() {
        assert_eq!(
            classify_type("ServerError", Some(500)),
            FailureType::ServerError
        );
    }

    #[test]
    fn classify_timeout() {
        assert_eq!(
            classify_type("ResponseTimeExceeded", None),
            FailureType::Timeout
        );
    }

    #[test]
    fn classify_malformed_json() {
        assert_eq!(
            classify_type("MalformedJson", Some(200)),
            FailureType::SchemaViolation
        );
    }

    #[test]
    fn classify_unknown_falls_back_to_status() {
        assert_eq!(
            classify_type("CustomFailure", Some(502)),
            FailureType::ServerError
        );
        assert_eq!(
            classify_type("CustomFailure", Some(401)),
            FailureType::AuthError
        );
        assert_eq!(
            classify_type("CustomFailure", None),
            FailureType::UnexpectedError
        );
    }

    #[test]
    fn map_severity_critical() {
        assert_eq!(
            map_severity("critical", FailureType::ServerError),
            Severity::Critical
        );
    }

    #[test]
    fn map_severity_high_to_error() {
        assert_eq!(
            map_severity("high", FailureType::ServerError),
            Severity::Error
        );
    }

    #[test]
    fn map_severity_medium_to_warning() {
        assert_eq!(
            map_severity("medium", FailureType::Timeout),
            Severity::Warning
        );
    }

    #[test]
    fn map_severity_low_to_info() {
        assert_eq!(
            map_severity("low", FailureType::ServerError),
            Severity::Info
        );
    }

    #[test]
    fn map_severity_unknown_uses_type_default() {
        assert_eq!(
            map_severity("unknown", FailureType::ServerError),
            Severity::Critical
        );
        assert_eq!(
            map_severity("", FailureType::SchemaViolation),
            Severity::Warning
        );
    }

    #[test]
    fn parse_operation_normal() {
        let (m, p) = parse_operation("POST /api/users");
        assert_eq!(m, "POST");
        assert_eq!(p, "/api/users");
    }

    #[test]
    fn parse_operation_no_space() {
        let (m, p) = parse_operation("unknown");
        assert_eq!(m, "UNKNOWN");
        assert_eq!(p, "unknown");
    }

    #[test]
    fn convert_server_error_without_interaction() {
        let output = SchemathesisOutput {
            total: 100,
            success: 99,
            failure_count: 1,
            failures: vec![server_error_failure()],
            interactions: vec![],
            errors: vec![],
        };

        let failures = classify_failures(&output);
        assert_eq!(failures.len(), 1);

        let f = &failures[0];
        assert_eq!(f.failure_type, FailureType::ServerError);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.method, "POST");
        assert_eq!(f.path, "/api/users");
        assert_eq!(f.status_code, 500);
        assert_eq!(f.id, "case1");
    }

    #[test]
    fn convert_server_error_with_interaction() {
        let output = SchemathesisOutput {
            total: 100,
            success: 99,
            failure_count: 1,
            failures: vec![server_error_failure()],
            interactions: vec![sample_interaction("case1")],
            errors: vec![],
        };

        let failures = classify_failures(&output);
        assert_eq!(failures.len(), 1);

        let f = &failures[0];
        assert_eq!(f.request.method, "POST");
        assert!(f.request.headers.contains_key("Content-Type"));
        assert!(f.request.body.is_some());
        assert!(f.response.is_some());

        let resp = f.response.as_ref().unwrap();
        assert_eq!(resp.status_code, 500);
        assert_eq!(resp.latency_ms, 123);
    }

    #[test]
    fn convert_timeout_failure() {
        let output = SchemathesisOutput {
            total: 50,
            success: 49,
            failure_count: 1,
            failures: vec![timeout_failure()],
            interactions: vec![],
            errors: vec![],
        };

        let failures = classify_failures(&output);
        let f = &failures[0];

        assert_eq!(f.failure_type, FailureType::Timeout);
        assert_eq!(f.severity, Severity::Warning); // medium → Warning
        assert_eq!(f.method, "GET");
        assert_eq!(f.path, "/health");
        assert_eq!(f.context.get("elapsed_s"), Some(&"5.200".to_string()));
        assert_eq!(f.context.get("deadline_s"), Some(&"1.000".to_string()));
        // No case_id → auto-generated ID
        assert_eq!(f.id, "f0");
    }

    #[test]
    fn convert_malformed_json_failure() {
        let output = SchemathesisOutput {
            total: 10,
            success: 9,
            failure_count: 1,
            failures: vec![malformed_json_failure()],
            interactions: vec![],
            errors: vec![],
        };

        let failures = classify_failures(&output);
        let f = &failures[0];

        assert_eq!(f.failure_type, FailureType::SchemaViolation);
        assert_eq!(f.severity, Severity::Error); // high → Error
        assert_eq!(
            f.context.get("validation_message"),
            Some(&"Expecting value".to_string())
        );
    }

    #[test]
    fn convert_multiple_failures() {
        let output = SchemathesisOutput {
            total: 200,
            success: 197,
            failure_count: 3,
            failures: vec![
                server_error_failure(),
                timeout_failure(),
                malformed_json_failure(),
            ],
            interactions: vec![sample_interaction("case1")],
            errors: vec![],
        };

        let failures = classify_failures(&output);
        assert_eq!(failures.len(), 3);

        // Server error with interaction
        assert_eq!(failures[0].failure_type, FailureType::ServerError);
        assert!(failures[0].response.is_some());

        // Timeout without interaction
        assert_eq!(failures[1].failure_type, FailureType::Timeout);
        assert!(failures[1].response.is_none());

        // MalformedJson without matching interaction
        assert_eq!(failures[2].failure_type, FailureType::SchemaViolation);
    }

    #[test]
    fn empty_output_produces_no_failures() {
        let output = SchemathesisOutput {
            total: 100,
            success: 100,
            failure_count: 0,
            failures: vec![],
            interactions: vec![],
            errors: vec![],
        };

        assert!(classify_failures(&output).is_empty());
    }
}
