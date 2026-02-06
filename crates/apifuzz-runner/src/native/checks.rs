//! Response validation checks
//!
//! Two categories:
//!
//! **Health checks** (phase-independent):
//! - ServerError: 5xx always critical
//! - ResponseTimeExceeded: over configured limit
//!
//! **Expectation checks** (spec + phase derived):
//! - StatusSatisfyExpectation: actual status vs phase-aware expectation
//! - HeaderSatisfyExpectation: Content-Type + declared response headers
//! - BodySatisfyExpectation: MIME compliance + jsonschema + encoding

use std::collections::HashSet;

use apifuzz_core::schema::RawFailure;

use super::phases::StatusExpectation;
use super::spec::Operation;

/// Input for response validation checks — pure data, no I/O.
pub(super) struct CheckInput<'a> {
    pub(super) status_code: u16,
    pub(super) body_text: &'a str,
    pub(super) content_type: Option<&'a str>,
    pub(super) response_headers: &'a reqwest::header::HeaderMap,
    pub(super) elapsed: f64,
    pub(super) url: &'a str,
    pub(super) operation_label: &'a str,
    pub(super) case_id: &'a str,
    pub(super) expectation: &'a StatusExpectation,
    pub(super) op: &'a Operation,
    pub(super) response_time_limit: Option<f64>,
    /// Dedup set for spec-gap warnings: "op_label:status:check_name"
    pub(super) seen_spec_gaps: &'a mut HashSet<String>,
}

/// Run all response validation checks.
///
/// Spec-gap warnings are deduplicated via `seen_spec_gaps`.
pub(super) fn run_checks(input: &mut CheckInput) -> Vec<RawFailure> {
    let mut failures = Vec::new();
    let status = input.status_code;

    // ── Health Check: ServerError (5xx, always critical) ──
    if (500..600).contains(&status) {
        failures.push(make_failure(
            "ServerError",
            input.operation_label,
            "Server error",
            &format!("{status} on {}", input.url),
            input.case_id,
            "critical",
            Some(status),
        ));
    }

    // ── Health Check: Response time threshold ──
    if let Some(limit) = input.response_time_limit {
        if input.elapsed > limit {
            let mut f = make_failure(
                "ResponseTimeExceeded",
                input.operation_label,
                "Response time limit exceeded",
                &format!("{:.3}s > {:.3}s on {}", input.elapsed, limit, input.url),
                input.case_id,
                "medium",
                Some(status),
            );
            f.elapsed = Some(input.elapsed);
            f.deadline = Some(limit);
            failures.push(f);
        }
    }

    // ── Expectation Check: Status ──
    check_status_expectation(input, &mut failures);

    // ── Expectation Check: Headers ──
    check_header_expectation(input, &mut failures);

    // ── Expectation Check: Body ──
    check_body_expectation(input, &mut failures);

    failures
}

/// Check actual status code against the phase-derived expectation.
///
/// Replaces old Check 2 (StatusCodeConformance) + Check 3 (NegativeTestAccepted).
fn check_status_expectation(input: &mut CheckInput, failures: &mut Vec<RawFailure>) {
    let status = input.status_code;

    // 5xx is always handled by the ServerError health check — don't double-report
    if (500..600).contains(&status) {
        return;
    }

    match input.expectation {
        StatusExpectation::SuccessExpected(expected) => {
            // Valid input → expect 2xx (spec-declared success codes)
            if !expected.contains(&status) {
                let is_2xx = (200..300).contains(&status);
                if is_2xx {
                    // Got a different 2xx than declared (e.g. 201 when only 200 declared)
                    // Still a conformance issue but lower severity
                    failures.push(make_failure(
                        "StatusSatisfyExpectation",
                        input.operation_label,
                        "Unexpected success status code",
                        &format!(
                            "Got {status}, expected one of {expected:?} \
                             (valid input should return declared success code)"
                        ),
                        input.case_id,
                        "medium",
                        Some(status),
                    ));
                } else {
                    // Got non-2xx for valid input — server rejected valid request
                    failures.push(make_failure(
                        "StatusSatisfyExpectation",
                        input.operation_label,
                        "Valid input rejected",
                        &format!(
                            "Got {status}, expected one of {expected:?} \
                             (spec-compliant input was rejected)"
                        ),
                        input.case_id,
                        "high",
                        Some(status),
                    ));
                }
            }
        }
        StatusExpectation::AnyDeclared(declared) => {
            // Edge/unknown input → any declared status is acceptable
            if !declared.contains(&status) {
                failures.push(make_failure(
                    "StatusSatisfyExpectation",
                    input.operation_label,
                    "Undeclared status code",
                    &format!("Got {status}, not in declared statuses {declared:?}"),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        }
        StatusExpectation::Rejection => {
            // Invalid input → must be rejected with 4xx
            if (200..300).contains(&status) {
                failures.push(make_failure(
                    "StatusSatisfyExpectation",
                    input.operation_label,
                    "Invalid input accepted",
                    &format!(
                        "Type-confused request returned {status} on {} \
                         (expected 4xx rejection)",
                        input.url
                    ),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        }
    }
}

/// Check response headers against OpenAPI spec expectations.
///
/// - Content-Type matches declared media types for this status
/// - Required response headers are present
/// - Header values match declared schemas (if available)
fn check_header_expectation(input: &mut CheckInput, failures: &mut Vec<RawFailure>) {
    let status = input.status_code;
    let is_success = (200..300).contains(&status);

    // ── Content-Type check ──
    match input.op.response_content_types.get(&status) {
        Some(expected_types) if !expected_types.is_empty() => match &input.content_type {
            Some(actual_ct) => {
                let actual_media = actual_ct.split(';').next().unwrap_or("").trim();
                if !expected_types.iter().any(|t| t == actual_media) {
                    failures.push(make_failure(
                        "HeaderSatisfyExpectation",
                        input.operation_label,
                        "Unexpected Content-Type",
                        &format!("Got \"{actual_media}\", expected one of {expected_types:?}"),
                        input.case_id,
                        "medium",
                        Some(status),
                    ));
                }
            }
            None => {
                failures.push(make_failure(
                    "HeaderSatisfyExpectation",
                    input.operation_label,
                    "Missing Content-Type header",
                    &format!("No Content-Type header, expected one of {expected_types:?}"),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        },
        _ => {
            // No content types declared for this status → spec gap
            if is_success {
                let key = format!("{}:{status}:ct_missing", input.operation_label);
                if input.seen_spec_gaps.insert(key) {
                    failures.push(make_failure(
                        "HeaderSatisfyExpectation",
                        input.operation_label,
                        "No content types declared in spec",
                        &format!(
                            "Status {status} has no content types declared in spec, not validated"
                        ),
                        input.case_id,
                        "low",
                        Some(status),
                    ));
                }
            }
        }
    }

    // ── Response headers declared in spec ──
    if let Some(expected_headers) = input.op.response_headers.get(&status) {
        for hdr in expected_headers {
            let actual_value = input
                .response_headers
                .get(&hdr.name)
                .and_then(|v| v.to_str().ok());

            // Required header must be present
            if hdr.required && actual_value.is_none() {
                failures.push(make_failure(
                    "HeaderSatisfyExpectation",
                    input.operation_label,
                    "Required response header missing",
                    &format!(
                        "Header '{}' is required for status {status} but not present",
                        hdr.name
                    ),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
                continue;
            }

            // Schema validation for header value (if schema declared and header present)
            if let (Some(value_str), Some(schema)) = (actual_value, &hdr.schema) {
                validate_header_value(
                    input.operation_label,
                    input.case_id,
                    status,
                    &hdr.name,
                    value_str,
                    schema,
                    failures,
                );
            }
        }
    }
}

/// Validate a response header value against its declared JSON Schema.
fn validate_header_value(
    operation_label: &str,
    case_id: &str,
    status: u16,
    header_name: &str,
    value_str: &str,
    schema: &serde_json::Value,
    failures: &mut Vec<RawFailure>,
) {
    let type_str = schema.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let coerced: Option<serde_json::Value> = match type_str {
        "integer" => value_str.parse::<i64>().ok().map(|n| serde_json::json!(n)),
        "number" => value_str.parse::<f64>().ok().map(|n| serde_json::json!(n)),
        "boolean" => match value_str {
            "true" => Some(serde_json::json!(true)),
            "false" => Some(serde_json::json!(false)),
            _ => None,
        },
        "string" | "" => Some(serde_json::json!(value_str)),
        _ => Some(serde_json::json!(value_str)),
    };

    let Some(val) = coerced else {
        failures.push(make_failure(
            "HeaderSatisfyExpectation",
            operation_label,
            "Response header type mismatch",
            &format!("Header '{header_name}' value \"{value_str}\" cannot be parsed as {type_str}"),
            case_id,
            "medium",
            Some(status),
        ));
        return;
    };

    if let Ok(validator) = jsonschema::validator_for(schema) {
        let errors: Vec<String> = validator
            .iter_errors(&val)
            .take(3)
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
            failures.push(make_failure(
                "HeaderSatisfyExpectation",
                operation_label,
                "Response header schema violation",
                &format!(
                    "Header '{header_name}' value \"{value_str}\": {}",
                    errors.join("; ")
                ),
                case_id,
                "medium",
                Some(status),
            ));
        }
    }
}

/// Check response body against OpenAPI spec expectations.
///
/// - MIME type compliance: if Content-Type says JSON, body must be valid JSON
/// - JSON Schema validation: required fields, types, enums, nested structure
/// - Spec gap detection: missing schema for 2xx responses
fn check_body_expectation(input: &mut CheckInput, failures: &mut Vec<RawFailure>) {
    let status = input.status_code;
    let is_success = (200..300).contains(&status);

    // ── MIME compliance: Content-Type declares JSON → body must be valid JSON ──
    if let Some(ct) = input.content_type {
        let media = ct.split(';').next().unwrap_or("").trim();
        if media == "application/json"
            && !input.body_text.is_empty()
            && serde_json::from_str::<serde_json::Value>(input.body_text).is_err()
        {
            failures.push(make_failure(
                "BodySatisfyExpectation",
                input.operation_label,
                "Response body is not valid JSON",
                &format!(
                    "Content-Type is application/json but body is not valid JSON: {}",
                    &input.body_text[..input.body_text.len().min(200)]
                ),
                input.case_id,
                "high",
                Some(status),
            ));
            // Can't do schema validation if JSON is invalid
            return;
        }
    }

    // ── JSON Schema validation ──
    match input.op.response_schemas.get(&status) {
        Some(schema) if schema.as_object().is_some_and(|o| !o.is_empty()) => {
            // Schema exists and non-empty → validate body
            if let Ok(body_val) = serde_json::from_str::<serde_json::Value>(input.body_text) {
                if let Ok(validator) = jsonschema::validator_for(schema) {
                    let errors: Vec<String> = validator
                        .iter_errors(&body_val)
                        .take(5)
                        .map(|e| e.to_string())
                        .collect();
                    if !errors.is_empty() {
                        let mut f = make_failure(
                            "BodySatisfyExpectation",
                            input.operation_label,
                            "Response body does not match schema",
                            &errors.join("; "),
                            input.case_id,
                            "medium",
                            Some(status),
                        );
                        f.validation_message = Some(errors.join("; "));
                        failures.push(f);
                    }
                }
            } else if !input.body_text.is_empty() {
                // Non-JSON body when JSON schema exists (MIME check may not have caught it
                // if Content-Type was wrong/missing)
                failures.push(make_failure(
                    "BodySatisfyExpectation",
                    input.operation_label,
                    "Response body is not valid JSON",
                    &format!(
                        "Expected JSON matching schema, got: {}",
                        &input.body_text[..input.body_text.len().min(200)]
                    ),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        }
        Some(_) if is_success => {
            // Empty schema {} for 2xx → spec gap (once per operation+status)
            let key = format!("{}:{status}:schema_empty", input.operation_label);
            if input.seen_spec_gaps.insert(key) {
                failures.push(make_failure(
                    "BodySatisfyExpectation",
                    input.operation_label,
                    "Response schema is empty",
                    &format!("Status {status} has empty schema {{}}, response body not validated"),
                    input.case_id,
                    "low",
                    Some(status),
                ));
            }
        }
        None if is_success && !input.body_text.is_empty() => {
            // No schema defined for 2xx with body → spec gap (once per operation+status)
            let key = format!("{}:{status}:schema_missing", input.operation_label);
            if input.seen_spec_gaps.insert(key) {
                failures.push(make_failure(
                    "BodySatisfyExpectation",
                    input.operation_label,
                    "No response schema defined",
                    &format!(
                        "Status {status} has no response schema in spec, \
                         response body not validated"
                    ),
                    input.case_id,
                    "low",
                    Some(status),
                ));
            }
        }
        _ => {}
    }
}

/// Create a RawFailure with common fields.
fn make_failure(
    failure_type: &str,
    operation: &str,
    title: &str,
    message: &str,
    case_id: &str,
    severity: &str,
    status_code: Option<u16>,
) -> RawFailure {
    RawFailure {
        failure_type: failure_type.to_string(),
        operation: operation.to_string(),
        title: title.to_string(),
        message: message.to_string(),
        case_id: Some(case_id.to_string()),
        severity: severity.to_string(),
        status_code,
        elapsed: None,
        deadline: None,
        validation_message: None,
        document: None,
        position: None,
        lineno: None,
        colno: None,
    }
}
