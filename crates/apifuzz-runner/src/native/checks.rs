//! Response validation checks (6-check pipeline)
//!
//! No I/O. Every check either produces a failure or
//! explicitly documents why it was skipped.

use std::collections::HashSet;

use apifuzz_core::schema::RawFailure;

use super::phases::FuzzPhase;
use super::spec::Operation;

/// Input for response validation checks — pure data, no I/O.
pub(super) struct CheckInput<'a> {
    pub(super) status_code: u16,
    pub(super) body_text: &'a str,
    pub(super) content_type: Option<&'a str>,
    pub(super) elapsed: f64,
    pub(super) url: &'a str,
    pub(super) operation_label: &'a str,
    pub(super) case_id: &'a str,
    pub(super) phase: FuzzPhase,
    pub(super) op: &'a Operation,
    pub(super) response_time_limit: Option<f64>,
    /// Dedup set for spec-gap warnings: "op_label:status:check_name"
    pub(super) seen_spec_gaps: &'a mut HashSet<String>,
}

/// Run all 6 response validation checks.
///
/// Spec-gap warnings are deduplicated via `seen_spec_gaps`.
pub(super) fn run_checks(input: &mut CheckInput) -> Vec<RawFailure> {
    let mut failures = Vec::new();
    let status = input.status_code;
    let is_success = (200..300).contains(&status);

    // ── Check 1: 5xx = server error (always critical) ──
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

    // ── Check 2: Status code conformance ──
    if !input.op.expected_statuses.is_empty()
        && !input.op.expected_statuses.contains(&status)
        && !(500..600).contains(&status)
    {
        failures.push(make_failure(
            "StatusCodeConformance",
            input.operation_label,
            "Undeclared status code",
            &format!(
                "{status} not in spec (declared: {:?})",
                input.op.expected_statuses
            ),
            input.case_id,
            "medium",
            Some(status),
        ));
    }

    // ── Check 3: Negative testing (type-confusion phase only) ──
    if input.phase == FuzzPhase::TypeConfusion && is_success {
        failures.push(make_failure(
            "NegativeTestAccepted",
            input.operation_label,
            "Invalid input accepted",
            &format!("Type-confused request returned {status} on {}", input.url),
            input.case_id,
            "medium",
            Some(status),
        ));
    }

    // ── Check 4: Response time threshold ──
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

    // ── Check 5: Response schema validation ──
    check_schema(input, &mut failures);

    // ── Check 6: Content-Type conformance ──
    check_content_type(input, &mut failures);

    failures
}

/// Check 5: Response body vs OpenAPI schema.
///
/// - Schema defined + non-empty → validate body
/// - Schema empty `{}` + 2xx → Warn (spec gap, validation impossible)
/// - Schema undefined + 2xx + body present → Warn (spec gap)
fn check_schema(input: &mut CheckInput, failures: &mut Vec<RawFailure>) {
    let status = input.status_code;
    let is_success = (200..300).contains(&status);

    match input.op.response_schemas.get(&status) {
        Some(schema) if schema.as_object().is_some_and(|o| !o.is_empty()) => {
            // Schema exists and non-empty → validate
            if let Ok(body_val) = serde_json::from_str::<serde_json::Value>(input.body_text) {
                if let Ok(validator) = jsonschema::validator_for(schema) {
                    let errors: Vec<String> = validator
                        .iter_errors(&body_val)
                        .take(5)
                        .map(|e| e.to_string())
                        .collect();
                    if !errors.is_empty() {
                        let mut f = make_failure(
                            "SchemaViolation",
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
                // Non-JSON body when JSON schema exists
                failures.push(make_failure(
                    "SchemaViolation",
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
                    "SchemaViolation",
                    input.operation_label,
                    "Response schema is empty",
                    &format!("Status {status} has empty schema {{}}, response body not validated"),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        }
        None if is_success && !input.body_text.is_empty() => {
            // No schema defined for 2xx with body → spec gap (once per operation+status)
            let key = format!("{}:{status}:schema_missing", input.operation_label);
            if input.seen_spec_gaps.insert(key) {
                failures.push(make_failure(
                    "SchemaViolation",
                    input.operation_label,
                    "No response schema defined",
                    &format!(
                        "Status {status} has no response schema in spec, response body not validated"
                    ),
                    input.case_id,
                    "medium",
                    Some(status),
                ));
            }
        }
        _ => {}
    }
}

/// Check 6: Content-Type conformance.
///
/// - Types declared + match → OK
/// - Types declared + mismatch → ContentTypeMismatch
/// - Types declared + no header → ContentTypeMismatch (missing header)
/// - No types declared + 2xx → Warn (spec gap)
fn check_content_type(input: &mut CheckInput, failures: &mut Vec<RawFailure>) {
    let status = input.status_code;
    let is_success = (200..300).contains(&status);

    match input.op.response_content_types.get(&status) {
        Some(expected_types) if !expected_types.is_empty() => {
            match &input.content_type {
                Some(actual_ct) => {
                    let actual_media = actual_ct.split(';').next().unwrap_or("").trim();
                    if !expected_types.iter().any(|t| t == actual_media) {
                        failures.push(make_failure(
                            "ContentTypeMismatch",
                            input.operation_label,
                            "Unexpected Content-Type",
                            &format!(
                                "Got \"{actual_media}\", expected one of {:?}",
                                expected_types
                            ),
                            input.case_id,
                            "medium",
                            Some(status),
                        ));
                    }
                }
                None => {
                    // No Content-Type header but spec declares types
                    failures.push(make_failure(
                        "ContentTypeMismatch",
                        input.operation_label,
                        "Missing Content-Type header",
                        &format!(
                            "No Content-Type header, expected one of {:?}",
                            expected_types
                        ),
                        input.case_id,
                        "medium",
                        Some(status),
                    ));
                }
            }
        }
        _ => {
            // No content types declared for this status (once per operation+status)
            if is_success {
                let key = format!("{}:{status}:ct_missing", input.operation_label);
                if input.seen_spec_gaps.insert(key) {
                    failures.push(make_failure(
                        "ContentTypeMismatch",
                        input.operation_label,
                        "No content types declared in spec",
                        &format!(
                            "Status {status} has no content types declared in spec, not validated"
                        ),
                        input.case_id,
                        "medium",
                        Some(status),
                    ));
                }
            }
        }
    }
}

/// Create a RawFailure with common fields. Reduces boilerplate.
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
