//! Pure Rust API fuzzer — no Python dependency
//!
//! Parses OpenAPI spec with serde_json, generates requests with datagen,
//! sends with reqwest, checks responses.

mod checks;
mod phases;
mod spec;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use apifuzz_core::schema::{RawCase, RawFailure, RawInteraction, RawResponse, SchemathesisOutput};
use apifuzz_core::{Config, Probe};

use crate::datagen;

use checks::CheckInput;
use checks::run_checks;
use phases::{
    FuzzPhase, Overrides, StatusExpectation, collect_boundary_cases, collect_probe_cases,
    collect_type_confusion_cases, generate_neighborhood_case,
};
use spec::{Operation, ParamLocation, extract_operations};

/// Fuzz intensity level
#[derive(Debug, Clone, Copy, Default)]
pub enum FuzzLevel {
    /// 100 examples
    Quick,
    /// 1000 examples
    #[default]
    Normal,
    /// 5000 examples
    Heavy,
}

impl FuzzLevel {
    #[must_use]
    pub const fn max_examples(self) -> u32 {
        match self {
            Self::Quick => 100,
            Self::Normal => 1000,
            Self::Heavy => 5000,
        }
    }
}

/// Accumulates fuzz results across all operations and phases.
struct FuzzAccumulator {
    total: u64,
    success: u64,
    failures: Vec<RawFailure>,
    interactions: Vec<RawInteraction>,
    errors: Vec<String>,
    seen_spec_gaps: HashSet<String>,
}

impl FuzzAccumulator {
    fn new() -> Self {
        Self {
            total: 0,
            success: 0,
            failures: Vec::new(),
            interactions: Vec::new(),
            errors: Vec::new(),
            seen_spec_gaps: HashSet::new(),
        }
    }

    /// Record one execution result. Returns `true` if the request had failures.
    fn record(
        &mut self,
        result: Result<(RawInteraction, Vec<RawFailure>), String>,
        op_label: &str,
        phase_label: &str,
    ) -> bool {
        self.total += 1;
        match result {
            Ok((interaction, failures)) => {
                let failed = !failures.is_empty();
                if !failed {
                    self.success += 1;
                }
                self.failures.extend(failures);
                self.interactions.push(interaction);
                failed
            }
            Err(e) => {
                self.errors.push(format!("{op_label}: {phase_label}: {e}"));
                false
            }
        }
    }

    fn into_output(self) -> SchemathesisOutput {
        SchemathesisOutput {
            total: self.total,
            success: self.success,
            failure_count: u64::try_from(self.failures.len()).unwrap_or(u64::MAX),
            failures: self.failures,
            interactions: self.interactions,
            errors: self.errors,
        }
    }
}

/// Per-phase statistics for progress reporting.
#[derive(Default)]
struct PhaseStats {
    total: u32,
    fail: u32,
}

impl PhaseStats {
    fn record(&mut self, failed: bool) {
        self.total += 1;
        if failed {
            self.fail += 1;
        }
    }
}

/// Record one fuzz result, update phase stats and op counter,
/// and return whether `--stop-on-failure` was triggered.
fn record_and_check_stop(
    acc: &mut FuzzAccumulator,
    stats: &mut PhaseStats,
    result: Result<(RawInteraction, Vec<RawFailure>), String>,
    op_label: &str,
    phase_name: &str,
    op_count: &mut u32,
    stop_on_failure: bool,
) -> bool {
    let failed = acc.record(result, op_label, phase_name);
    stats.record(failed);
    *op_count += 1;
    stop_on_failure && failed
}

/// Pure Rust API fuzzer
pub struct NativeRunner {
    spec_path: PathBuf,
    base_url: String,
    headers: HashMap<String, String>,
    path_params: HashMap<String, String>,
    probes: Vec<Probe>,
    response_time_limit: Option<f64>,
    level: FuzzLevel,
    /// Override neighborhood+random count (takes precedence over level)
    examples: Option<u32>,
    /// Stop on first failure detection
    stop_on_failure: bool,
    /// Per-operation request limit (across all phases)
    limit: Option<u32>,
}

impl NativeRunner {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            spec_path: config.spec.clone(),
            base_url: config.base_url.clone(),
            headers: config.headers.clone(),
            path_params: config.path_params.clone(),
            probes: config.probes.clone(),
            response_time_limit: config.response_time_limit,
            level: FuzzLevel::default(),
            examples: None,
            stop_on_failure: false,
            limit: None,
        }
    }

    #[must_use]
    pub fn with_level(mut self, level: FuzzLevel) -> Self {
        self.level = level;
        self
    }

    #[must_use]
    pub fn with_examples(mut self, examples: Option<u32>) -> Self {
        self.examples = examples;
        self
    }

    #[must_use]
    pub fn with_stop_on_failure(mut self, stop: bool) -> Self {
        self.stop_on_failure = stop;
        self
    }

    #[must_use]
    pub fn with_limit(mut self, limit: Option<u32>) -> Self {
        self.limit = limit;
        self
    }

    /// Generate a dry run plan: parse spec, count phases, validate config.
    /// No HTTP requests are sent.
    ///
    /// # Errors
    ///
    /// Returns error if spec cannot be read or parsed.
    pub fn plan(
        &self,
        config: &apifuzz_core::Config,
    ) -> Result<apifuzz_core::dryrun::DryRunPlan, NativeError> {
        use apifuzz_core::dryrun::{
            DryRunPlan, MatchedProbe, OperationPlan, PhaseCounts, Validation, ValidationStatus,
        };

        let spec_content = std::fs::read_to_string(&self.spec_path)
            .map_err(|e| NativeError::Io(format!("{}: {e}", self.spec_path.display())))?;
        let spec: serde_json::Value = parse_spec(&self.spec_path, &spec_content)?;

        let components = spec
            .get("components")
            .and_then(|c| c.get("schemas"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let operations = extract_operations(&spec);

        let max_examples = self.examples.unwrap_or_else(|| self.level.max_examples());
        let neighborhood_count = max_examples / 3;
        let random_count = max_examples - neighborhood_count;

        let mut op_plans = Vec::new();
        let mut total_requests: u64 = 0;

        for op in &operations {
            let probe_cases = collect_probe_cases(op, &self.probes);
            let boundary_cases = collect_boundary_cases(op, &components);
            let tc_cases = collect_type_confusion_cases(op, &components);

            let probe_count = u32::try_from(probe_cases.len()).unwrap_or(u32::MAX);
            let boundary_count = u32::try_from(boundary_cases.len()).unwrap_or(u32::MAX);
            let tc_count = u32::try_from(tc_cases.len()).unwrap_or(u32::MAX);
            let op_total =
                probe_count + boundary_count + tc_count + neighborhood_count + random_count;

            total_requests += u64::from(op_total);

            // Parameter names
            let parameters: Vec<String> = op.parameters.iter().map(|p| p.name.clone()).collect();

            // Body property names
            let body_properties: Vec<String> = op
                .request_body_schema
                .as_ref()
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.as_object())
                .map(|props| props.keys().cloned().collect())
                .unwrap_or_default();

            // Matched probes
            let matched_probes: Vec<MatchedProbe> = self
                .probes
                .iter()
                .filter(|p| p.matches_operation(&op.method, &op.path))
                .map(|p| MatchedProbe {
                    target: p.target.clone(),
                    values: p.to_json_values(),
                })
                .collect();

            op_plans.push(OperationPlan {
                operation: format!("{} {}", op.method, op.path),
                method: op.method.clone(),
                path: op.path.clone(),
                total: op_total,
                phases: PhaseCounts {
                    probe: probe_count,
                    boundary: boundary_count,
                    type_confusion: tc_count,
                    neighborhood: neighborhood_count,
                    random: random_count,
                },
                parameters,
                body_properties,
                matched_probes,
            });
        }

        // Config validation
        let mut validations = apifuzz_core::dryrun::validate_config(config);

        // Spec parse result
        validations.push(Validation {
            check: "spec_parse".into(),
            status: if operations.is_empty() {
                ValidationStatus::Error
            } else {
                ValidationStatus::Ok
            },
            message: format!("spec parsed: {} operations found", operations.len()),
        });

        // Probe → operation matching validation
        for probe in &self.probes {
            let matched = operations
                .iter()
                .any(|op| probe.matches_operation(&op.method, &op.path));
            if !matched {
                validations.push(Validation {
                    check: "probe_match".into(),
                    status: ValidationStatus::Warning,
                    message: format!(
                        "probe '{}' target '{}' does not match any operation in spec",
                        probe.operation, probe.target
                    ),
                });
            }
        }

        Ok(DryRunPlan {
            operations: op_plans,
            total_requests,
            validations,
        })
    }

    /// Run the fuzzer. Returns output compatible with existing verdict pipeline.
    ///
    /// # Errors
    ///
    /// Returns error if spec cannot be read/parsed or HTTP client fails to build.
    pub fn run(&self) -> Result<SchemathesisOutput, NativeError> {
        let spec_content = std::fs::read_to_string(&self.spec_path)
            .map_err(|e| NativeError::Io(format!("{}: {e}", self.spec_path.display())))?;
        let spec: serde_json::Value = parse_spec(&self.spec_path, &spec_content)?;

        let components = spec
            .get("components")
            .and_then(|c| c.get("schemas"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let operations = extract_operations(&spec);

        if operations.is_empty() {
            return Err(NativeError::Parse(
                "No operations found in OpenAPI spec".into(),
            ));
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| NativeError::Http(e.to_string()))?;

        let mut rng = SmallRng::from_entropy();
        let max_examples = self.examples.unwrap_or_else(|| self.level.max_examples());
        let mut acc = FuzzAccumulator::new();

        let neighborhood_count = max_examples / 3;
        let random_count = max_examples - neighborhood_count;

        let probe_count: usize = self.probes.len();
        eprintln!(
            "Fuzzing {} operations ({} probes + boundary + type-confusion + {} near + {} rand)...",
            operations.len(),
            probe_count,
            neighborhood_count,
            random_count
        );

        let mut stopped_early = false;

        'ops: for op in &operations {
            let op_label = format!("{} {}", op.method, op.path);
            let mut op_count: u32 = 0;

            // Phase 0: Custom probes (user-defined known-bug patterns)
            let probe_cases = collect_probe_cases(op, &self.probes);
            let mut pr = PhaseStats::default();
            for case in &probe_cases {
                if self.limit.is_some_and(|l| op_count >= l) {
                    break;
                }
                let r = self.execute_one(
                    &client,
                    op,
                    &components,
                    &mut rng,
                    Some(&case.overrides),
                    &case.expectation,
                    &mut acc.seen_spec_gaps,
                );
                if record_and_check_stop(
                    &mut acc,
                    &mut pr,
                    r,
                    &op_label,
                    "probe",
                    &mut op_count,
                    self.stop_on_failure,
                ) {
                    stopped_early = true;
                    break 'ops;
                }
            }

            // Phase 1: Fixed boundary (deterministic)
            let boundary_cases = collect_boundary_cases(op, &components);
            let mut p1 = PhaseStats::default();
            for case in &boundary_cases {
                if self.limit.is_some_and(|l| op_count >= l) {
                    break;
                }
                let r = self.execute_one(
                    &client,
                    op,
                    &components,
                    &mut rng,
                    Some(&case.overrides),
                    &case.expectation,
                    &mut acc.seen_spec_gaps,
                );
                if record_and_check_stop(
                    &mut acc,
                    &mut p1,
                    r,
                    &op_label,
                    "boundary",
                    &mut op_count,
                    self.stop_on_failure,
                ) {
                    stopped_early = true;
                    break 'ops;
                }
            }

            // Phase 1b: Type confusion (deterministic)
            let tc_cases = collect_type_confusion_cases(op, &components);
            let mut tc = PhaseStats::default();
            for case in &tc_cases {
                if self.limit.is_some_and(|l| op_count >= l) {
                    break;
                }
                let r = self.execute_one(
                    &client,
                    op,
                    &components,
                    &mut rng,
                    Some(&case.overrides),
                    &case.expectation,
                    &mut acc.seen_spec_gaps,
                );
                if record_and_check_stop(
                    &mut acc,
                    &mut tc,
                    r,
                    &op_label,
                    "type-confusion",
                    &mut op_count,
                    self.stop_on_failure,
                ) {
                    stopped_early = true;
                    break 'ops;
                }
            }

            // Phase 2: Boundary neighborhood random
            let mut p2 = PhaseStats::default();
            for _ in 0..neighborhood_count {
                if self.limit.is_some_and(|l| op_count >= l) {
                    break;
                }
                let case = generate_neighborhood_case(op, &components, &mut rng);
                let ov = if case.overrides.params.is_empty() && case.overrides.body_props.is_empty()
                {
                    None
                } else {
                    Some(&case.overrides)
                };
                let r = self.execute_one(
                    &client,
                    op,
                    &components,
                    &mut rng,
                    ov,
                    &case.expectation,
                    &mut acc.seen_spec_gaps,
                );
                if record_and_check_stop(
                    &mut acc,
                    &mut p2,
                    r,
                    &op_label,
                    "neighborhood",
                    &mut op_count,
                    self.stop_on_failure,
                ) {
                    stopped_early = true;
                    break 'ops;
                }
            }

            // Phase 3: Full random (spec-compliant input → expect 2xx)
            let random_expectation = StatusExpectation::from_phase(op, FuzzPhase::Random);
            let mut p3 = PhaseStats::default();
            for _ in 0..random_count {
                if self.limit.is_some_and(|l| op_count >= l) {
                    break;
                }
                let r = self.execute_one(
                    &client,
                    op,
                    &components,
                    &mut rng,
                    None,
                    &random_expectation,
                    &mut acc.seen_spec_gaps,
                );
                if record_and_check_stop(
                    &mut acc,
                    &mut p3,
                    r,
                    &op_label,
                    "random",
                    &mut op_count,
                    self.stop_on_failure,
                ) {
                    stopped_early = true;
                    break 'ops;
                }
            }

            let total_fail = pr.fail + p1.fail + tc.fail + p2.fail + p3.fail;
            if total_fail > 0 {
                let probe_str = if pr.total > 0 {
                    format!("probe {}/{}, ", pr.fail, pr.total)
                } else {
                    String::new()
                };
                eprintln!(
                    "  {op_label}: {total_fail} failures ({probe_str}fixed {}/{}, type {}/{}, near {}/{}, rand {}/{})",
                    p1.fail, p1.total, tc.fail, tc.total, p2.fail, p2.total, p3.fail, p3.total
                );
            } else {
                let probe_str = if pr.total > 0 {
                    format!("{} probe + ", pr.total)
                } else {
                    String::new()
                };
                eprintln!(
                    "  {op_label}: OK ({probe_str}{} fixed + {} type + {} near + {} rand)",
                    p1.total, tc.total, p2.total, p3.total
                );
            }
        }

        if stopped_early {
            eprintln!("Stopped early: failure detected (--stop-on-failure)");
        }

        Ok(acc.into_output())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_one(
        &self,
        client: &reqwest::blocking::Client,
        op: &Operation,
        components: &serde_json::Value,
        rng: &mut impl Rng,
        overrides: Option<&Overrides>,
        expectation: &StatusExpectation,
        seen_spec_gaps: &mut HashSet<String>,
    ) -> Result<(RawInteraction, Vec<RawFailure>), String> {
        // Build URL with path parameters
        let mut url_path = op.path.clone();
        let mut path_params_resolved: HashMap<String, serde_json::Value> = HashMap::new();
        for param in &op.parameters {
            if param.location == ParamLocation::Path {
                let value = if let Some(ov) = overrides.and_then(|o| o.params.get(&param.name)) {
                    value_to_param_string(ov)
                } else {
                    self.path_params
                        .get(&param.name)
                        .cloned()
                        .unwrap_or_else(|| {
                            datagen::generate(&param.schema, components, rng)
                                .to_string()
                                .trim_matches('"')
                                .to_string()
                        })
                };
                url_path = url_path.replace(&format!("{{{}}}", param.name), &value);
                path_params_resolved.insert(param.name.clone(), serde_json::Value::String(value));
            }
        }
        let url = format!("{}{url_path}", self.base_url);

        // Query parameters
        let mut query_params: Vec<(String, String)> = Vec::new();
        for p in &op.parameters {
            if p.location == ParamLocation::Query {
                if let Some(ov) = overrides.and_then(|o| o.params.get(&p.name)) {
                    // Boundary: always include overridden params
                    query_params.push((p.name.clone(), value_to_param_string(ov)));
                } else if p.required || rng.gen_bool(0.3) {
                    let v = datagen::generate(&p.schema, components, rng);
                    query_params.push((p.name.clone(), value_to_param_string(&v)));
                }
            }
        }

        // Headers (configured + spec-defined)
        let mut req_headers = self.headers.clone();
        for param in &op.parameters {
            if param.location == ParamLocation::Header {
                if let Some(ov) = overrides.and_then(|o| o.params.get(&param.name)) {
                    req_headers.insert(param.name.clone(), value_to_param_string(ov));
                } else {
                    let v = datagen::generate(&param.schema, components, rng);
                    req_headers.insert(param.name.clone(), value_to_param_string(&v));
                }
            }
        }

        // Request body
        let body = op.request_body_schema.as_ref().map(|schema| {
            let mut generated = datagen::generate(schema, components, rng);
            // Apply body property overrides
            if let Some(ov) = overrides {
                if let serde_json::Value::Object(ref mut obj) = generated {
                    for (k, v) in &ov.body_props {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
            generated
        });

        // Build request
        let method = reqwest::Method::from_bytes(op.method.as_bytes())
            .map_err(|_| format!("invalid HTTP method '{}' for {}", op.method, op.path))?;

        let mut req = client.request(method, &url);
        for (k, v) in &req_headers {
            // Skip header values that are invalid in HTTP (e.g. \0, \r\n from
            // boundary testing).  These never reach the server so testing them
            // via headers has no value.
            if reqwest::header::HeaderValue::from_str(v).is_ok() {
                req = req.header(k, v);
            }
        }
        for (k, v) in &query_params {
            req = req.query(&[(k, v)]);
        }
        if let Some(ref body_value) = body {
            req = req.header("Content-Type", "application/json");
            req = req.json(body_value);
        }

        // Send
        let start = Instant::now();
        let resp = req.send().map_err(|e| e.to_string())?;
        let elapsed = start.elapsed().as_secs_f64();

        let status_code = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();

        // Capture response headers before consuming response body
        let resp_content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let resp_headers = resp.headers().clone();

        // Capture response body (truncated for memory safety)
        let body_text = resp.text().unwrap_or_default();
        let content_length = body_text.len() as u64;
        const MAX_BODY_BYTES: usize = 4096;
        let body_stored = if body_text.is_empty() {
            None
        } else if body_text.len() <= MAX_BODY_BYTES {
            Some(body_text.clone())
        } else {
            // Safe UTF-8 truncation: walk back to char boundary
            let mut end = MAX_BODY_BYTES;
            while end > 0 && !body_text.is_char_boundary(end) {
                end -= 1;
            }
            Some(format!(
                "{}…({} bytes total)",
                &body_text[..end],
                body_text.len()
            ))
        };

        let case_id = format!("{:016x}", rng.r#gen::<u64>());
        let operation_label = format!("{} {}", op.method, op.path);

        let raw_case = RawCase {
            method: op.method.clone(),
            path: op.path.clone(),
            id: Some(case_id.clone()),
            path_parameters: if path_params_resolved.is_empty() {
                None
            } else {
                Some(path_params_resolved)
            },
            headers: if req_headers.is_empty() {
                None
            } else {
                Some(req_headers.clone())
            },
            query: if query_params.is_empty() {
                None
            } else {
                Some(
                    query_params
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect(),
                )
            },
            body: body.clone(),
            media_type: body.as_ref().map(|_| "application/json".to_string()),
        };

        let raw_response = RawResponse {
            status_code,
            elapsed,
            message: status_text,
            content_length,
            body: body_stored,
        };

        // Run response validation checks (pure logic, no I/O)
        let mut check_input = CheckInput {
            status_code,
            body_text: &body_text,
            content_type: resp_content_type.as_deref(),
            response_headers: &resp_headers,
            elapsed,
            url: &url,
            operation_label: &operation_label,
            case_id: &case_id,
            expectation,
            op,
            response_time_limit: self.response_time_limit,
            seen_spec_gaps,
        };
        let failures = run_checks(&mut check_input);

        let interaction = RawInteraction {
            case: raw_case,
            response: raw_response,
            operation: operation_label,
            failures: failures.clone(),
        };

        Ok((interaction, failures))
    }
}

/// Parse an OpenAPI spec from JSON or YAML.
///
/// Detection strategy: try extension first (`.yaml`/`.yml`), then fall back to
/// content sniffing (leading `{` → JSON, otherwise YAML).
fn parse_spec(path: &std::path::Path, content: &str) -> Result<serde_json::Value, NativeError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "yaml" | "yml" => serde_yml::from_str(content)
            .map_err(|e| NativeError::Parse(format!("Invalid YAML: {e}"))),
        "json" => serde_json::from_str(content)
            .map_err(|e| NativeError::Parse(format!("Invalid JSON: {e}"))),
        _ => {
            // Content sniffing: trimmed first char
            if content.trim_start().starts_with('{') {
                serde_json::from_str(content)
                    .map_err(|e| NativeError::Parse(format!("Invalid JSON: {e}")))
            } else {
                serde_yml::from_str(content)
                    .map_err(|e| NativeError::Parse(format!("Invalid YAML: {e}")))
            }
        }
    }
}

fn value_to_param_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("HTTP error: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    use checks::CheckInput;
    use checks::run_checks;
    use phases::StatusExpectation;
    use spec::Operation;

    // ── Test helpers ──

    fn base_op() -> Operation {
        Operation {
            method: "GET".to_string(),
            path: "/test".to_string(),
            parameters: vec![],
            request_body_schema: None,
            expected_statuses: vec![200, 422],
            response_schemas: HashMap::new(),
            response_content_types: HashMap::new(),
            response_headers: HashMap::new(),
        }
    }

    fn check(input: &mut CheckInput) -> Vec<RawFailure> {
        run_checks(input)
    }

    /// Default expectation: AnyDeclared [200, 422] — won't fire StatusSatisfyExpectation
    /// for statuses 200 or 422, allowing other checks to be tested in isolation.
    fn default_expectation() -> StatusExpectation {
        StatusExpectation::AnyDeclared(vec![200, 422])
    }

    fn input_with<'a>(
        op: &'a Operation,
        status: u16,
        body: &'a str,
        expectation: &'a StatusExpectation,
        resp_headers: &'a reqwest::header::HeaderMap,
        seen: &'a mut HashSet<String>,
    ) -> CheckInput<'a> {
        CheckInput {
            status_code: status,
            body_text: body,
            content_type: Some("application/json"),
            response_headers: resp_headers,
            elapsed: 0.05,
            url: "http://localhost:8080/test",
            operation_label: "GET /test",
            case_id: "test-001",
            expectation,
            op,
            response_time_limit: None,
            seen_spec_gaps: seen,
        }
    }

    fn has_type(failures: &[RawFailure], ft: &str) -> bool {
        failures.iter().any(|f| f.failure_type == ft)
    }

    fn find_type<'a>(failures: &'a [RawFailure], ft: &str) -> Option<&'a RawFailure> {
        failures.iter().find(|f| f.failure_type == ft)
    }

    // ── extract_operations ──

    #[test]
    fn extract_operations_from_spec() {
        let spec = serde_json::json!({
            "openapi": "3.1.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/health": {
                    "get": {
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"name": {"type": "string"}},
                                        "required": ["name"]
                                    }
                                }
                            }
                        },
                        "responses": {"200": {}, "400": {}}
                    }
                },
                "/users/{user_id}": {
                    "get": {
                        "parameters": [
                            {"name": "user_id", "in": "path", "required": true, "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {}, "404": {}}
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops.len(), 3);

        let health = ops.iter().find(|o| o.path == "/health").unwrap();
        assert_eq!(health.method, "GET");
        assert!(health.parameters.is_empty());

        let create = ops.iter().find(|o| o.path == "/users").unwrap();
        assert_eq!(create.method, "POST");
        assert!(create.request_body_schema.is_some());
        assert!(create.expected_statuses.contains(&200));
        assert!(create.expected_statuses.contains(&400));

        let get_user = ops
            .iter()
            .find(|o| o.path == "/users/{user_id}" && o.method == "GET")
            .unwrap();
        assert_eq!(get_user.parameters.len(), 1);
        assert_eq!(get_user.parameters[0].name, "user_id");
    }

    // ═══════════════════════════════════════════
    // Health Check: ServerError (5xx)
    // ═══════════════════════════════════════════

    #[test]
    fn server_error_500_detected() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 500, "Internal Server Error", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(has_type(&f, "ServerError"), "500 must be detected");
    }

    #[test]
    fn server_error_502_detected() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 502, "Bad Gateway", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(has_type(&f, "ServerError"), "502 must be detected");
    }

    #[test]
    fn server_error_200_not_flagged() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(!has_type(&f, "ServerError"), "200 must not be ServerError");
    }

    #[test]
    fn server_error_400_not_flagged() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 400, "Bad Request", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(!has_type(&f, "ServerError"), "400 must not be ServerError");
    }

    // ═══════════════════════════════════════════
    // StatusSatisfyExpectation (replaces Check 2 + 3)
    // ═══════════════════════════════════════════

    #[test]
    fn status_any_declared_undeclared_detected() {
        let op = base_op(); // declared: [200, 422]
        let exp = StatusExpectation::AnyDeclared(vec![200, 422]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 404, "Not Found", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "StatusSatisfyExpectation"),
            "404 not in [200, 422] must be detected"
        );
        let fail = find_type(&f, "StatusSatisfyExpectation").unwrap();
        assert!(fail.message.contains("404"));
    }

    #[test]
    fn status_any_declared_ok() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = StatusExpectation::AnyDeclared(vec![200, 422]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "StatusSatisfyExpectation"),
            "200 is declared, should not fire"
        );
    }

    #[test]
    fn status_5xx_excluded_from_expectation() {
        let op = base_op();
        let exp = StatusExpectation::AnyDeclared(vec![200, 422]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 500, "error", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "StatusSatisfyExpectation"),
            "5xx handled by ServerError, not status expectation"
        );
        assert!(has_type(&f, "ServerError"));
    }

    #[test]
    fn status_rejection_2xx_detected() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = StatusExpectation::Rejection;
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "StatusSatisfyExpectation"),
            "Rejection expectation + 2xx must be detected"
        );
        let fail = find_type(&f, "StatusSatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Invalid input accepted");
    }

    #[test]
    fn status_rejection_422_not_flagged() {
        let op = base_op();
        let exp = StatusExpectation::Rejection;
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 422, r#"{"detail":"err"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "StatusSatisfyExpectation"),
            "Rejection + 422 = correctly rejected"
        );
    }

    #[test]
    fn status_success_expected_wrong_2xx() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = StatusExpectation::SuccessExpected(vec![200]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 201, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "StatusSatisfyExpectation"),
            "Got 201 when only 200 expected"
        );
        let fail = find_type(&f, "StatusSatisfyExpectation").unwrap();
        assert_eq!(fail.severity, "medium");
    }

    #[test]
    fn status_success_expected_non_2xx() {
        let op = base_op();
        let exp = StatusExpectation::SuccessExpected(vec![200]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 422, r#"{"detail":"err"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "StatusSatisfyExpectation"),
            "Valid input rejected → high severity"
        );
        let fail = find_type(&f, "StatusSatisfyExpectation").unwrap();
        assert_eq!(fail.severity, "high");
        assert_eq!(fail.title, "Valid input rejected");
    }

    #[test]
    fn status_success_expected_ok() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = StatusExpectation::SuccessExpected(vec![200]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "StatusSatisfyExpectation"),
            "200 is expected → no failure"
        );
    }

    // ═══════════════════════════════════════════
    // Health Check: ResponseTimeExceeded
    // ═══════════════════════════════════════════

    #[test]
    fn response_time_exceeded_detected() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, "{}", &exp, &hdrs, &mut seen);
        input.response_time_limit = Some(1.0);
        input.elapsed = 2.5;
        let f = check(&mut input);
        assert!(has_type(&f, "ResponseTimeExceeded"));
        let fail = find_type(&f, "ResponseTimeExceeded").unwrap();
        assert!(fail.elapsed == Some(2.5));
        assert!(fail.deadline == Some(1.0));
    }

    #[test]
    fn response_time_under_limit_ok() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, "{}", &exp, &hdrs, &mut seen);
        input.response_time_limit = Some(5.0);
        input.elapsed = 0.05;
        let f = check(&mut input);
        assert!(
            !has_type(&f, "ResponseTimeExceeded"),
            "Under limit must not fire"
        );
    }

    #[test]
    fn response_time_no_limit_configured() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, "{}", &exp, &hdrs, &mut seen);
        input.response_time_limit = None;
        input.elapsed = 999.0;
        let f = check(&mut input);
        assert!(
            !has_type(&f, "ResponseTimeExceeded"),
            "No limit configured → skip"
        );
    }

    // ═══════════════════════════════════════════
    // BodySatisfyExpectation (replaces SchemaViolation)
    // ═══════════════════════════════════════════

    #[test]
    fn body_violates_schema() {
        let mut op = base_op();
        op.response_schemas.insert(
            200,
            serde_json::json!({
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"]
            }),
        );
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(
            &op,
            200,
            r#"{"id": "not-a-number"}"#,
            &exp,
            &hdrs,
            &mut seen,
        );
        let f = check(&mut input);
        assert!(
            has_type(&f, "BodySatisfyExpectation"),
            "Body violating schema must be detected"
        );
        let fail = find_type(&f, "BodySatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Response body does not match schema");
    }

    #[test]
    fn body_matches_schema() {
        let mut op = base_op();
        op.response_schemas.insert(
            200,
            serde_json::json!({
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"]
            }),
        );
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"id": 42}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "BodySatisfyExpectation"),
            "Valid body must not fire"
        );
    }

    #[test]
    fn body_non_json_with_json_content_type() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, "this is not json", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(has_type(&f, "BodySatisfyExpectation"));
        let fail = find_type(&f, "BodySatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Response body is not valid JSON");
    }

    #[test]
    fn body_empty_schema_warns_on_2xx() {
        let mut op = base_op();
        op.response_schemas.insert(200, serde_json::json!({}));
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"anything": "goes"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "BodySatisfyExpectation"),
            "Empty schema on 2xx must warn (spec gap)"
        );
        let fail = find_type(&f, "BodySatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Response schema is empty");
        assert_eq!(fail.severity, "low");
    }

    #[test]
    fn body_no_schema_defined_warns_on_2xx() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"data": 1}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "BodySatisfyExpectation"),
            "No schema for 2xx with body must warn (spec gap)"
        );
        let fail = find_type(&f, "BodySatisfyExpectation").unwrap();
        assert_eq!(fail.title, "No response schema defined");
    }

    #[test]
    fn body_no_schema_on_4xx_silent() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 422, r#"{"detail":"err"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "BodySatisfyExpectation"),
            "Non-2xx missing schema should not warn"
        );
    }

    #[test]
    fn body_no_schema_on_2xx_empty_body_silent() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, "", &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "BodySatisfyExpectation"
                    && ff.title == "No response schema defined"),
            "No schema + empty body → no warning needed"
        );
    }

    // ═══════════════════════════════════════════
    // HeaderSatisfyExpectation (replaces ContentTypeMismatch)
    // ═══════════════════════════════════════════

    #[test]
    fn header_content_type_mismatch_detected() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"<html>oops</html>"#, &exp, &hdrs, &mut seen);
        input.content_type = Some("text/html");
        let f = check(&mut input);
        assert!(
            has_type(&f, "HeaderSatisfyExpectation"),
            "text/html when spec says application/json must be detected"
        );
        let fail = find_type(&f, "HeaderSatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Unexpected Content-Type");
    }

    #[test]
    fn header_content_type_match_ok() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !has_type(&f, "HeaderSatisfyExpectation"),
            "Matching Content-Type must not fire"
        );
    }

    #[test]
    fn header_content_type_charset_ignored() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        input.content_type = Some("application/json; charset=utf-8");
        let f = check(&mut input);
        assert!(
            !has_type(&f, "HeaderSatisfyExpectation"),
            "charset param must be ignored in comparison"
        );
    }

    #[test]
    fn header_missing_content_type_detected() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        input.content_type = None;
        let f = check(&mut input);
        assert!(
            has_type(&f, "HeaderSatisfyExpectation"),
            "Missing Content-Type header when spec declares types must be detected"
        );
        let fail = find_type(&f, "HeaderSatisfyExpectation").unwrap();
        assert_eq!(fail.title, "Missing Content-Type header");
    }

    #[test]
    fn header_no_types_declared_warns_on_2xx() {
        let mut op = base_op();
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            has_type(&f, "HeaderSatisfyExpectation"),
            "No content types declared for 2xx must warn (spec gap)"
        );
        let fail = find_type(&f, "HeaderSatisfyExpectation").unwrap();
        assert_eq!(fail.title, "No content types declared in spec");
    }

    #[test]
    fn header_no_types_on_4xx_silent() {
        let op = base_op();
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 422, r#"{"detail":"err"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "HeaderSatisfyExpectation"
                    && ff.title == "No content types declared in spec"),
            "Non-2xx missing content types should not warn"
        );
    }

    // ═══════════════════════════════════════════
    // HeaderSatisfyExpectation: response headers
    // ═══════════════════════════════════════════

    #[test]
    fn header_required_missing_detected() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_headers.insert(
            200,
            vec![spec::ResponseHeader {
                name: "X-Request-Id".to_string(),
                required: true,
                schema: None,
            }],
        );
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new(); // missing X-Request-Id
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        let hdr_fails: Vec<_> = f
            .iter()
            .filter(|ff| {
                ff.failure_type == "HeaderSatisfyExpectation"
                    && ff.title == "Required response header missing"
            })
            .collect();
        assert_eq!(
            hdr_fails.len(),
            1,
            "Required header missing must be detected"
        );
        assert!(hdr_fails[0].message.contains("X-Request-Id"));
    }

    #[test]
    fn header_required_present_ok() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_headers.insert(
            200,
            vec![spec::ResponseHeader {
                name: "X-Request-Id".to_string(),
                required: true,
                schema: None,
            }],
        );
        let exp = default_expectation();
        let mut hdrs = reqwest::header::HeaderMap::new();
        hdrs.insert("X-Request-Id", "abc-123".parse().unwrap());
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "HeaderSatisfyExpectation"
                    && ff.title == "Required response header missing"),
            "Present required header must not fire"
        );
    }

    #[test]
    fn header_schema_violation_detected() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_headers.insert(
            200,
            vec![spec::ResponseHeader {
                name: "X-Rate-Limit".to_string(),
                required: false,
                schema: Some(serde_json::json!({"type": "integer", "minimum": 0})),
            }],
        );
        let exp = default_expectation();
        let mut hdrs = reqwest::header::HeaderMap::new();
        hdrs.insert("X-Rate-Limit", "not-a-number".parse().unwrap());
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        let hdr_fails: Vec<_> = f
            .iter()
            .filter(|ff| {
                ff.failure_type == "HeaderSatisfyExpectation"
                    && ff.title == "Response header type mismatch"
            })
            .collect();
        assert_eq!(
            hdr_fails.len(),
            1,
            "Non-integer value for integer schema must be detected"
        );
        assert!(hdr_fails[0].message.contains("X-Rate-Limit"));
    }

    #[test]
    fn header_schema_valid_integer_ok() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_headers.insert(
            200,
            vec![spec::ResponseHeader {
                name: "X-Rate-Limit".to_string(),
                required: false,
                schema: Some(serde_json::json!({"type": "integer", "minimum": 0})),
            }],
        );
        let exp = default_expectation();
        let mut hdrs = reqwest::header::HeaderMap::new();
        hdrs.insert("X-Rate-Limit", "100".parse().unwrap());
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "HeaderSatisfyExpectation"
                    && (ff.title == "Response header type mismatch"
                        || ff.title == "Response header schema violation")),
            "Valid integer header must not fire"
        );
    }

    #[test]
    fn header_optional_missing_silent() {
        let mut op = base_op();
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        op.response_schemas
            .insert(200, serde_json::json!({"type": "object"}));
        op.response_headers.insert(
            200,
            vec![spec::ResponseHeader {
                name: "X-Optional".to_string(),
                required: false,
                schema: Some(serde_json::json!({"type": "string"})),
            }],
        );
        let exp = default_expectation();
        let hdrs = reqwest::header::HeaderMap::new(); // missing optional header
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"ok":true}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            !f.iter()
                .any(|ff| ff.failure_type == "HeaderSatisfyExpectation"
                    && ff.title == "Required response header missing"),
            "Optional header missing must not fire"
        );
    }

    // ═══════════════════════════════════════════
    // Cross-check: multiple checks fire together
    // ═══════════════════════════════════════════

    #[test]
    fn multiple_checks_fire_simultaneously() {
        let mut op = base_op();
        op.response_schemas.insert(
            200,
            serde_json::json!({
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"]
            }),
        );
        op.response_content_types
            .insert(200, vec!["application/xml".to_string()]);
        let exp = StatusExpectation::Rejection;
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"id": "wrong"}"#, &exp, &hdrs, &mut seen);
        input.response_time_limit = Some(0.01);
        input.elapsed = 1.0;
        let f = check(&mut input);
        assert!(
            has_type(&f, "StatusSatisfyExpectation"),
            "Invalid input accepted"
        );
        assert!(has_type(&f, "ResponseTimeExceeded"), "Over limit");
        assert!(has_type(&f, "BodySatisfyExpectation"), "Schema mismatch");
        assert!(
            has_type(&f, "HeaderSatisfyExpectation"),
            "Content-Type mismatch"
        );
    }

    // ═══════════════════════════════════════════
    // parse_spec: JSON / YAML / content sniffing
    // ═══════════════════════════════════════════

    #[test]
    fn parse_spec_json_by_extension() {
        let json = r#"{"openapi": "3.1.0", "info": {"title": "T", "version": "1"}}"#;
        let v = parse_spec(std::path::Path::new("spec.json"), json).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
    }

    #[test]
    fn parse_spec_yaml_by_extension() {
        let yaml = "openapi: '3.1.0'\ninfo:\n  title: T\n  version: '1'\n";
        let v = parse_spec(std::path::Path::new("spec.yaml"), yaml).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
    }

    #[test]
    fn parse_spec_yml_by_extension() {
        let yaml = "openapi: '3.1.0'\ninfo:\n  title: T\n  version: '1'\n";
        let v = parse_spec(std::path::Path::new("spec.yml"), yaml).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
    }

    #[test]
    fn parse_spec_sniff_json() {
        let json = r#"{"openapi": "3.1.0"}"#;
        let v = parse_spec(std::path::Path::new("spec"), json).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
    }

    #[test]
    fn parse_spec_sniff_yaml() {
        let yaml = "openapi: '3.1.0'\n";
        let v = parse_spec(std::path::Path::new("spec.txt"), yaml).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
    }

    #[test]
    fn parse_spec_invalid_json_error() {
        let bad = "{ invalid json";
        let err = parse_spec(std::path::Path::new("spec.json"), bad);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Invalid JSON"));
    }

    #[test]
    fn parse_spec_invalid_yaml_error() {
        let bad = ":\n  :\n    - [invalid";
        let err = parse_spec(std::path::Path::new("spec.yaml"), bad);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Invalid YAML"));
    }

    #[test]
    fn clean_200_with_full_spec_no_failures() {
        let mut op = base_op();
        op.response_schemas.insert(
            200,
            serde_json::json!({
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"]
            }),
        );
        op.response_content_types
            .insert(200, vec!["application/json".to_string()]);
        let exp = StatusExpectation::SuccessExpected(vec![200]);
        let hdrs = reqwest::header::HeaderMap::new();
        let mut seen = HashSet::new();
        let mut input = input_with(&op, 200, r#"{"status": "ok"}"#, &exp, &hdrs, &mut seen);
        let f = check(&mut input);
        assert!(
            f.is_empty(),
            "Clean response with full spec → zero failures, got: {f:?}"
        );
    }
}
