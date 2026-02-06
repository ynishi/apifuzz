//! Dry run plan types and config validation
//!
//! Describes what the fuzzer *would* do without sending any requests.
//! Used for pre-flight validation and CI previews.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Config;

// ── Plan types ──

/// Complete dry run plan: operations, request counts, and config warnings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DryRunPlan {
    /// Per-operation execution plan
    pub operations: Vec<OperationPlan>,
    /// Total requests that would be sent
    pub total_requests: u64,
    /// Config/spec validation results
    pub validations: Vec<Validation>,
}

/// Execution plan for a single operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationPlan {
    /// Operation label, e.g. "POST /api/users"
    pub operation: String,
    /// HTTP method
    pub method: String,
    /// Path template
    pub path: String,
    /// Total requests for this operation
    pub total: u32,
    /// Per-phase request counts
    pub phases: PhaseCounts,
    /// Parameter names (path, query, header)
    pub parameters: Vec<String>,
    /// Request body property names
    pub body_properties: Vec<String>,
    /// Matched probes for this operation
    pub matched_probes: Vec<MatchedProbe>,
}

/// Per-phase request counts.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PhaseCounts {
    pub probe: u32,
    pub boundary: u32,
    pub type_confusion: u32,
    pub neighborhood: u32,
    pub random: u32,
}

/// A probe that matched an operation with its values.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchedProbe {
    pub target: String,
    pub values: Vec<serde_json::Value>,
}

/// A validation check result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Validation {
    pub check: String,
    pub status: ValidationStatus,
    pub message: String,
}

/// Status of a validation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Ok,
    Warning,
    Error,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ── Config validation ──

/// Patterns that suggest a placeholder value rather than a real credential.
const PLACEHOLDER_PATTERNS: &[&str] = &[
    "your-token",
    "your_token",
    "YOUR_TOKEN",
    "your-api-key",
    "YOUR_API_KEY",
    "TODO",
    "CHANGEME",
    "changeme",
    "placeholder",
    "xxx",
    "XXX",
    "replace-me",
    "REPLACE_ME",
    "insert-",
    "INSERT_",
    "example",
];

/// Validate config and produce validation results.
#[must_use]
pub fn validate_config(config: &Config) -> Vec<Validation> {
    let mut checks = Vec::new();

    // Spec file exists
    if config.spec.exists() {
        checks.push(Validation {
            check: "spec".into(),
            status: ValidationStatus::Ok,
            message: format!("spec: {} (exists)", config.spec.display()),
        });
    } else {
        checks.push(Validation {
            check: "spec".into(),
            status: ValidationStatus::Error,
            message: format!("spec: {} (not found)", config.spec.display()),
        });
    }

    // Base URL
    if config.base_url.starts_with("http://") || config.base_url.starts_with("https://") {
        checks.push(Validation {
            check: "base_url".into(),
            status: ValidationStatus::Ok,
            message: format!("base_url: {}", config.base_url),
        });
    } else {
        checks.push(Validation {
            check: "base_url".into(),
            status: ValidationStatus::Warning,
            message: format!(
                "base_url: {} (missing http:// or https:// prefix)",
                config.base_url
            ),
        });
    }

    // Headers — check for placeholders
    if config.headers.is_empty() {
        checks.push(Validation {
            check: "headers".into(),
            status: ValidationStatus::Ok,
            message: "headers: none configured".into(),
        });
    } else {
        let mut header_issues = Vec::new();
        for (key, value) in &config.headers {
            // Check for angle-bracket placeholders: <token>, <your-key>
            if value.contains('<') && value.contains('>') {
                header_issues.push(format!("{key}: contains '<...>' placeholder"));
            }
            // Check for known placeholder patterns
            for pattern in PLACEHOLDER_PATTERNS {
                if value.contains(pattern) {
                    header_issues.push(format!("{key}: contains '{pattern}' — may be placeholder"));
                    break;
                }
            }
        }

        if header_issues.is_empty() {
            checks.push(Validation {
                check: "headers".into(),
                status: ValidationStatus::Ok,
                message: format!("headers: {} configured", config.headers.len()),
            });
        } else {
            for issue in header_issues {
                checks.push(Validation {
                    check: "headers".into(),
                    status: ValidationStatus::Warning,
                    message: issue,
                });
            }
        }
    }

    // Probes
    if !config.probes.is_empty() {
        let total_values: usize = config.probes.iter().map(|p| p.to_json_values().len()).sum();
        checks.push(Validation {
            check: "probes".into(),
            status: ValidationStatus::Ok,
            message: format!(
                "probes: {} defined ({} values)",
                config.probes.len(),
                total_values
            ),
        });
    }

    checks
}

// ── Display helpers ──

impl DryRunPlan {
    /// Format as human-readable terminal output.
    #[must_use]
    pub fn to_terminal(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "Dry run: {} operations, {} requests planned\n",
            self.operations.len(),
            self.total_requests,
        ));

        for op in &self.operations {
            lines.push(format!("{} ({} requests):", op.operation, op.total,));
            lines.push(format!(
                "  Phases: {} probe, {} boundary, {} type_confusion, {} neighborhood, {} random",
                op.phases.probe,
                op.phases.boundary,
                op.phases.type_confusion,
                op.phases.neighborhood,
                op.phases.random,
            ));

            if !op.parameters.is_empty() {
                lines.push(format!("  Parameters: {}", op.parameters.join(", ")));
            }
            if !op.body_properties.is_empty() {
                lines.push(format!(
                    "  Body properties: {}",
                    op.body_properties.join(", ")
                ));
            }
            for probe in &op.matched_probes {
                let vals: Vec<String> = probe
                    .values
                    .iter()
                    .map(|v| {
                        if v.is_string() {
                            format!("{v}")
                        } else {
                            v.to_string()
                        }
                    })
                    .collect();
                lines.push(format!("  Probe [{}]: {}", probe.target, vals.join(", "),));
            }
            lines.push(String::new());
        }

        // Validations
        lines.push("Config validation:".into());
        for v in &self.validations {
            let icon = match v.status {
                ValidationStatus::Ok => "OK",
                ValidationStatus::Warning => "WARNING",
                ValidationStatus::Error => "ERROR",
            };
            lines.push(format!("  [{icon}] {}", v.message));
        }

        lines.join("\n")
    }

    /// Returns true if any validation has Error status.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.validations
            .iter()
            .any(|v| v.status == ValidationStatus::Error)
    }

    /// Returns true if any validation has Warning status.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.validations
            .iter()
            .any(|v| v.status == ValidationStatus::Warning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SuccessCriteria;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn config_with_headers(headers: HashMap<String, String>) -> Config {
        Config {
            spec: PathBuf::from("nonexistent.yaml"),
            base_url: "http://localhost:8080".into(),
            headers,
            path_params: HashMap::new(),
            probes: vec![],
            response_time_limit: None,
            success_criteria: SuccessCriteria::Default,
            min_success_rate: None,
        }
    }

    #[test]
    fn validate_placeholder_angle_brackets() {
        let mut h = HashMap::new();
        h.insert("Authorization".into(), "Bearer <your-token-here>".into());
        let checks = validate_config(&config_with_headers(h));
        let header_checks: Vec<_> = checks.iter().filter(|c| c.check == "headers").collect();
        assert!(
            header_checks
                .iter()
                .any(|c| c.status == ValidationStatus::Warning),
            "Should warn about angle-bracket placeholder"
        );
    }

    #[test]
    fn validate_placeholder_pattern() {
        let mut h = HashMap::new();
        h.insert("X-API-Key".into(), "YOUR_TOKEN_HERE".into());
        let checks = validate_config(&config_with_headers(h));
        let header_checks: Vec<_> = checks.iter().filter(|c| c.check == "headers").collect();
        assert!(
            header_checks
                .iter()
                .any(|c| c.status == ValidationStatus::Warning),
            "Should warn about YOUR_TOKEN placeholder"
        );
    }

    #[test]
    fn validate_real_token_no_warning() {
        let mut h = HashMap::new();
        h.insert(
            "Authorization".into(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.abc.xyz".into(),
        );
        let checks = validate_config(&config_with_headers(h));
        let header_checks: Vec<_> = checks.iter().filter(|c| c.check == "headers").collect();
        assert_eq!(header_checks.len(), 1);
        assert_eq!(header_checks[0].status, ValidationStatus::Ok);
    }

    #[test]
    fn validate_bad_base_url() {
        let cfg = Config {
            base_url: "localhost:8080".into(),
            ..config_with_headers(HashMap::new())
        };
        let checks = validate_config(&cfg);
        let url_check = checks.iter().find(|c| c.check == "base_url").unwrap();
        assert_eq!(url_check.status, ValidationStatus::Warning);
    }

    #[test]
    fn validate_spec_not_found() {
        let cfg = config_with_headers(HashMap::new());
        let checks = validate_config(&cfg);
        let spec_check = checks.iter().find(|c| c.check == "spec").unwrap();
        assert_eq!(spec_check.status, ValidationStatus::Error);
    }

    #[test]
    fn plan_terminal_output() {
        let plan = DryRunPlan {
            operations: vec![OperationPlan {
                operation: "POST /users".into(),
                method: "POST".into(),
                path: "/users".into(),
                total: 150,
                phases: PhaseCounts {
                    probe: 5,
                    boundary: 20,
                    type_confusion: 10,
                    neighborhood: 38,
                    random: 77,
                },
                parameters: vec!["user_id".into()],
                body_properties: vec!["name".into(), "email".into()],
                matched_probes: vec![MatchedProbe {
                    target: "name".into(),
                    values: vec![
                        serde_json::Value::String("".into()),
                        serde_json::Value::Null,
                    ],
                }],
            }],
            total_requests: 150,
            validations: vec![Validation {
                check: "spec".into(),
                status: ValidationStatus::Ok,
                message: "spec: openapi.yaml (exists)".into(),
            }],
        };

        let text = plan.to_terminal();
        assert!(text.contains("1 operations, 150 requests planned"));
        assert!(text.contains("POST /users (150 requests)"));
        assert!(text.contains("5 probe"));
        assert!(text.contains("Parameters: user_id"));
        assert!(text.contains("Body properties: name, email"));
        assert!(text.contains("Probe [name]"));
        assert!(text.contains("[OK] spec: openapi.yaml (exists)"));
    }

    #[test]
    fn plan_has_errors() {
        let plan = DryRunPlan {
            operations: vec![],
            total_requests: 0,
            validations: vec![Validation {
                check: "spec".into(),
                status: ValidationStatus::Error,
                message: "not found".into(),
            }],
        };
        assert!(plan.has_errors());
        assert!(!plan.has_warnings());
    }
}
