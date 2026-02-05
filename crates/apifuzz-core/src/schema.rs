//! Raw interchange types: Schemathesis Python SDK → Rust
//!
//! These types mirror Schemathesis's own object model exactly.
//! Python just dumps them as JSON; Rust does all classification/verdict logic.
//! Source of truth: schemathesis.checks.Failure and friends.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Top-level output from the Python wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SchemathesisOutput {
    /// Total HTTP requests made
    pub total: u64,
    /// Successful requests (no check failures)
    pub success: u64,
    /// Number of failures
    pub failure_count: u64,
    /// Raw failures from Schemathesis checks
    pub failures: Vec<RawFailure>,
    /// Raw interactions (case + response pairs)
    #[serde(default)]
    pub interactions: Vec<RawInteraction>,
    /// Errors from the wrapper itself (connection errors, etc.)
    #[serde(default)]
    pub errors: Vec<String>,
}

/// A failure from Schemathesis checks - mirrors schemathesis.checks.Failure hierarchy.
///
/// Subtypes: ServerError, ResponseTimeExceeded, MalformedJson, CustomFailure, Failure (base)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RawFailure {
    /// Python class name: "ServerError", "ResponseTimeExceeded", "MalformedJson", etc.
    #[serde(rename = "type")]
    pub failure_type: String,
    /// Operation label: "GET /health"
    pub operation: String,
    /// Short title: "Server error", "Response time limit exceeded"
    pub title: String,
    /// Detailed message
    pub message: String,
    /// Case ID for reproduction
    pub case_id: Option<String>,
    /// Schemathesis severity: "critical", "high", "medium", "low"
    pub severity: String,

    // -- ServerError specific --
    /// HTTP status code (ServerError only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    // -- ResponseTimeExceeded specific --
    /// Actual elapsed time in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed: Option<f64>,
    /// Configured deadline in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<f64>,

    // -- MalformedJson specific --
    /// JSON validation error message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_message: Option<String>,
    /// The malformed document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    /// Position in document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
    /// Line number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineno: Option<u64>,
    /// Column number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colno: Option<u64>,
}

/// A test case (request) as produced by Schemathesis.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RawCase {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_parameters: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// A response as seen by the fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RawResponse {
    pub status_code: u16,
    #[serde(default)]
    pub elapsed: f64,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub content_length: u64,
    /// Response body (truncated for large responses)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// A single interaction: case + response + optional failures.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RawInteraction {
    pub case: RawCase,
    pub response: RawResponse,
    pub operation: String,
    #[serde(default)]
    pub failures: Vec<RawFailure>,
}

/// Generate JSON Schema for the interchange format.
#[must_use]
pub fn generate_schema() -> String {
    let schema = schemars::schema_for!(SchemathesisOutput);
    serde_json::to_string_pretty(&schema).expect("schema serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_server_error() {
        let json = r#"{
            "type": "ServerError",
            "operation": "POST /api/users",
            "title": "Server error",
            "message": "500 Internal Server Error",
            "case_id": "abc123",
            "severity": "critical",
            "status_code": 500
        }"#;
        let f: RawFailure = serde_json::from_str(json).unwrap();
        assert_eq!(f.failure_type, "ServerError");
        assert_eq!(f.status_code, Some(500));
        assert_eq!(f.severity, "critical");
    }

    #[test]
    fn deserialize_response_time_exceeded() {
        let json = r#"{
            "type": "ResponseTimeExceeded",
            "operation": "GET /health",
            "title": "Response time limit exceeded",
            "message": "Took 5.2s, limit 1.0s",
            "case_id": null,
            "severity": "medium",
            "elapsed": 5.2,
            "deadline": 1.0
        }"#;
        let f: RawFailure = serde_json::from_str(json).unwrap();
        assert_eq!(f.failure_type, "ResponseTimeExceeded");
        assert_eq!(f.elapsed, Some(5.2));
        assert_eq!(f.deadline, Some(1.0));
    }

    #[test]
    fn deserialize_full_output() {
        let json = r#"{
            "total": 200,
            "success": 195,
            "failure_count": 5,
            "failures": [
                {
                    "type": "ServerError",
                    "operation": "POST /users",
                    "title": "Server error",
                    "message": "",
                    "case_id": "xyz",
                    "severity": "critical",
                    "status_code": 500
                }
            ],
            "interactions": [],
            "errors": []
        }"#;
        let output: SchemathesisOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.total, 200);
        assert_eq!(output.success, 195);
        assert_eq!(output.failures.len(), 1);
    }

    #[test]
    fn deserialize_with_interactions() {
        let json = r#"{
            "total": 1,
            "success": 0,
            "failure_count": 1,
            "failures": [],
            "interactions": [{
                "case": {"method": "GET", "path": "/health"},
                "response": {"status_code": 200, "elapsed": 0.05, "message": "OK", "content_length": 15},
                "operation": "GET /health",
                "failures": []
            }],
            "errors": []
        }"#;
        let output: SchemathesisOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.interactions.len(), 1);
        assert_eq!(output.interactions[0].case.method, "GET");
        assert_eq!(output.interactions[0].response.status_code, 200);
    }

    #[test]
    fn deserialize_with_errors() {
        let json = r#"{
            "total": 0,
            "success": 0,
            "failure_count": 0,
            "failures": [],
            "interactions": [],
            "errors": ["ConnectionError: refused"]
        }"#;
        let output: SchemathesisOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.errors.len(), 1);
    }

    #[test]
    fn schema_generation_produces_valid_json() {
        let schema = generate_schema();
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();
        assert!(parsed.get("$schema").is_some() || parsed.get("type").is_some());
        assert_eq!(
            parsed.get("title").and_then(|v| v.as_str()),
            Some("SchemathesisOutput")
        );
    }
}
