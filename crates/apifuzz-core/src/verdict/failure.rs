//! Failure types and structured representation

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::Severity;

/// Type of failure - determines default severity and remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureType {
    /// Server error (5xx)
    ServerError,
    /// Unhandled exception crash
    Crash,
    /// Request timeout
    Timeout,
    /// Response doesn't match OpenAPI schema
    SchemaViolation,
    /// Unexpected authentication error
    AuthError,
    /// Rate limit hit
    RateLimit,
    /// Status code not declared in OpenAPI spec
    StatusCodeConformance,
    /// Invalid input accepted with success status (negative testing)
    NegativeTestAccepted,
    /// Response Content-Type does not match OpenAPI spec
    ContentTypeMismatch,
    /// Other unexpected error
    UnexpectedError,
}

impl FailureType {
    /// Default severity for this failure type
    #[must_use]
    pub const fn default_severity(self) -> Severity {
        match self {
            Self::ServerError | Self::Crash | Self::Timeout => Severity::Critical,
            Self::SchemaViolation | Self::RateLimit => Severity::Warning,
            Self::StatusCodeConformance
            | Self::NegativeTestAccepted
            | Self::ContentTypeMismatch => Severity::Warning,
            Self::AuthError | Self::UnexpectedError => Severity::Error,
        }
    }

    /// Human-readable description
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ServerError => "Server returned 5xx error",
            Self::Crash => "Server crashed or returned malformed response",
            Self::Timeout => "Request timed out",
            Self::SchemaViolation => "Response does not match OpenAPI schema",
            Self::AuthError => "Unexpected authentication/authorization error",
            Self::RateLimit => "Rate limit exceeded",
            Self::StatusCodeConformance => "Status code not declared in OpenAPI spec",
            Self::NegativeTestAccepted => "Invalid input accepted with success status",
            Self::ContentTypeMismatch => "Response Content-Type does not match OpenAPI spec",
            Self::UnexpectedError => "Unexpected error occurred",
        }
    }
}

impl std::fmt::Display for FailureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

/// Snapshot of HTTP request for reproduction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestSnapshot {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Snapshot of HTTP response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseSnapshot {
    pub status_code: u16,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub latency_ms: u64,
}

/// A single failure case
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    /// Unique identifier for reproduction
    pub id: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Actual status code received
    pub status_code: u16,
    /// Expected status code (if known)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
    /// Type of failure
    pub failure_type: FailureType,
    /// Severity level
    pub severity: Severity,
    /// Full request for reproduction
    pub request: RequestSnapshot,
    /// Response received (if any)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseSnapshot>,
    /// Additional context
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, String>,
}

impl Failure {
    /// Create a new failure from status code (auto-classifies type)
    #[must_use]
    pub fn from_status(
        id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        status_code: u16,
        request: RequestSnapshot,
    ) -> Self {
        let failure_type = classify_status(status_code);
        let severity = failure_type.default_severity();

        Self {
            id: id.into(),
            method: method.into(),
            path: path.into(),
            status_code,
            expected_status: None,
            failure_type,
            severity,
            request,
            response: None,
            context: HashMap::new(),
        }
    }

    /// Add response to failure
    #[must_use]
    pub fn with_response(mut self, response: ResponseSnapshot) -> Self {
        self.response = Some(response);
        self
    }

    /// Add context entry
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Override severity
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
}

/// Classify status code into failure type
fn classify_status(status: u16) -> FailureType {
    match status {
        // Timeout must be checked before general 5xx
        408 | 504 => FailureType::Timeout,
        500..=599 => FailureType::ServerError,
        401 | 403 => FailureType::AuthError,
        429 => FailureType::RateLimit,
        _ => FailureType::UnexpectedError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> RequestSnapshot {
        RequestSnapshot {
            method: "POST".to_string(),
            url: "http://localhost:8080/api/users".to_string(),
            headers: HashMap::new(),
            body: Some(r#"{"name": "test"}"#.to_string()),
        }
    }

    #[test]
    fn failure_type_severity_mapping() {
        assert_eq!(
            FailureType::ServerError.default_severity(),
            Severity::Critical
        );
        assert_eq!(FailureType::Crash.default_severity(), Severity::Critical);
        assert_eq!(FailureType::Timeout.default_severity(), Severity::Critical);
        assert_eq!(
            FailureType::SchemaViolation.default_severity(),
            Severity::Warning
        );
        assert_eq!(FailureType::AuthError.default_severity(), Severity::Error);
    }

    #[test]
    fn classify_500_as_server_error() {
        assert_eq!(classify_status(500), FailureType::ServerError);
        assert_eq!(classify_status(502), FailureType::ServerError);
        assert_eq!(classify_status(503), FailureType::ServerError);
    }

    #[test]
    fn classify_401_403_as_auth_error() {
        assert_eq!(classify_status(401), FailureType::AuthError);
        assert_eq!(classify_status(403), FailureType::AuthError);
    }

    #[test]
    fn classify_429_as_rate_limit() {
        assert_eq!(classify_status(429), FailureType::RateLimit);
    }

    #[test]
    fn classify_timeout_status_codes() {
        assert_eq!(classify_status(408), FailureType::Timeout);
        assert_eq!(classify_status(504), FailureType::Timeout);
    }

    #[test]
    fn failure_from_status_500() {
        let failure = Failure::from_status("f1", "POST", "/api/users", 500, sample_request());

        assert_eq!(failure.failure_type, FailureType::ServerError);
        assert_eq!(failure.severity, Severity::Critical);
        assert_eq!(failure.status_code, 500);
    }

    #[test]
    fn failure_builder_pattern() {
        let failure = Failure::from_status("f1", "GET", "/api", 500, sample_request())
            .with_severity(Severity::Error)
            .with_context("reason", "test override");

        assert_eq!(failure.severity, Severity::Error);
        assert_eq!(
            failure.context.get("reason"),
            Some(&"test override".to_string())
        );
    }

    #[test]
    fn failure_serialization_roundtrip() {
        let failure = Failure::from_status("f1", "POST", "/api/users", 500, sample_request());
        let json = serde_json::to_string(&failure).unwrap();
        let parsed: Failure = serde_json::from_str(&json).unwrap();

        assert_eq!(failure, parsed);
    }
}
