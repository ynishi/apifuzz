//! HTTP file generator - converts failures to .http format

use crate::verdict::{Failure, RequestSnapshot};

/// Generate .http file content from failures
pub fn to_http_file(failures: &[Failure], base_url_var: &str) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "# Auto-generated reproduction cases ({} failures)",
        failures.len()
    ));
    lines.push(format!("# Base URL variable: {{{{{base_url_var}}}}}"));
    lines.push(String::new());

    for (idx, failure) in failures.iter().enumerate() {
        lines.push(format!(
            "### [{idx}] {} - {} {}",
            failure.severity, failure.failure_type, failure.status_code
        ));
        lines.push(format!("# ID: {}", failure.id));

        // Request line
        let url = if failure.request.url.starts_with("http") {
            failure.request.url.clone()
        } else {
            format!("{{{{{base_url_var}}}}}{}", failure.request.url)
        };
        lines.push(format!("{} {}", failure.method, url));

        // Headers
        for (key, value) in &failure.request.headers {
            if !matches!(key.to_lowercase().as_str(), "host" | "content-length") {
                lines.push(format!("{key}: {value}"));
            }
        }

        // Body
        if let Some(body) = &failure.request.body {
            if !failure.request.headers.contains_key("Content-Type") {
                lines.push("Content-Type: application/json".to_string());
            }
            lines.push(String::new());
            lines.push(body.clone());
        }

        lines.push(String::new());
        lines.push("###".to_string());
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Generate a single request as .http format
pub fn request_to_http(request: &RequestSnapshot, comment: Option<&str>) -> String {
    let mut lines = Vec::new();

    if let Some(c) = comment {
        lines.push(format!("### {c}"));
    }

    lines.push(format!("{} {}", request.method, request.url));

    for (key, value) in &request.headers {
        lines.push(format!("{key}: {value}"));
    }

    if let Some(body) = &request.body {
        lines.push(String::new());
        lines.push(body.clone());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_failure() -> Failure {
        let request = RequestSnapshot {
            method: "POST".to_string(),
            url: "http://localhost:8080/api/users".to_string(),
            headers: HashMap::from([("Authorization".to_string(), "Bearer token".to_string())]),
            body: Some(r#"{"name": "test"}"#.to_string()),
        };

        Failure::from_status("f1", "POST", "/api/users", 500, request)
    }

    #[test]
    fn generates_http_file_header() {
        let failures = vec![sample_failure()];
        let output = to_http_file(&failures, "base_url");

        assert!(output.contains("# Auto-generated reproduction cases (1 failures)"));
        assert!(output.contains("{{base_url}}"));
    }

    #[test]
    fn generates_request_with_method_and_url() {
        let failures = vec![sample_failure()];
        let output = to_http_file(&failures, "base_url");

        assert!(output.contains("POST http://localhost:8080/api/users"));
    }

    #[test]
    fn includes_headers() {
        let failures = vec![sample_failure()];
        let output = to_http_file(&failures, "base_url");

        assert!(output.contains("Authorization: Bearer token"));
    }

    #[test]
    fn includes_body() {
        let failures = vec![sample_failure()];
        let output = to_http_file(&failures, "base_url");

        assert!(output.contains(r#"{"name": "test"}"#));
    }

    #[test]
    fn includes_severity_and_status() {
        let failures = vec![sample_failure()];
        let output = to_http_file(&failures, "base_url");

        assert!(output.contains("critical"));
        assert!(output.contains("500"));
    }

    #[test]
    fn request_to_http_basic() {
        let request = RequestSnapshot {
            method: "GET".to_string(),
            url: "http://localhost/api".to_string(),
            headers: HashMap::new(),
            body: None,
        };

        let output = request_to_http(&request, Some("Test request"));

        assert!(output.contains("### Test request"));
        assert!(output.contains("GET http://localhost/api"));
    }
}
