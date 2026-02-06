//! Verdict policy - determines how failures are filtered and judged

use super::{Failure, FailureType, Severity};

/// Policy for filtering and judging failures
#[derive(Debug, Clone)]
pub struct VerdictPolicy {
    /// Strict mode: warnings become errors
    pub strict: bool,
    /// Status codes to ignore
    pub ignore_status_codes: Vec<u16>,
    /// Failure types to ignore
    pub ignore_failure_types: Vec<FailureType>,
    /// Minimum severity to report (below this = ignored)
    pub min_severity: Severity,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            strict: true, // Default is strict - explicit opt-out required
            ignore_status_codes: vec![],
            ignore_failure_types: vec![],
            min_severity: Severity::Warning,
        }
    }
}

impl VerdictPolicy {
    /// Create a lenient policy (warnings don't fail)
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            strict: false,
            ..Default::default()
        }
    }

    /// Filter failures according to policy
    #[must_use]
    pub fn filter(&self, failures: Vec<Failure>) -> Vec<Failure> {
        failures
            .into_iter()
            .filter(|f| self.should_report(f))
            .collect()
    }

    /// Check if a failure should be reported
    fn should_report(&self, failure: &Failure) -> bool {
        // Check ignore lists
        if self.ignore_status_codes.contains(&failure.status_code) {
            return false;
        }
        if self.ignore_failure_types.contains(&failure.failure_type) {
            return false;
        }
        // Check minimum severity
        if failure.severity < self.min_severity {
            return false;
        }
        true
    }

    /// Determine final exit code from failures and request counts.
    ///
    /// Returns the highest exit code among all failures,
    /// or 3 if there were errors (non-success, non-failure requests).
    #[must_use]
    pub fn exit_code(&self, failures: &[Failure], has_errors: bool) -> i32 {
        let failure_code = failures
            .iter()
            .map(|f| f.severity.exit_code(self.strict))
            .max()
            .unwrap_or(0);

        if failure_code > 0 {
            return failure_code;
        }

        // Errors (connection failures, etc.) → exit 3 (tool error)
        if has_errors {
            return 3;
        }

        0
    }

    /// Determine verdict from request counts and classified failures.
    ///
    /// PASS requires **all** requests to be Success.
    /// Any Failure (check violation) or Error (connection/transport) → FAIL.
    #[must_use]
    pub fn verdict(
        &self,
        failures: &[Failure],
        total: u64,
        success: u64,
        error_count: u64,
    ) -> Verdict {
        let has_errors = error_count > 0;
        let exit_code = self.exit_code(failures, has_errors);

        // PASS iff every request succeeded (success == total)
        let status = if success == total && total > 0 {
            VerdictStatus::Pass
        } else {
            VerdictStatus::Fail
        };

        let reason = if status == VerdictStatus::Pass {
            "All requests passed".to_string()
        } else if total == 0 {
            "No requests were made".to_string()
        } else {
            let mut parts = Vec::new();
            if !failures.is_empty() {
                let critical = failures
                    .iter()
                    .filter(|f| f.severity == Severity::Critical)
                    .count();
                let error = failures
                    .iter()
                    .filter(|f| f.severity == Severity::Error)
                    .count();
                let warning = failures
                    .iter()
                    .filter(|f| f.severity == Severity::Warning)
                    .count();
                parts.push(format!(
                    "{} failures ({} critical, {} error, {} warning)",
                    failures.len(),
                    critical,
                    error,
                    warning
                ));
            }
            if has_errors {
                parts.push(format!("{error_count} errors (connection/transport)"));
            }
            parts.join("; ")
        };

        Verdict {
            status,
            exit_code,
            reason,
        }
    }
}

/// Final verdict
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub exit_code: i32,
    pub reason: String,
}

/// Pass or fail
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictStatus {
    Pass,
    Fail,
}

impl std::fmt::Display for VerdictStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::failure::RequestSnapshot;
    use std::collections::HashMap;

    fn sample_request() -> RequestSnapshot {
        RequestSnapshot {
            method: "GET".to_string(),
            url: "http://localhost/api".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    fn critical_failure() -> Failure {
        Failure::from_status("c1", "GET", "/api", 500, sample_request())
    }

    fn warning_failure() -> Failure {
        Failure::from_status("w1", "GET", "/api", 400, sample_request())
            .with_severity(Severity::Warning)
    }

    fn error_failure() -> Failure {
        Failure::from_status("e1", "GET", "/api", 401, sample_request())
    }

    #[test]
    fn default_policy_is_strict() {
        let policy = VerdictPolicy::default();
        assert!(policy.strict);
    }

    // --- exit_code tests ---

    #[test]
    fn exit_code_no_failures_no_errors() {
        let policy = VerdictPolicy::default();
        assert_eq!(policy.exit_code(&[], false), 0);
    }

    #[test]
    fn exit_code_critical_failure() {
        let policy = VerdictPolicy::default();
        assert_eq!(policy.exit_code(&[critical_failure()], false), 2);
    }

    #[test]
    fn exit_code_warning_strict() {
        let policy = VerdictPolicy::default(); // strict=true
        assert_eq!(policy.exit_code(&[warning_failure()], false), 1);
    }

    #[test]
    fn exit_code_warning_lenient() {
        let policy = VerdictPolicy::lenient();
        assert_eq!(policy.exit_code(&[warning_failure()], false), 0);
    }

    #[test]
    fn exit_code_highest_severity_wins() {
        let policy = VerdictPolicy::default();
        let failures = vec![warning_failure(), error_failure(), critical_failure()];
        assert_eq!(policy.exit_code(&failures, false), 2);
    }

    #[test]
    fn exit_code_errors_only_returns_3() {
        let policy = VerdictPolicy::default();
        assert_eq!(policy.exit_code(&[], true), 3);
    }

    #[test]
    fn exit_code_failures_take_precedence_over_errors() {
        let policy = VerdictPolicy::default();
        // critical failure (exit 2) > error (exit 3)? No — failure_code > 0 returns first.
        assert_eq!(policy.exit_code(&[critical_failure()], true), 2);
    }

    // --- filter tests ---

    #[test]
    fn filter_ignores_specified_status_codes() {
        let mut policy = VerdictPolicy::default();
        policy.ignore_status_codes = vec![500];
        assert!(policy.filter(vec![critical_failure()]).is_empty());
    }

    #[test]
    fn filter_ignores_specified_failure_types() {
        let mut policy = VerdictPolicy::default();
        policy.ignore_failure_types = vec![FailureType::ServerError];
        assert!(policy.filter(vec![critical_failure()]).is_empty());
    }

    #[test]
    fn filter_respects_min_severity() {
        let mut policy = VerdictPolicy::default();
        policy.min_severity = Severity::Error;
        assert!(policy.filter(vec![warning_failure()]).is_empty());
    }

    // --- verdict tests (three-state) ---

    #[test]
    fn verdict_all_success_is_pass() {
        let policy = VerdictPolicy::default();
        let v = policy.verdict(&[], 100, 100, 0);
        assert_eq!(v.status, VerdictStatus::Pass);
        assert_eq!(v.exit_code, 0);
        assert_eq!(v.reason, "All requests passed");
    }

    #[test]
    fn verdict_zero_requests_is_fail() {
        let policy = VerdictPolicy::default();
        let v = policy.verdict(&[], 0, 0, 0);
        assert_eq!(v.status, VerdictStatus::Fail);
        assert!(v.reason.contains("No requests were made"));
    }

    #[test]
    fn verdict_all_errors_is_fail() {
        let policy = VerdictPolicy::default();
        // total=100, success=0, errors=100
        let v = policy.verdict(&[], 100, 0, 100);
        assert_eq!(v.status, VerdictStatus::Fail);
        assert_eq!(v.exit_code, 3);
        assert!(v.reason.contains("100 errors"));
    }

    #[test]
    fn verdict_failures_is_fail() {
        let policy = VerdictPolicy::default();
        let failures = vec![critical_failure()];
        // total=10, success=9, errors=0 (1 failed request)
        let v = policy.verdict(&failures, 10, 9, 0);
        assert_eq!(v.status, VerdictStatus::Fail);
        assert_eq!(v.exit_code, 2);
        assert!(v.reason.contains("1 failures"));
        assert!(v.reason.contains("1 critical"));
    }

    #[test]
    fn verdict_mixed_failures_and_errors() {
        let policy = VerdictPolicy::default();
        let failures = vec![error_failure()];
        // total=100, success=50, errors=20 (30 failed requests)
        let v = policy.verdict(&failures, 100, 50, 20);
        assert_eq!(v.status, VerdictStatus::Fail);
        assert!(v.reason.contains("1 failures"));
        assert!(v.reason.contains("20 errors"));
    }

    #[test]
    fn verdict_reason_includes_severity_counts() {
        let policy = VerdictPolicy::default();
        let failures = vec![critical_failure(), warning_failure()];
        let v = policy.verdict(&failures, 10, 8, 0);
        assert!(v.reason.contains("2 failures"));
        assert!(v.reason.contains("1 critical"));
        assert!(v.reason.contains("1 warning"));
    }
}
