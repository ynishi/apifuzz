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

    /// Determine final exit code from failures
    ///
    /// Returns the highest exit code among all failures
    #[must_use]
    pub fn exit_code(&self, failures: &[Failure]) -> i32 {
        if failures.is_empty() {
            return 0;
        }

        failures
            .iter()
            .map(|f| f.severity.exit_code(self.strict))
            .max()
            .unwrap_or(0)
    }

    /// Determine verdict status
    #[must_use]
    pub fn verdict(&self, failures: &[Failure]) -> Verdict {
        let exit_code = self.exit_code(failures);
        let status = if exit_code == 0 {
            VerdictStatus::Pass
        } else {
            VerdictStatus::Fail
        };

        let reason = if failures.is_empty() {
            "No failures detected".to_string()
        } else {
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

            format!(
                "{} failures: {} critical, {} error, {} warning",
                failures.len(),
                critical,
                error,
                warning
            )
        };

        Verdict {
            status,
            exit_code,
            reason,
        }
    }

    /// Determine verdict with additional context from the runner.
    ///
    /// This is the preferred method when runner metadata is available.
    /// It catches cases where Schemathesis itself failed (exit_code != 0)
    /// but no failures were parsed, or no requests were made at all.
    ///
    /// Returns exit code 3 for tool errors (distinct from test failures).
    #[must_use]
    pub fn verdict_with_context(
        &self,
        failures: &[Failure],
        total_requests: u64,
        schemathesis_exit_code: i32,
    ) -> Verdict {
        // Safety: no requests made at all → tool error
        if total_requests == 0 {
            return Verdict {
                status: VerdictStatus::Fail,
                exit_code: 3,
                reason: format!(
                    "No requests were made. Schemathesis may have failed to start (exit code: {}).",
                    schemathesis_exit_code
                ),
            };
        }

        // Safety: Schemathesis failed but no parsed failures
        if schemathesis_exit_code != 0 && failures.is_empty() {
            return Verdict {
                status: VerdictStatus::Fail,
                exit_code: 3,
                reason: format!(
                    "Schemathesis exited with code {} but no failures were parsed. Check cassette manually.",
                    schemathesis_exit_code
                ),
            };
        }

        // Normal verdict path
        self.verdict(failures)
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

    #[test]
    fn empty_failures_returns_pass() {
        let policy = VerdictPolicy::default();
        let verdict = policy.verdict(&[]);

        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.exit_code, 0);
    }

    #[test]
    fn critical_failure_returns_exit_2() {
        let policy = VerdictPolicy::default();
        let failures = vec![critical_failure()];

        assert_eq!(policy.exit_code(&failures), 2);
    }

    #[test]
    fn warning_in_strict_mode_returns_exit_1() {
        let policy = VerdictPolicy::default(); // strict=true
        let failures = vec![warning_failure()];

        assert_eq!(policy.exit_code(&failures), 1);
    }

    #[test]
    fn warning_in_lenient_mode_returns_exit_0() {
        let policy = VerdictPolicy::lenient();
        let failures = vec![warning_failure()];

        assert_eq!(policy.exit_code(&failures), 0);
    }

    #[test]
    fn highest_severity_wins() {
        let policy = VerdictPolicy::default();
        let failures = vec![warning_failure(), error_failure(), critical_failure()];

        // Critical (exit 2) should win over Error (1) and Warning (1)
        assert_eq!(policy.exit_code(&failures), 2);
    }

    #[test]
    fn filter_ignores_specified_status_codes() {
        let mut policy = VerdictPolicy::default();
        policy.ignore_status_codes = vec![500];

        let failures = vec![critical_failure()]; // status 500
        let filtered = policy.filter(failures);

        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_ignores_specified_failure_types() {
        let mut policy = VerdictPolicy::default();
        policy.ignore_failure_types = vec![FailureType::ServerError];

        let failures = vec![critical_failure()]; // ServerError
        let filtered = policy.filter(failures);

        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_respects_min_severity() {
        let mut policy = VerdictPolicy::default();
        policy.min_severity = Severity::Error;

        let failures = vec![warning_failure()]; // Severity::Warning < Error
        let filtered = policy.filter(failures);

        assert!(filtered.is_empty());
    }

    #[test]
    fn verdict_fail_on_any_error() {
        let policy = VerdictPolicy::default();
        let failures = vec![error_failure()];
        let verdict = policy.verdict(&failures);

        assert_eq!(verdict.status, VerdictStatus::Fail);
    }

    #[test]
    fn verdict_reason_includes_counts() {
        let policy = VerdictPolicy::default();
        let failures = vec![critical_failure(), warning_failure()];
        let verdict = policy.verdict(&failures);

        assert!(verdict.reason.contains("2 failures"));
        assert!(verdict.reason.contains("1 critical"));
        assert!(verdict.reason.contains("1 warning"));
    }

    #[test]
    fn verdict_with_context_zero_requests_returns_exit_3() {
        let policy = VerdictPolicy::default();
        let verdict = policy.verdict_with_context(&[], 0, 1);

        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.exit_code, 3);
        assert!(verdict.reason.contains("No requests were made"));
    }

    #[test]
    fn verdict_with_context_exit_nonzero_no_failures_returns_exit_3() {
        let policy = VerdictPolicy::default();
        let verdict = policy.verdict_with_context(&[], 100, 1);

        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.exit_code, 3);
        assert!(verdict.reason.contains("no failures were parsed"));
    }

    #[test]
    fn verdict_with_context_normal_pass() {
        let policy = VerdictPolicy::default();
        let verdict = policy.verdict_with_context(&[], 100, 0);

        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.exit_code, 0);
    }

    #[test]
    fn verdict_with_context_normal_fail() {
        let policy = VerdictPolicy::default();
        let failures = vec![critical_failure()];
        let verdict = policy.verdict_with_context(&failures, 100, 1);

        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.exit_code, 2);
    }
}
