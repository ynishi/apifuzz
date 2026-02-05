//! Severity levels for API failures
//!
//! Severity directly determines exit codes - this is the core of "no false OK"

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Failure severity - maps directly to exit codes
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational (exit 0)
    Info,
    /// Warning: spec violation but server works (exit 0, or 1 if --strict)
    Warning,
    /// Error: unexpected 4xx (exit 1)
    Error,
    /// Critical: 5xx, crash, timeout (exit 2)
    Critical,
}

impl Severity {
    /// Convert severity to exit code
    ///
    /// - strict=true: Warning becomes exit 1
    /// - strict=false: Warning is exit 0
    #[must_use]
    pub const fn exit_code(self, strict: bool) -> i32 {
        match self {
            Self::Info => 0,
            Self::Warning => {
                if strict {
                    1
                } else {
                    0
                }
            }
            Self::Error => 1,
            Self::Critical => 2,
        }
    }

    /// Human-readable label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_info_always_zero() {
        assert_eq!(Severity::Info.exit_code(true), 0);
        assert_eq!(Severity::Info.exit_code(false), 0);
    }

    #[test]
    fn exit_code_warning_depends_on_strict() {
        assert_eq!(Severity::Warning.exit_code(false), 0);
        assert_eq!(Severity::Warning.exit_code(true), 1);
    }

    #[test]
    fn exit_code_error_always_one() {
        assert_eq!(Severity::Error.exit_code(true), 1);
        assert_eq!(Severity::Error.exit_code(false), 1);
    }

    #[test]
    fn exit_code_critical_always_two() {
        assert_eq!(Severity::Critical.exit_code(true), 2);
        assert_eq!(Severity::Critical.exit_code(false), 2);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn severity_serialization() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");

        let parsed: Severity = serde_json::from_str("\"warning\"").unwrap();
        assert_eq!(parsed, Severity::Warning);
    }
}
