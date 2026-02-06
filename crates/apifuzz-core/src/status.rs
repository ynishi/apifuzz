//! Status code distribution analysis and pattern detection
//!
//! Computes per-operation and global status code distributions from fuzz results,
//! then applies the configured [`SuccessCriteria`] to produce warnings or failures.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::SuccessCriteria;
use crate::schema::RawInteraction;

// ── Data types ──

/// Per-operation status code statistics.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationStats {
    /// Operation label, e.g. "POST /api/users"
    pub operation: String,
    /// Total requests sent for this operation
    pub total: u64,
    /// Status code → count
    pub status_distribution: HashMap<u16, u64>,
    /// Fraction of 2xx responses (0.0–1.0)
    pub success_rate: f64,
}

/// Kind of issue detected from status code patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StatusWarningKind {
    /// All (or nearly all) responses are 401/403
    AuthenticationIssue,
    /// All (or nearly all) responses are 429
    RateLimited,
    /// All (or nearly all) responses are 404
    EndpointNotFound,
    /// Zero 2xx responses (no specific pattern detected)
    NoSuccessfulResponses,
    /// 2xx rate below configured threshold (require_2xx mode)
    LowSuccessRate,
}

impl StatusWarningKind {
    /// Whether this warning should be treated as a failure under strict mode.
    #[must_use]
    pub const fn is_failure_in_require_2xx(self) -> bool {
        matches!(
            self,
            Self::AuthenticationIssue
                | Self::RateLimited
                | Self::EndpointNotFound
                | Self::NoSuccessfulResponses
                | Self::LowSuccessRate
        )
    }
}

impl std::fmt::Display for StatusWarningKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationIssue => write!(f, "authentication may be invalid"),
            Self::RateLimited => write!(f, "rate limited — consider adding delay"),
            Self::EndpointNotFound => {
                write!(f, "endpoint not found — check base_url or spec paths")
            }
            Self::NoSuccessfulResponses => write!(f, "no successful responses"),
            Self::LowSuccessRate => write!(f, "success rate below threshold"),
        }
    }
}

/// A warning about a specific operation's status code pattern.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StatusWarning {
    /// Operation label
    pub operation: String,
    /// What kind of issue was detected
    pub kind: StatusWarningKind,
    /// Human-readable message
    pub message: String,
    /// Whether this should be treated as a failure (depends on criteria)
    pub is_failure: bool,
}

/// Global summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GlobalStats {
    pub total: u64,
    pub status_distribution: HashMap<u16, u64>,
    pub success_rate: f64,
}

/// Complete status analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StatusAnalysis {
    /// Per-operation statistics
    pub operations: Vec<OperationStats>,
    /// Global aggregated statistics
    pub global: GlobalStats,
    /// Warnings and failures detected from patterns
    pub warnings: Vec<StatusWarning>,
}

// ── Computation ──

/// Compute per-operation status code statistics from raw interactions.
#[must_use]
pub fn compute_operation_stats(interactions: &[RawInteraction]) -> Vec<OperationStats> {
    // Group by operation label
    let mut groups: HashMap<String, HashMap<u16, u64>> = HashMap::new();
    for interaction in interactions {
        let entry = groups.entry(interaction.operation.clone()).or_default();
        *entry.entry(interaction.response.status_code).or_default() += 1;
    }

    let mut stats: Vec<OperationStats> = groups
        .into_iter()
        .map(|(operation, dist)| {
            let total: u64 = dist.values().sum();
            let success_count: u64 = dist
                .iter()
                .filter(|&(&code, _)| (200..300).contains(&code))
                .map(|(_, &count)| count)
                .sum();
            let success_rate = if total > 0 {
                success_count as f64 / total as f64
            } else {
                0.0
            };
            OperationStats {
                operation,
                total,
                status_distribution: dist,
                success_rate,
            }
        })
        .collect();

    // Stable ordering for deterministic output
    stats.sort_by(|a, b| a.operation.cmp(&b.operation));
    stats
}

/// Compute global aggregated stats from per-operation stats.
#[must_use]
pub fn compute_global_stats(op_stats: &[OperationStats]) -> GlobalStats {
    let mut dist: HashMap<u16, u64> = HashMap::new();
    let mut total: u64 = 0;

    for op in op_stats {
        total += op.total;
        for (&code, &count) in &op.status_distribution {
            *dist.entry(code).or_default() += count;
        }
    }

    let success_count: u64 = dist
        .iter()
        .filter(|&(&code, _)| (200..300).contains(&code))
        .map(|(_, &count)| count)
        .sum();
    let success_rate = if total > 0 {
        success_count as f64 / total as f64
    } else {
        0.0
    };

    GlobalStats {
        total,
        status_distribution: dist,
        success_rate,
    }
}

// ── Pattern detection ──

/// Detect the dominant status code pattern for an operation.
///
/// Returns `Some(kind)` if ≥90% of responses share a recognizable pattern.
fn detect_pattern(stats: &OperationStats) -> Option<StatusWarningKind> {
    if stats.total == 0 {
        return None;
    }

    // Check if a single status class dominates (≥90%)
    let threshold = (stats.total as f64 * 0.9).ceil() as u64;

    let auth_count: u64 = stats
        .status_distribution
        .iter()
        .filter(|&(&code, _)| code == 401 || code == 403)
        .map(|(_, &c)| c)
        .sum();
    if auth_count >= threshold {
        return Some(StatusWarningKind::AuthenticationIssue);
    }

    let rate_limit_count: u64 = stats.status_distribution.get(&429).copied().unwrap_or(0);
    if rate_limit_count >= threshold {
        return Some(StatusWarningKind::RateLimited);
    }

    let not_found_count: u64 = stats.status_distribution.get(&404).copied().unwrap_or(0);
    if not_found_count >= threshold {
        return Some(StatusWarningKind::EndpointNotFound);
    }

    // No specific pattern, but no 2xx at all
    if stats.success_rate == 0.0 {
        return Some(StatusWarningKind::NoSuccessfulResponses);
    }

    None
}

// ── Main analysis entry point ──

/// Analyze status code distributions and produce warnings/failures.
///
/// This is the main entry point. It computes stats, detects patterns,
/// and applies the configured success criteria to determine severity.
#[must_use]
pub fn analyze(
    interactions: &[RawInteraction],
    criteria: SuccessCriteria,
    min_success_rate: Option<f64>,
) -> StatusAnalysis {
    let operations = compute_operation_stats(interactions);
    let global = compute_global_stats(&operations);
    let mut warnings = Vec::new();

    let effective_min_rate = min_success_rate.unwrap_or(0.1);

    for op in &operations {
        match criteria {
            SuccessCriteria::AnyResponse => {
                // Record stats only — no warnings
            }
            SuccessCriteria::Default => {
                if let Some(kind) = detect_pattern(op) {
                    warnings.push(StatusWarning {
                        operation: op.operation.clone(),
                        kind,
                        message: format!(
                            "{}: {} ({}% 2xx, {}/{})",
                            op.operation,
                            kind,
                            format_pct(op.success_rate),
                            count_2xx(op),
                            op.total,
                        ),
                        is_failure: false, // warnings only in default mode
                    });
                }
            }
            SuccessCriteria::Require2xx => {
                // First check for specific patterns
                if let Some(kind) = detect_pattern(op) {
                    warnings.push(StatusWarning {
                        operation: op.operation.clone(),
                        kind,
                        message: format!(
                            "{}: {} ({}% 2xx, {}/{})",
                            op.operation,
                            kind,
                            format_pct(op.success_rate),
                            count_2xx(op),
                            op.total,
                        ),
                        is_failure: true,
                    });
                } else if op.success_rate < effective_min_rate {
                    // Below threshold but no specific pattern
                    warnings.push(StatusWarning {
                        operation: op.operation.clone(),
                        kind: StatusWarningKind::LowSuccessRate,
                        message: format!(
                            "{}: success rate {}% below threshold {}% ({}/{})",
                            op.operation,
                            format_pct(op.success_rate),
                            format_pct(effective_min_rate),
                            count_2xx(op),
                            op.total,
                        ),
                        is_failure: true,
                    });
                }
            }
        }
    }

    StatusAnalysis {
        operations,
        global,
        warnings,
    }
}

fn count_2xx(op: &OperationStats) -> u64 {
    op.status_distribution
        .iter()
        .filter(|&(&code, _)| (200..300).contains(&code))
        .map(|(_, &c)| c)
        .sum()
}

fn format_pct(rate: f64) -> String {
    let pct = rate * 100.0;
    if pct == 0.0 || pct == 100.0 {
        format!("{pct:.0}")
    } else {
        format!("{pct:.1}")
    }
}

/// Format status distribution as a compact string: "200x50, 401x10, 500x2"
pub fn format_distribution(dist: &HashMap<u16, u64>) -> String {
    let mut entries: Vec<(u16, u64)> = dist.iter().map(|(&k, &v)| (k, v)).collect();
    entries.sort_by_key(|(code, _)| *code);
    entries
        .iter()
        .map(|(code, count)| format!("{code}x{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{RawCase, RawInteraction, RawResponse};

    fn interaction(operation: &str, status: u16) -> RawInteraction {
        RawInteraction {
            case: RawCase {
                method: "POST".into(),
                path: "/test".into(),
                id: None,
                path_parameters: None,
                headers: None,
                query: None,
                body: None,
                media_type: None,
            },
            response: RawResponse {
                status_code: status,
                elapsed: 0.05,
                message: String::new(),
                content_length: 0,
                body: None,
            },
            operation: operation.into(),
            failures: vec![],
        }
    }

    fn interactions_uniform(op: &str, status: u16, count: usize) -> Vec<RawInteraction> {
        (0..count).map(|_| interaction(op, status)).collect()
    }

    fn interactions_mixed(op: &str, statuses: &[(u16, usize)]) -> Vec<RawInteraction> {
        statuses
            .iter()
            .flat_map(|&(status, count)| (0..count).map(move |_| interaction(op, status)))
            .collect()
    }

    // ── compute_operation_stats ──

    #[test]
    fn stats_single_operation() {
        let data = interactions_mixed("POST /users", &[(200, 8), (401, 2)]);
        let stats = compute_operation_stats(&data);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].total, 10);
        assert!((stats[0].success_rate - 0.8).abs() < 0.01);
        assert_eq!(stats[0].status_distribution[&200], 8);
        assert_eq!(stats[0].status_distribution[&401], 2);
    }

    #[test]
    fn stats_multiple_operations() {
        let mut data = interactions_uniform("GET /health", 200, 5);
        data.extend(interactions_uniform("POST /users", 500, 3));
        let stats = compute_operation_stats(&data);
        assert_eq!(stats.len(), 2);

        let health = stats.iter().find(|s| s.operation == "GET /health").unwrap();
        assert_eq!(health.total, 5);
        assert!((health.success_rate - 1.0).abs() < 0.01);

        let users = stats.iter().find(|s| s.operation == "POST /users").unwrap();
        assert_eq!(users.total, 3);
        assert!((users.success_rate - 0.0).abs() < 0.01);
    }

    #[test]
    fn stats_empty_interactions() {
        let stats = compute_operation_stats(&[]);
        assert!(stats.is_empty());
    }

    // ── compute_global_stats ──

    #[test]
    fn global_stats_aggregation() {
        let data = interactions_mixed("POST /users", &[(200, 7), (401, 3)]);
        let op_stats = compute_operation_stats(&data);
        let global = compute_global_stats(&op_stats);
        assert_eq!(global.total, 10);
        assert!((global.success_rate - 0.7).abs() < 0.01);
    }

    // ── detect_pattern ──

    #[test]
    fn detect_auth_pattern() {
        let data = interactions_uniform("POST /api", 401, 100);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(
            detect_pattern(stats),
            Some(StatusWarningKind::AuthenticationIssue)
        );
    }

    #[test]
    fn detect_auth_pattern_403() {
        let data = interactions_uniform("POST /api", 403, 50);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(
            detect_pattern(stats),
            Some(StatusWarningKind::AuthenticationIssue)
        );
    }

    #[test]
    fn detect_auth_mixed_401_403() {
        let data = interactions_mixed("POST /api", &[(401, 45), (403, 50), (200, 5)]);
        let stats = &compute_operation_stats(&data)[0];
        // 95/100 = 95% are auth → should detect
        assert_eq!(
            detect_pattern(stats),
            Some(StatusWarningKind::AuthenticationIssue)
        );
    }

    #[test]
    fn detect_rate_limit_pattern() {
        let data = interactions_uniform("POST /api", 429, 100);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(detect_pattern(stats), Some(StatusWarningKind::RateLimited));
    }

    #[test]
    fn detect_not_found_pattern() {
        let data = interactions_uniform("GET /missing", 404, 100);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(
            detect_pattern(stats),
            Some(StatusWarningKind::EndpointNotFound)
        );
    }

    #[test]
    fn detect_no_success_generic() {
        // All 422 — no specific pattern, but 0% 2xx
        let data = interactions_uniform("POST /api", 422, 100);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(
            detect_pattern(stats),
            Some(StatusWarningKind::NoSuccessfulResponses)
        );
    }

    #[test]
    fn detect_no_pattern_healthy() {
        let data = interactions_mixed("POST /api", &[(200, 80), (400, 20)]);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(detect_pattern(stats), None);
    }

    #[test]
    fn detect_below_threshold_no_pattern() {
        // 80% are 401 — below 90% threshold
        let data = interactions_mixed("POST /api", &[(401, 80), (200, 20)]);
        let stats = &compute_operation_stats(&data)[0];
        assert_eq!(detect_pattern(stats), None);
    }

    // ── analyze: Default criteria ──

    #[test]
    fn analyze_default_all_401_warns() {
        let data = interactions_uniform("POST /api", 401, 100);
        let result = analyze(&data, SuccessCriteria::Default, None);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].kind,
            StatusWarningKind::AuthenticationIssue
        );
        assert!(!result.warnings[0].is_failure);
    }

    #[test]
    fn analyze_default_healthy_no_warnings() {
        let data = interactions_mixed("POST /api", &[(200, 80), (400, 20)]);
        let result = analyze(&data, SuccessCriteria::Default, None);
        assert!(result.warnings.is_empty());
    }

    // ── analyze: Require2xx criteria ──

    #[test]
    fn analyze_require2xx_all_401_is_failure() {
        let data = interactions_uniform("POST /api", 401, 100);
        let result = analyze(&data, SuccessCriteria::Require2xx, Some(0.1));
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].kind,
            StatusWarningKind::AuthenticationIssue
        );
        assert!(result.warnings[0].is_failure);
    }

    #[test]
    fn analyze_require2xx_low_rate_is_failure() {
        let data = interactions_mixed("POST /api", &[(200, 5), (400, 95)]);
        let result = analyze(&data, SuccessCriteria::Require2xx, Some(0.1));
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].kind, StatusWarningKind::LowSuccessRate);
        assert!(result.warnings[0].is_failure);
    }

    #[test]
    fn analyze_require2xx_above_threshold_ok() {
        let data = interactions_mixed("POST /api", &[(200, 50), (400, 50)]);
        let result = analyze(&data, SuccessCriteria::Require2xx, Some(0.1));
        assert!(result.warnings.is_empty());
    }

    // ── analyze: AnyResponse criteria ──

    #[test]
    fn analyze_any_response_never_warns() {
        let data = interactions_uniform("POST /api", 401, 100);
        let result = analyze(&data, SuccessCriteria::AnyResponse, None);
        assert!(result.warnings.is_empty());
        // But stats are still computed
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.global.total, 100);
    }

    // ── format helpers ──

    #[test]
    fn format_distribution_sorted() {
        let mut dist = HashMap::new();
        dist.insert(500, 2);
        dist.insert(200, 50);
        dist.insert(401, 10);
        assert_eq!(format_distribution(&dist), "200x50, 401x10, 500x2");
    }

    #[test]
    fn format_pct_edge_cases() {
        assert_eq!(format_pct(0.0), "0");
        assert_eq!(format_pct(1.0), "100");
        assert_eq!(format_pct(0.5), "50.0");
        assert_eq!(format_pct(0.123), "12.3");
    }

    // ── multi-operation analysis ──

    #[test]
    fn analyze_multi_operation_mixed() {
        let mut data = interactions_uniform("GET /health", 200, 50);
        data.extend(interactions_uniform("POST /api", 401, 100));
        let result = analyze(&data, SuccessCriteria::Default, None);

        // Only POST /api should warn
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].operation, "POST /api");

        // Global stats cover both
        assert_eq!(result.global.total, 150);
        assert!((result.global.success_rate - 50.0 / 150.0).abs() < 0.01);
    }
}
