//! Status code distribution statistics
//!
//! Computes per-operation and global status code distributions from fuzz results.
//! Pure statistics — no verdict logic. Individual status expectations are now
//! handled by `StatusSatisfyExpectation` checks in the runner.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

// ── Computation ──

/// Compute status code statistics from raw interactions.
#[must_use]
pub fn analyze(interactions: &[RawInteraction]) -> StatusAnalysis {
    let operations = compute_operation_stats(interactions);
    let global = compute_global_stats(&operations);
    StatusAnalysis { operations, global }
}

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

// ── Format helpers ──

/// Format a rate (0.0–1.0) as a percentage string.
///
/// Returns "0" for 0.0, "100" for 1.0, and one decimal place otherwise.
pub fn format_pct(rate: f64) -> String {
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

    // ── analyze ──

    #[test]
    fn analyze_returns_stats() {
        let data = interactions_mixed("POST /api", &[(200, 80), (400, 20)]);
        let result = analyze(&data);
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.global.total, 100);
        assert!((result.global.success_rate - 0.8).abs() < 0.01);
    }

    #[test]
    fn analyze_multi_operation() {
        let mut data = interactions_uniform("GET /health", 200, 50);
        data.extend(interactions_uniform("POST /api", 401, 100));
        let result = analyze(&data);

        assert_eq!(result.operations.len(), 2);
        assert_eq!(result.global.total, 150);
        assert!((result.global.success_rate - 50.0 / 150.0).abs() < 0.01);
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
}
