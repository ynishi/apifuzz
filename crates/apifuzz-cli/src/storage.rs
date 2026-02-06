//! Persistent report storage — `~/.apifuzz/reports/`
//!
//! Every `apifuzz fuzz` run is automatically saved regardless of `--output` mode.
//! Directory layout: `{host_port}_{timestamp}_{level}/`

use std::path::PathBuf;
use std::time::SystemTime;

use apifuzz_core::schema::SchemathesisOutput;
use apifuzz_core::{Config, Failure, VerdictStatus};

/// Everything needed to persist a fuzz session.
pub struct ReportData<'a> {
    pub config: &'a Config,
    pub output: &'a SchemathesisOutput,
    pub failures: &'a [Failure],
    pub verdict_status: VerdictStatus,
    pub verdict_exit_code: i32,
    pub verdict_reason: &'a str,
    pub level: &'a str,
    pub duration_secs: f64,
}

/// Save a fuzz report to `~/.apifuzz/reports/{host_port}_{timestamp}_{level}/`.
///
/// Returns the report directory path on success.
pub fn save_report(data: &ReportData) -> Result<PathBuf, std::io::Error> {
    let base = report_base_dir()?;
    let dir_name = build_dir_name(&data.config.base_url, data.level);
    let report_dir = base.join(&dir_name);
    std::fs::create_dir_all(&report_dir)?;

    // config.toml — snapshot of the config used
    let config_toml =
        toml::to_string_pretty(data.config).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(report_dir.join("config.toml"), config_toml)?;

    // summary.json — verdict + stats + metadata
    let summary = serde_json::json!({
        "verdict": {
            "status": format!("{}", data.verdict_status),
            "exit_code": data.verdict_exit_code,
            "reason": data.verdict_reason,
        },
        "stats": {
            "total": data.output.total,
            "success": data.output.success,
            "failure": data.output.total.saturating_sub(data.output.success).saturating_sub(data.output.errors.len() as u64),
            "error": data.output.errors.len(),
        },
        "meta": {
            "timestamp": timestamp_iso(),
            "level": data.level,
            "duration_secs": data.duration_secs,
            "base_url": data.config.base_url,
            "spec": data.config.spec.display().to_string(),
        },
    });
    std::fs::write(
        report_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).unwrap_or_default(),
    )?;

    // failures.json — classified failures (only if present)
    if !data.failures.is_empty() {
        std::fs::write(
            report_dir.join("failures.json"),
            serde_json::to_string_pretty(data.failures).unwrap_or_default(),
        )?;
    }

    // reproductions.http — for quick replay in IDE/curl
    if !data.failures.is_empty() {
        let http_content = apifuzz_core::to_http_file(data.failures, "base_url");
        std::fs::write(report_dir.join("reproductions.http"), http_content)?;
    }

    Ok(report_dir)
}

fn report_base_dir() -> Result<PathBuf, std::io::Error> {
    let home = std::env::var("HOME")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME not set"))?;
    Ok(PathBuf::from(home).join(".apifuzz").join("reports"))
}

/// `{host_port}_{timestamp}_{level}` e.g. `localhost_8080_20260205T193000_quick`
fn build_dir_name(base_url: &str, level: &str) -> String {
    let host_port = extract_host_port(base_url);
    let ts = timestamp_compact();
    format!("{host_port}_{ts}_{level}")
}

/// `"http://localhost:8080/path"` → `"localhost_8080"`
fn extract_host_port(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("unknown")
        .replace(':', "_")
}

/// `"20260205T193000"` — filesystem-safe compact timestamp.
fn timestamp_compact() -> String {
    let (y, mo, d, h, mi, s) = utc_now();
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}")
}

/// `"2026-02-05T19:30:00Z"` — ISO 8601 for JSON.
fn timestamp_iso() -> String {
    let (y, mo, d, h, mi, s) = utc_now();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Current UTC date-time from epoch. No external crate needed.
fn utc_now() -> (i32, u32, u32, u32, u32, u32) {
    let epoch_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (epoch_secs / 86400) as i64;
    let tod = epoch_secs % 86400;
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (tod / 3600) as u32,
        ((tod % 3600) / 60) as u32,
        (tod % 60) as u32,
    )
}

/// Howard Hinnant's `civil_from_days` — epoch days → (year, month, day).
///
/// Reference: <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_port_standard() {
        assert_eq!(extract_host_port("http://localhost:8080"), "localhost_8080");
        assert_eq!(
            extract_host_port("https://api.example.com"),
            "api.example.com"
        );
        assert_eq!(
            extract_host_port("http://10.0.0.1:3000/v1"),
            "10.0.0.1_3000"
        );
    }

    #[test]
    fn civil_from_days_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_date() {
        // 2026-02-05 = day 20489 from epoch
        assert_eq!(civil_from_days(20_489), (2026, 2, 5));
    }

    #[test]
    fn dir_name_format() {
        let name = build_dir_name("http://localhost:8080", "quick");
        assert!(name.starts_with("localhost_8080_"));
        assert!(name.ends_with("_quick"));
    }
}
