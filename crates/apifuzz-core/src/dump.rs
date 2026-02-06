//! Full request/response dump to JSONL files
//!
//! Writes all interactions (not just failures) to per-operation JSONL files
//! for post-hoc analysis, debugging, and audit trails.
//!
//! ```text
//! .apifuzz/dumps/
//! ├── GET_health.jsonl
//! ├── POST_api_users.jsonl
//! └── index.json
//! ```

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schema::RawInteraction;

/// Headers that should be masked in dumps for security.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
];

/// Mask value for redacted headers.
const MASK: &str = "***";

/// Summary of a dump operation, written as `index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpIndex {
    /// Total interactions dumped
    pub total: u64,
    /// Per-operation file listing
    pub operations: Vec<DumpOperationEntry>,
    /// Directory where files were written
    pub dump_dir: PathBuf,
}

/// An entry in the dump index for one operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpOperationEntry {
    /// Operation label, e.g. "POST /api/users"
    pub operation: String,
    /// Filename within dump directory
    pub file: String,
    /// Number of interactions in this file
    pub count: u64,
}

/// Write all interactions to per-operation JSONL files.
///
/// Returns the dump index on success, or an error message.
///
/// # Errors
///
/// Returns error if dump directory cannot be created or files cannot be written.
pub fn write_dump(
    interactions: &[RawInteraction],
    dump_dir: &Path,
    mask_headers: bool,
) -> Result<DumpIndex, DumpError> {
    std::fs::create_dir_all(dump_dir)
        .map_err(|e| DumpError::Io(format!("create {}: {e}", dump_dir.display())))?;

    // Group interactions by operation
    let mut groups: HashMap<String, Vec<&RawInteraction>> = HashMap::new();
    for interaction in interactions {
        groups
            .entry(interaction.operation.clone())
            .or_default()
            .push(interaction);
    }

    let mut entries = Vec::new();
    let mut total: u64 = 0;

    // Sort by operation name for deterministic output
    let mut ops: Vec<_> = groups.into_iter().collect();
    ops.sort_by(|a, b| a.0.cmp(&b.0));

    for (operation, interactions) in ops {
        let filename = sanitize_filename(&operation);
        let filepath = dump_dir.join(&filename);

        let file = std::fs::File::create(&filepath)
            .map_err(|e| DumpError::Io(format!("create {}: {e}", filepath.display())))?;
        let mut writer = std::io::BufWriter::new(file);

        let count = interactions.len() as u64;
        total += count;

        for interaction in interactions {
            let line = if mask_headers {
                let masked = mask_interaction(interaction);
                serde_json::to_string(&masked)
            } else {
                serde_json::to_string(interaction)
            }
            .map_err(|e| DumpError::Serialize(e.to_string()))?;
            writer
                .write_all(line.as_bytes())
                .map_err(|e| DumpError::Io(format!("write {}: {e}", filepath.display())))?;
            writer
                .write_all(b"\n")
                .map_err(|e| DumpError::Io(format!("write {}: {e}", filepath.display())))?;
        }

        writer
            .flush()
            .map_err(|e| DumpError::Io(format!("flush {}: {e}", filepath.display())))?;

        entries.push(DumpOperationEntry {
            operation,
            file: filename,
            count,
        });
    }

    let index = DumpIndex {
        total,
        operations: entries,
        dump_dir: dump_dir.to_path_buf(),
    };

    // Write index.json
    let index_path = dump_dir.join("index.json");
    let index_json =
        serde_json::to_string_pretty(&index).map_err(|e| DumpError::Serialize(e.to_string()))?;
    std::fs::write(&index_path, index_json)
        .map_err(|e| DumpError::Io(format!("write {}: {e}", index_path.display())))?;

    Ok(index)
}

/// Maximum characters kept from the operation label in the filename.
/// Prevents PATH_MAX issues on macOS (1024) and Linux (4096).
const MAX_FILENAME_LEN: usize = 200;

/// Convert an operation label to a safe filename.
///
/// "POST /api/v2/users/{id}" → "POST_api_v2_users_id.jsonl"
fn sanitize_filename(operation: &str) -> String {
    let sanitized: String = operation
        .chars()
        .take(MAX_FILENAME_LEN)
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' => c,
            _ => '_',
        })
        .collect();
    format!("{sanitized}.jsonl")
}

/// Returns true if the header name matches a known sensitive header (case-insensitive).
fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|&h| name.eq_ignore_ascii_case(h))
}

/// Mask sensitive headers in an interaction.
fn mask_interaction(interaction: &RawInteraction) -> RawInteraction {
    let mut masked = interaction.clone();
    if let Some(ref mut headers) = masked.case.headers {
        for (key, value) in headers.iter_mut() {
            if is_sensitive_header(key) {
                *value = MASK.to_string();
            }
        }
    }
    masked
}

#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{RawCase, RawResponse};

    fn interaction(operation: &str, status: u16) -> RawInteraction {
        RawInteraction {
            case: RawCase {
                method: "POST".into(),
                path: "/test".into(),
                id: Some("case-001".into()),
                path_parameters: None,
                headers: Some(HashMap::from([
                    ("Authorization".into(), "Bearer secret-token".into()),
                    ("Content-Type".into(), "application/json".into()),
                ])),
                query: None,
                body: Some(serde_json::json!({"key": "value"})),
                media_type: Some("application/json".into()),
            },
            response: RawResponse {
                status_code: status,
                elapsed: 0.05,
                message: "OK".into(),
                content_length: 15,
                body: Some(r#"{"ok":true}"#.into()),
            },
            operation: operation.into(),
            failures: vec![],
        }
    }

    #[test]
    fn sanitize_simple() {
        assert_eq!(sanitize_filename("GET /health"), "GET__health.jsonl");
    }

    #[test]
    fn sanitize_complex_path() {
        assert_eq!(
            sanitize_filename("POST /api/v2/users/{id}"),
            "POST__api_v2_users__id_.jsonl"
        );
    }

    #[test]
    fn mask_authorization_header() {
        let i = interaction("POST /test", 200);
        let masked = mask_interaction(&i);
        let headers = masked.case.headers.unwrap();
        assert_eq!(headers["Authorization"], "***");
        assert_eq!(headers["Content-Type"], "application/json");
    }

    #[test]
    fn mask_case_insensitive() {
        let mut i = interaction("POST /test", 200);
        let headers = i.case.headers.as_mut().unwrap();
        headers.insert("x-api-key".into(), "my-secret".into());
        let masked = mask_interaction(&i);
        let mh = masked.case.headers.unwrap();
        assert_eq!(mh["x-api-key"], "***");
    }

    #[test]
    fn no_mask_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let interactions = vec![interaction("POST /test", 200)];
        let index = write_dump(&interactions, dir.path(), false).unwrap();
        assert_eq!(index.total, 1);

        // Read back and verify header is NOT masked
        let file_path = dir.path().join(&index.operations[0].file);
        let content = std::fs::read_to_string(file_path).unwrap();
        let parsed: RawInteraction = serde_json::from_str(content.trim()).unwrap();
        let headers = parsed.case.headers.unwrap();
        assert_eq!(headers["Authorization"], "Bearer secret-token");
    }

    #[test]
    fn write_dump_basic() {
        let dir = tempfile::tempdir().unwrap();
        let interactions = vec![
            interaction("POST /users", 200),
            interaction("POST /users", 401),
            interaction("GET /health", 200),
        ];

        let index = write_dump(&interactions, dir.path(), true).unwrap();

        assert_eq!(index.total, 3);
        assert_eq!(index.operations.len(), 2);

        // Check operation entries (sorted)
        assert_eq!(index.operations[0].operation, "GET /health");
        assert_eq!(index.operations[0].count, 1);
        assert_eq!(index.operations[1].operation, "POST /users");
        assert_eq!(index.operations[1].count, 2);

        // Check JSONL files exist and have correct line counts
        for entry in &index.operations {
            let path = dir.path().join(&entry.file);
            assert!(path.exists(), "File should exist: {}", entry.file);
            let content = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<_> = content.lines().collect();
            assert_eq!(
                lines.len(),
                entry.count as usize,
                "Line count mismatch for {}",
                entry.file
            );
            // Each line should be valid JSON
            for line in lines {
                let _: RawInteraction = serde_json::from_str(line).unwrap();
            }
        }

        // Check index.json exists
        let index_path = dir.path().join("index.json");
        assert!(index_path.exists());
        let index_content = std::fs::read_to_string(index_path).unwrap();
        let parsed: DumpIndex = serde_json::from_str(&index_content).unwrap();
        assert_eq!(parsed.total, 3);
    }

    #[test]
    fn write_dump_masked_headers() {
        let dir = tempfile::tempdir().unwrap();
        let interactions = vec![interaction("POST /test", 200)];
        write_dump(&interactions, dir.path(), true).unwrap();

        let file_path = dir.path().join("POST__test.jsonl");
        let content = std::fs::read_to_string(file_path).unwrap();
        let parsed: RawInteraction = serde_json::from_str(content.trim()).unwrap();
        let headers = parsed.case.headers.unwrap();
        assert_eq!(headers["Authorization"], "***");
        assert_eq!(headers["Content-Type"], "application/json");
    }

    #[test]
    fn write_dump_empty_interactions() {
        let dir = tempfile::tempdir().unwrap();
        let index = write_dump(&[], dir.path(), true).unwrap();
        assert_eq!(index.total, 0);
        assert!(index.operations.is_empty());
        // index.json should still exist
        assert!(dir.path().join("index.json").exists());
    }
}
