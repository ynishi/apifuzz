//! Project configuration for API fuzzing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Project configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// OpenAPI spec path (local file)
    pub spec: PathBuf,

    /// Base URL of the server to test
    pub base_url: String,

    /// HTTP headers (Auth, API keys, etc.)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Path parameters (entity IDs, etc.)
    #[serde(default)]
    pub path_params: HashMap<String, String>,

    /// Custom probe values for known bug patterns
    #[serde(default)]
    pub probes: Vec<Probe>,

    /// Response time limit in seconds (optional, disabled by default)
    #[serde(default)]
    pub response_time_limit: Option<f64>,

    /// Dump all request/response pairs to JSONL files
    #[serde(default)]
    pub dump: bool,

    /// Directory for dump files (default: ".apifuzz/dumps")
    #[serde(default)]
    pub dump_dir: Option<PathBuf>,
}

/// A custom probe: inject specific values into a parameter or body property.
///
/// Values are grouped by JSON type to satisfy TOML's same-type array constraint.
///
/// ```toml
/// [[probes]]
/// operation = "POST /orders"
/// target = "quantity"
/// int = [0, -1, 999999]
/// null = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    /// Operation to match, e.g. "POST /orders", "GET /compute/{value}"
    pub operation: String,

    /// Parameter name or body property name to override
    pub target: String,

    /// Integer values to inject
    #[serde(default)]
    pub int: Vec<i64>,

    /// Float values to inject
    #[serde(default)]
    pub float: Vec<f64>,

    /// String values to inject
    #[serde(default)]
    pub string: Vec<String>,

    /// Boolean values to inject
    #[serde(default, rename = "bool")]
    pub bools: Vec<bool>,

    /// Whether to inject null
    #[serde(default)]
    pub null: bool,
}

impl Probe {
    /// Convert all probe values to `serde_json::Value` list.
    pub fn to_json_values(&self) -> Vec<serde_json::Value> {
        let mut values = Vec::new();
        for &v in &self.int {
            values.push(serde_json::Value::Number(v.into()));
        }
        for &v in &self.float {
            if let Some(n) = serde_json::Number::from_f64(v) {
                values.push(serde_json::Value::Number(n));
            }
        }
        for v in &self.string {
            values.push(serde_json::Value::String(v.clone()));
        }
        for &v in &self.bools {
            values.push(serde_json::Value::Bool(v));
        }
        if self.null {
            values.push(serde_json::Value::Null);
        }
        values
    }

    /// Check if this probe matches the given operation label (e.g. "POST /orders").
    pub fn matches_operation(&self, method: &str, path: &str) -> bool {
        let label = format!("{} {}", method, path);
        self.operation == label
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            spec: PathBuf::from("openapi.yaml"),
            base_url: "http://localhost:8080".to_string(),
            headers: HashMap::new(),
            path_params: HashMap::new(),
            probes: Vec::new(),
            response_time_limit: None,
            dump: false,
            dump_dir: None,
        }
    }
}

impl Config {
    /// Load config from file
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.to_path_buf(), e.to_string()))?;

        if path.extension().is_some_and(|ext| ext == "json") {
            serde_json::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))
        } else {
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))
        }
    }

    /// Load from default location (.apifuzz.toml)
    pub fn load_default() -> Result<Self, ConfigError> {
        let candidates = [".apifuzz.toml", ".apifuzz.json", "apifuzz.toml"];

        for name in candidates {
            let path = Path::new(name);
            if path.exists() {
                return Self::load(path);
            }
        }

        // No config file, return default
        Ok(Self::default())
    }

    /// Create example config file
    pub fn example() -> &'static str {
        r#"# apifuzz configuration

# OpenAPI spec (local file path)
spec = "openapi.yaml"

# Server to test
base_url = "http://localhost:8080"

# HTTP headers (auth, api keys)
[headers]
Authorization = "Bearer your-token-here"
# X-API-Key = "your-api-key"

# Path parameters (entity IDs for testing)
[path_params]
user_id = "1"
# order_id = "100"

# Custom probes: inject known-buggy values (highest priority, runs first)
# [[probes]]
# operation = "POST /orders"
# target = "quantity"
# int = [0, -1, 999999]
#
# [[probes]]
# operation = "GET /search"
# target = "limit"
# int = [0, 1001, 99999]
# null = true

# Response time limit in seconds (disabled by default)
# response_time_limit = 5.0

# Dump all request/response pairs to JSONL files (default: false)
# dump = true
# dump_dir = ".apifuzz/dumps"
"#
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Cannot read {0}: {1}")]
    Io(PathBuf, String),
    #[error("Parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.base_url, "http://localhost:8080");
        assert_eq!(config.spec, PathBuf::from("openapi.yaml"));
    }

    #[test]
    fn parse_toml() {
        let toml = r#"
spec = "api.yaml"
base_url = "http://localhost:3000"

[headers]
Authorization = "Bearer token123"

[path_params]
user_id = "42"
"#;
        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.spec, PathBuf::from("api.yaml"));
        assert_eq!(config.base_url, "http://localhost:3000");
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(config.path_params.get("user_id"), Some(&"42".to_string()));
        assert!(config.probes.is_empty());
    }

    #[test]
    fn parse_toml_with_probes() {
        let toml = r#"
spec = "api.yaml"
base_url = "http://localhost:3000"

[[probes]]
operation = "POST /orders"
target = "quantity"
int = [0, -1, 999999]

[[probes]]
operation = "GET /search"
target = "limit"
int = [0, 1001]
null = true

[[probes]]
operation = "POST /users"
target = "name"
string = ["", "a"]
bool = [true]
"#;
        let config: Config = toml::from_str(toml).unwrap();

        assert_eq!(config.probes.len(), 3);

        let p0 = &config.probes[0];
        assert_eq!(p0.operation, "POST /orders");
        assert_eq!(p0.target, "quantity");
        assert_eq!(p0.int, vec![0, -1, 999999]);
        assert!(!p0.null);

        let p1 = &config.probes[1];
        assert_eq!(p1.operation, "GET /search");
        assert_eq!(p1.target, "limit");
        assert_eq!(p1.int, vec![0, 1001]);
        assert!(p1.null);

        let p2 = &config.probes[2];
        assert_eq!(p2.operation, "POST /users");
        assert_eq!(p2.target, "name");
        assert_eq!(p2.string, vec!["", "a"]);
        assert_eq!(p2.bools, vec![true]);
    }

    #[test]
    fn probe_to_json_values() {
        let probe = Probe {
            operation: "POST /orders".into(),
            target: "quantity".into(),
            int: vec![0, -1],
            float: vec![3.14],
            string: vec!["abc".into()],
            bools: vec![true],
            null: true,
        };

        let values = probe.to_json_values();
        assert_eq!(values.len(), 6); // 2 int + 1 float + 1 string + 1 bool + 1 null
        assert_eq!(values[0], serde_json::json!(0));
        assert_eq!(values[1], serde_json::json!(-1));
        assert_eq!(values[2], serde_json::json!(3.14));
        assert_eq!(values[3], serde_json::json!("abc"));
        assert_eq!(values[4], serde_json::json!(true));
        assert_eq!(values[5], serde_json::Value::Null);
    }

    #[test]
    fn probe_matches_operation() {
        let probe = Probe {
            operation: "POST /orders".into(),
            target: "quantity".into(),
            int: vec![0],
            float: vec![],
            string: vec![],
            bools: vec![],
            null: false,
        };

        assert!(probe.matches_operation("POST", "/orders"));
        assert!(!probe.matches_operation("GET", "/orders"));
        assert!(!probe.matches_operation("POST", "/users"));
    }

    #[test]
    fn parse_toml_ignores_legacy_success_criteria() {
        // Existing configs may still have success_criteria — serde ignores unknown fields
        let toml = r#"
spec = "api.yaml"
base_url = "http://localhost:3000"
success_criteria = "require_2xx"
min_success_rate = 0.2
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.base_url, "http://localhost:3000");
    }
}
