//! Integration test that generates fuzz-results.schema.json
//!
//! Run with: cargo test -p apifuzz-core --test generate_schema

use apifuzz_core::schema::generate_schema;
use std::path::Path;

#[test]
fn write_schema_file() {
    let schema = generate_schema();

    // Write to workspace root
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let schema_path = workspace_root.join("fuzz-results.schema.json");

    std::fs::write(&schema_path, &schema).expect("failed to write schema file");

    // Verify the file is valid JSON
    let content = std::fs::read_to_string(&schema_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        parsed.get("title").and_then(|v| v.as_str()),
        Some("SchemathesisOutput")
    );
}
