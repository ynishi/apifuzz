//! JSON Schema → random `serde_json::Value` generator
//!
//! Handles OpenAPI 3.x / JSON Schema Draft 7 subset:
//! string, integer, number, boolean, array, object, enum, $ref, anyOf, oneOf, allOf

use rand::Rng;
use serde_json::{Value, json};

/// Maximum recursion depth for schema traversal (prevents stack overflow on circular `$ref`).
const MAX_DEPTH: u32 = 20;

/// Maximum string length for boundary/generation (prevents OOM on absurd maxLength values).
const MAX_STRING_LEN: usize = 10_000;

/// Generate a random JSON value conforming to the given JSON Schema.
///
/// `components` is `spec["components"]["schemas"]` for `$ref` resolution.
pub fn generate(schema: &Value, components: &Value, rng: &mut impl Rng) -> Value {
    generate_inner(schema, components, rng, 0)
}

fn generate_inner(schema: &Value, components: &Value, rng: &mut impl Rng, depth: u32) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }

    // $ref
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, components) {
            return generate_inner(&resolved, components, rng, depth + 1);
        }
        return Value::Null;
    }

    // enum
    if let Some(enum_values) = schema.get("enum").and_then(|v| v.as_array()) {
        if !enum_values.is_empty() {
            return enum_values[rng.gen_range(0..enum_values.len())].clone();
        }
    }

    // anyOf / oneOf: pick one non-null variant
    for key in &["anyOf", "oneOf"] {
        if let Some(variants) = schema.get(*key).and_then(|v| v.as_array()) {
            let non_null: Vec<_> = variants
                .iter()
                .filter(|s| s.get("type").and_then(|t| t.as_str()) != Some("null"))
                .collect();
            if non_null.is_empty() {
                return Value::Null;
            }
            return generate_inner(
                non_null[rng.gen_range(0..non_null.len())],
                components,
                rng,
                depth + 1,
            );
        }
    }

    // allOf: merge objects
    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        let mut merged = serde_json::Map::new();
        for sub in all_of {
            if let Value::Object(obj) = generate_inner(sub, components, rng, depth + 1) {
                merged.extend(obj);
            }
        }
        return Value::Object(merged);
    }

    // type-based generation
    let type_str = schema.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match type_str {
        "string" => gen_string(schema, rng),
        "integer" => gen_integer(schema, rng),
        "number" => gen_number(schema, rng),
        "boolean" => Value::Bool(rng.gen_bool(0.5)),
        "array" => gen_array(schema, components, rng, depth + 1),
        "object" => gen_object(schema, components, rng, depth + 1),
        "null" => Value::Null,
        _ => {
            // Infer from structure
            if schema.get("properties").is_some() {
                gen_object(schema, components, rng, depth + 1)
            } else if schema.get("items").is_some() {
                gen_array(schema, components, rng, depth + 1)
            } else {
                Value::String(random_alnum(rng, 8))
            }
        }
    }
}

pub(crate) fn resolve_ref(ref_str: &str, components: &Value) -> Option<Value> {
    ref_str
        .strip_prefix("#/components/schemas/")
        .and_then(|name| components.get(name).cloned())
}

fn gen_string(schema: &Value, rng: &mut impl Rng) -> Value {
    let format = schema.get("format").and_then(|v| v.as_str());
    match format {
        Some("email") => Value::String(format!("user{}@example.com", rng.gen_range(1..9999_u32))),
        Some("uri" | "url") => Value::String("https://example.com".into()),
        Some("date") => Value::String("2024-01-15".into()),
        Some("date-time") => Value::String("2024-01-15T12:00:00Z".into()),
        Some("uuid") => Value::String(format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            rng.r#gen::<u32>(),
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>() & 0x0FFF,
            (rng.r#gen::<u16>() & 0x3FFF) | 0x8000,
            rng.r#gen::<u64>() & 0xFFFF_FFFF_FFFF,
        )),
        _ => {
            let min = schema
                .get("minLength")
                .and_then(|v| v.as_u64())
                .map(|v| (v as usize).min(MAX_STRING_LEN))
                .unwrap_or(1);
            let max = schema
                .get("maxLength")
                .and_then(|v| v.as_u64())
                .map(|v| (v as usize).min(MAX_STRING_LEN))
                .unwrap_or(20);
            let len = rng.gen_range(min..=max.max(min));
            Value::String(random_alnum(rng, len))
        }
    }
}

fn gen_integer(schema: &Value, rng: &mut impl Rng) -> Value {
    let has_min = schema.get("minimum").is_some();
    let has_max = schema.get("maximum").is_some();
    let min = schema
        .get("minimum")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1000);
    let max = schema
        .get("maximum")
        .and_then(|v| v.as_i64())
        .unwrap_or(1000);

    // 20% chance: inject boundary/edge values for fuzz effectiveness
    if rng.gen_bool(0.2) {
        let mut edges = if has_min && has_max {
            vec![min, max]
        } else {
            vec![0, -1, 1, i64::MIN, i64::MAX]
        };
        // Include 0 as edge only if within valid range
        if has_min && has_max && (min..=max).contains(&0) && !edges.contains(&0) {
            edges.push(0);
        }
        return Value::Number(edges[rng.gen_range(0..edges.len())].into());
    }

    Value::Number(rng.gen_range(min..=max).into())
}

fn gen_number(schema: &Value, rng: &mut impl Rng) -> Value {
    let min = schema
        .get("minimum")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let max = schema
        .get("maximum")
        .and_then(|v| v.as_f64())
        .unwrap_or(1000.0);
    json!(rng.gen_range(min..=max))
}

fn gen_array(schema: &Value, components: &Value, rng: &mut impl Rng, depth: u32) -> Value {
    let min = schema.get("minItems").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let max = schema.get("maxItems").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let count = rng.gen_range(min..=max.max(min));
    let items_schema = schema
        .get("items")
        .cloned()
        .unwrap_or(json!({"type": "string"}));
    Value::Array(
        (0..count)
            .map(|_| generate_inner(&items_schema, components, rng, depth))
            .collect(),
    )
}

fn gen_object(schema: &Value, components: &Value, rng: &mut impl Rng, depth: u32) -> Value {
    let mut obj = serde_json::Map::new();
    let required: Vec<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (key, prop_schema) in props {
            if required.contains(key) || rng.gen_bool(0.5) {
                obj.insert(
                    key.clone(),
                    generate_inner(prop_schema, components, rng, depth),
                );
            }
        }
    }
    Value::Object(obj)
}

/// Return deterministic boundary/edge-case values for the given schema.
///
/// These trigger common bugs: off-by-one, division by zero, overflow, empty input.
/// Used in the boundary testing phase before random fuzzing.
pub fn boundaries(schema: &Value, components: &Value) -> Vec<Value> {
    boundaries_inner(schema, components, 0)
}

fn boundaries_inner(schema: &Value, components: &Value, depth: u32) -> Vec<Value> {
    if depth > MAX_DEPTH {
        return vec![];
    }

    // $ref
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, components) {
            return boundaries_inner(&resolved, components, depth + 1);
        }
        return vec![];
    }

    // enum — every declared value + casing variants for strings
    if let Some(enum_values) = schema.get("enum").and_then(|v| v.as_array()) {
        let mut result = enum_values.clone();
        for ev in enum_values {
            if let Some(s) = ev.as_str() {
                result.extend(casing_variants(s));
            }
        }
        // Also try a value not in the enum at all
        result.push(json!("__INVALID_ENUM_VALUE__"));
        return result;
    }

    // anyOf/oneOf — boundaries of each non-null variant
    for key in &["anyOf", "oneOf"] {
        if let Some(variants) = schema.get(*key).and_then(|v| v.as_array()) {
            let mut all = Vec::new();
            for variant in variants {
                if variant.get("type").and_then(|t| t.as_str()) != Some("null") {
                    all.extend(boundaries_inner(variant, components, depth + 1));
                }
            }
            return all;
        }
    }

    let type_str = schema.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match type_str {
        "integer" => integer_boundaries(schema),
        "number" => number_boundaries(schema),
        "string" => string_boundaries(schema),
        "boolean" => vec![Value::Bool(true), Value::Bool(false)],
        "null" => vec![Value::Null],
        _ => vec![],
    }
}

/// Return per-property boundary values for an object schema.
///
/// Resolves `$ref` and returns `(property_name, boundary_values)` pairs.
pub fn object_property_boundaries(schema: &Value, components: &Value) -> Vec<(String, Vec<Value>)> {
    let resolved = if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        match resolve_ref(ref_str, components) {
            Some(r) => r,
            None => return vec![],
        }
    } else {
        schema.clone()
    };

    let props = match resolved.get("properties").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return vec![],
    };

    let mut result = Vec::new();
    for (name, prop_schema) in props {
        let bv = boundaries(prop_schema, components);
        if !bv.is_empty() {
            result.push((name.clone(), bv));
        }
    }
    result
}

fn integer_boundaries(schema: &Value) -> Vec<Value> {
    let mut values: Vec<i64> = Vec::new();

    // --- Pragmatic bug zone: -10..10 ---
    // Most off-by-one, division-by-zero, sign errors cluster here.
    values.extend(-10i64..=10);

    // --- Common application thresholds ---
    // Pagination limits, batch sizes, retry counts, HTTP chunk boundaries.
    values.extend([100, 255, 256, 1000, 1024, 4096, 10_000, 65_535, 65_536]);

    // --- 32-bit boundaries ---
    // Many languages/DBs (MySQL INT, C int, Go int32, Protobuf sint32) use 32-bit.
    // JSON parsers in Java (Jackson), Go (encoding/json) default to int/int32.
    values.extend([
        i32::MIN as i64,
        i32::MIN as i64 - 1,
        i32::MAX as i64,
        i32::MAX as i64 + 1,
        u32::MAX as i64,
        u32::MAX as i64 + 1,
    ]);

    // --- 64-bit boundaries ---
    values.extend([i64::MIN, i64::MAX]);

    // --- JavaScript Number.MAX_SAFE_INTEGER (2^53-1) ---
    // JSON parsed in Node.js/browsers loses precision beyond this.
    // Python's json module handles big ints but JS clients may not.
    values.extend([
        (1i64 << 53) - 1, // 9007199254740991 = MAX_SAFE_INTEGER
        1i64 << 53,       // 9007199254740992 = first unsafe
    ]);

    // --- Schema-specific min/max and off-by-one ---
    let min = schema.get("minimum").and_then(|v| v.as_i64());
    let max = schema.get("maximum").and_then(|v| v.as_i64());

    if let Some(min_val) = min {
        values.push(min_val);
        if let Some(below) = min_val.checked_sub(1) {
            values.push(below);
        }
    }

    if let Some(max_val) = max {
        values.push(max_val);
        if let Some(above) = max_val.checked_add(1) {
            values.push(above);
        }
    }

    values.sort();
    values.dedup();
    values.into_iter().map(|v| json!(v)).collect()
}

fn string_boundaries(schema: &Value) -> Vec<Value> {
    let mut values = vec![
        // --- Universal string boundaries ---
        // Empty / whitespace
        json!(""),
        json!(" "),
        json!("  \t\n  "),
        // Type-confusion strings: parsers may coerce these
        // Python: bool("false") == True, JS: "0" is falsy
        // Go: strconv.ParseBool accepts "0","1","true","false"
        json!("0"),
        json!("1"),
        json!("-1"),
        json!("true"),
        json!("false"),
        json!("null"),
        json!("undefined"),
        json!("NaN"),
        json!("Infinity"),
        json!("-Infinity"),
        json!("None"),
        // Null byte: C/Go strings terminate here, Python/Ruby keep going.
        // nginx, Apache, PHP path handling split on \0.
        json!("abc\0def"),
        json!("\0"),
        // Unicode control & special
        // BOM: Excel/CSV parsers prepend, JSON parsers may reject or keep.
        json!("\u{FEFF}data"),
        // Zero-width space: invisible but len > 0, breaks equality checks.
        json!("a\u{200B}b"),
        // RTL override: display confusion, log injection.
        json!("\u{202E}abc"),
        // Replacement char: appears after invalid UTF-8 decode.
        json!("\u{FFFD}"),
        // CRLF injection: HTTP header injection, log forging.
        json!("line1\r\nline2"),
        json!("value\r\nX-Injected: true"),
        // Template/interpolation injection
        // Jinja2/Django: {{, Flask/Mako: ${, Ruby ERB: <%=, Thymeleaf: ${
        json!("{{7*7}}"),
        json!("${7*7}"),
        json!("#{7*7}"),
        // Path traversal: file read/write endpoints
        json!("../../../etc/passwd"),
        json!("..\\..\\..\\windows\\system32"),
        // Long string (10 KB): buffer overflow, truncation bugs
        // Note: one copy per string param per operation in boundary phase
        json!("a".repeat(10_000)),
        // JSON-in-string: double-encoding bugs
        json!("{\"key\":\"value\"}"),
        json!("[1,2,3]"),
    ];

    // --- Format-specific additions ---
    let format = schema.get("format").and_then(|v| v.as_str());
    match format {
        Some("email") => {
            values.push(json!("not-an-email"));
            values.push(json!("a@b.c"));
            values.push(json!("user@localhost"));
            values.push(json!("user+tag@example.com"));
            values.push(json!("\"user\"@example.com"));
        }
        Some("uri" | "url") => {
            values.push(json!("not-a-url"));
            values.push(json!("javascript:alert(1)"));
            values.push(json!("file:///etc/passwd"));
            values.push(json!("data:text/html,<h1>test</h1>"));
        }
        Some("date") => {
            // ISO 8601 date edge cases
            values.push(json!("0000-00-00"));
            values.push(json!("0000-01-01")); // year zero (not valid in most libs)
            values.push(json!("0001-01-01")); // min valid Gregorian
            values.push(json!("9999-12-31")); // max 4-digit year
            values.push(json!("10000-01-01")); // 5-digit year (breaks fixed-width parsers)
            values.push(json!("not-a-date"));
            // Invalid month/day
            values.push(json!("2024-00-01")); // month 0
            values.push(json!("2024-13-01")); // month 13
            values.push(json!("2024-01-00")); // day 0
            values.push(json!("2024-01-32")); // day 32
            values.push(json!("2024-02-30")); // Feb 30
            // Leap year
            values.push(json!("2024-02-29")); // valid (2024 is leap)
            values.push(json!("2023-02-29")); // invalid (2023 not leap)
            values.push(json!("1900-02-29")); // invalid (century non-leap)
            values.push(json!("2000-02-29")); // valid (400-year leap)
            // Negative year (ISO 8601 extended)
            values.push(json!("-0001-01-01"));
            // Alternate separators (non-ISO but common mistakes)
            values.push(json!("2024/01/15"));
            values.push(json!("01-15-2024")); // US format confusion
            values.push(json!("20240115")); // compact ISO
        }
        Some("date-time") => {
            // ISO 8601 date-time edge cases
            values.push(json!("0000-01-01T00:00:00Z"));
            values.push(json!("0001-01-01T00:00:00Z"));
            values.push(json!("9999-12-31T23:59:59Z"));
            values.push(json!("not-a-datetime"));
            // Epoch & historic boundaries
            values.push(json!("1970-01-01T00:00:00Z")); // Unix epoch
            values.push(json!("1969-12-31T23:59:59Z")); // 1 sec before epoch (negative ts)
            values.push(json!("2000-01-01T00:00:00Z")); // Y2K
            values.push(json!("2038-01-19T03:14:07Z")); // Y2K38 (i32 max unix ts)
            values.push(json!("2038-01-19T03:14:08Z")); // Y2K38 overflow
            // Leap second (ISO 8601 allows :60)
            values.push(json!("2016-12-31T23:59:60Z")); // actual leap second event
            // T24:00:00 — valid in ISO 8601, means midnight end-of-day
            values.push(json!("2024-01-15T24:00:00Z"));
            // Sub-second precision variants
            values.push(json!("2024-01-15T12:00:00.0Z"));
            values.push(json!("2024-01-15T12:00:00.000000Z")); // microseconds
            values.push(json!("2024-01-15T12:00:00.000000000Z")); // nanoseconds
            values.push(json!("2024-01-15T12:00:00.9999999999Z")); // excess precision
            // Timezone offset edge cases
            values.push(json!("2024-01-15T12:00:00+00:00"));
            values.push(json!("2024-01-15T12:00:00-00:00")); // RFC 3339: -00:00 = unknown tz
            values.push(json!("2024-01-15T12:00:00+14:00")); // max valid offset (Kiribati)
            values.push(json!("2024-01-15T12:00:00-12:00")); // min valid offset (Baker Is.)
            values.push(json!("2024-01-15T12:00:00+99:99")); // invalid offset
            // Missing timezone (ambiguous — local or UTC?)
            values.push(json!("2024-01-15T12:00:00"));
            // Space instead of T (common in SQL, some parsers accept)
            values.push(json!("2024-01-15 12:00:00Z"));
        }
        Some("uuid") => {
            values.push(json!("not-a-uuid"));
            // Nil UUID (RFC 4122)
            values.push(json!("00000000-0000-0000-0000-000000000000"));
            // Max UUID (RFC 9562)
            values.push(json!("ffffffff-ffff-ffff-ffff-ffffffffffff"));
            // Uppercase (some parsers reject, some accept)
            values.push(json!("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"));
            // Mixed case
            values.push(json!("550e8400-E29B-41D4-A716-446655440000"));
            // No dashes (compact form — some libs accept, some reject)
            values.push(json!("550e8400e29b41d4a716446655440000"));
            // Too short / too long
            values.push(json!("550e8400-e29b-41d4-a716"));
            values.push(json!("550e8400-e29b-41d4-a716-446655440000-extra"));
            // Wrong dash positions
            values.push(json!("550e84-00e29b-41d4a716-446655440000"));
            // Braces (Microsoft GUID format)
            values.push(json!("{550e8400-e29b-41d4-a716-446655440000}"));
            // urn:uuid prefix (RFC 4122 URN)
            values.push(json!("urn:uuid:550e8400-e29b-41d4-a716-446655440000"));
        }
        Some("time") => {
            // ISO 8601 time-only
            values.push(json!("00:00:00"));
            values.push(json!("23:59:59"));
            values.push(json!("24:00:00")); // end-of-day midnight
            values.push(json!("23:59:60")); // leap second
            values.push(json!("25:00:00")); // invalid hour
            values.push(json!("12:60:00")); // invalid minute
            values.push(json!("12:00:60")); // invalid second (non-leap)
            values.push(json!("12:00:00Z")); // with timezone
            values.push(json!("12:00:00+09:00")); // with offset
            values.push(json!("12:00:00.000000000Z")); // nanoseconds
        }
        Some("duration") => {
            // ISO 8601 duration
            values.push(json!("P0D")); // zero duration
            values.push(json!("PT0S")); // zero seconds
            values.push(json!("P1D"));
            values.push(json!("PT1H30M"));
            values.push(json!("P999999D")); // very long
            values.push(json!("P-1D")); // negative (non-standard)
            values.push(json!("not-a-duration"));
        }
        _ => {}
    }

    // --- Schema-specific minLength/maxLength ---
    if let Some(min_len) = schema.get("minLength").and_then(|v| v.as_u64()) {
        let capped = (min_len as usize).min(MAX_STRING_LEN);
        values.push(json!("a".repeat(capped)));
        if capped > 0 {
            values.push(json!("a".repeat(capped - 1)));
        }
    }
    if let Some(max_len) = schema.get("maxLength").and_then(|v| v.as_u64()) {
        let capped = (max_len as usize).min(MAX_STRING_LEN);
        values.push(json!("a".repeat(capped)));
        values.push(json!("a".repeat(capped.saturating_add(1))));
    }

    values
}

fn number_boundaries(schema: &Value) -> Vec<Value> {
    let mut values = vec![
        // --- Pragmatic float bug zone ---
        json!(0.0),
        json!(-0.0), // IEEE 754: -0.0 != 0.0 in some comparisons
        json!(-1.0),
        json!(1.0),
        json!(0.1), // 0.1 + 0.2 != 0.3 in IEEE 754
        json!(0.5),
        // --- Currency/precision edge cases ---
        // Rounding bugs in financial calculations
        json!(0.001),
        json!(0.005), // half-cent rounding
        json!(99.99),
        json!(99.999),
        // --- Very small: underflow, epsilon ---
        json!(f64::EPSILON),      // 2.22e-16
        json!(f64::MIN_POSITIVE), // 2.22e-308
        // --- Large values: overflow territory ---
        json!(1e38),  // near f32::MAX (3.4e38)
        json!(1e39),  // exceeds f32::MAX → Inf in f32
        json!(1e308), // near f64::MAX
        json!(-1e308),
    ];

    // --- Schema-specific min/max ---
    let min = schema.get("minimum").and_then(|v| v.as_f64());
    let max = schema.get("maximum").and_then(|v| v.as_f64());

    if let Some(min_val) = min {
        values.push(json!(min_val));
        values.push(json!(min_val - 1.0));
        values.push(json!(min_val - f64::EPSILON));
    }

    if let Some(max_val) = max {
        values.push(json!(max_val));
        values.push(json!(max_val + 1.0));
        values.push(json!(max_val + f64::EPSILON));
    }

    values
}

/// Generate a random value near a boundary of the given schema.
///
/// Picks a boundary value and adds small noise, concentrating test effort
/// around boundary regions where bugs cluster.
pub fn near_boundary(schema: &Value, components: &Value, rng: &mut impl Rng) -> Value {
    near_boundary_inner(schema, components, rng, 0)
}

fn near_boundary_inner(
    schema: &Value,
    components: &Value,
    rng: &mut impl Rng,
    depth: u32,
) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }

    // $ref
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, components) {
            return near_boundary_inner(&resolved, components, rng, depth + 1);
        }
        return Value::Null;
    }

    let bv = boundaries(schema, components);
    if bv.is_empty() {
        return generate(schema, components, rng);
    }

    let base = &bv[rng.gen_range(0..bv.len())];
    perturb(base, schema, rng)
}

/// Return property schemas for an object (resolving `$ref`).
pub fn resolve_object_properties(schema: &Value, components: &Value) -> Vec<(String, Value)> {
    let resolved = if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        match resolve_ref(ref_str, components) {
            Some(r) => r,
            None => return vec![],
        }
    } else {
        schema.clone()
    };

    resolved
        .get("properties")
        .and_then(|v| v.as_object())
        .map(|props| props.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Add small noise to a boundary value.
fn perturb(value: &Value, schema: &Value, rng: &mut impl Rng) -> Value {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let noise = rng.gen_range(-10i64..=10);
                json!(i.saturating_add(noise))
            } else if let Some(f) = n.as_f64() {
                let noise = rng.gen_range(-10.0f64..=10.0);
                json!(f + noise)
            } else {
                value.clone()
            }
        }
        Value::String(s) => {
            let base_len = s.len();
            let delta = rng.gen_range(0..=3usize);
            let target_len = if rng.gen_bool(0.5) {
                base_len.saturating_add(delta)
            } else {
                base_len.saturating_sub(delta)
            };
            let format = schema.get("format").and_then(|v| v.as_str());
            if format == Some("email") {
                Value::String(format!(
                    "{}@example.com",
                    random_alnum(rng, target_len.max(1))
                ))
            } else {
                Value::String(random_alnum(rng, target_len))
            }
        }
        Value::Bool(_) => Value::Bool(rng.gen_bool(0.5)),
        _ => value.clone(),
    }
}

/// Return values of types DIFFERENT from the schema's declared type.
///
/// Tests how the API handles type confusion/coercion:
/// - string "123" where integer expected
/// - null where object expected
/// - array where string expected
/// - etc.
#[allow(clippy::approx_constant)] // 3.14 is an intentional test probe, not PI
pub fn type_confusion_values(schema: &Value, components: &Value) -> Vec<Value> {
    type_confusion_values_inner(schema, components, 0)
}

#[allow(clippy::approx_constant)]
fn type_confusion_values_inner(schema: &Value, components: &Value, depth: u32) -> Vec<Value> {
    if depth > MAX_DEPTH {
        return vec![];
    }

    // Resolve $ref
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, components) {
            return type_confusion_values_inner(&resolved, components, depth + 1);
        }
        return vec![];
    }

    // enum — skip type confusion (values are fixed)
    if schema.get("enum").and_then(|v| v.as_array()).is_some() {
        return vec![];
    }

    let declared = schema.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let mut values = Vec::new();

    // String probes (tests coercion: "123"→int, "true"→bool, etc.)
    if declared != "string" {
        values.push(json!(""));
        values.push(json!("123"));
        values.push(json!("true"));
    }

    // Integer probes
    if declared != "integer" && declared != "number" {
        values.push(json!(0));
        values.push(json!(42));
    }

    // Float probes (tests int/float confusion)
    if declared != "number" && declared != "integer" {
        values.push(json!(3.14));
    } else if declared == "integer" {
        // integer schema receiving a float is type confusion
        values.push(json!(3.14));
    }

    // Boolean probes
    if declared != "boolean" {
        values.push(json!(true));
        values.push(json!(false));
    }

    // Null probe (common crash source)
    if declared != "null" {
        values.push(Value::Null);
    }

    // Array probe
    if declared != "array" {
        values.push(json!([]));
        values.push(json!([1]));
    }

    // Object probe
    if declared != "object" {
        values.push(json!({}));
    }

    values
}

/// Generate casing variants for a string enum value.
///
/// Many APIs compare enum values case-sensitively but clients send
/// different casings. This catches:
/// - Python/Ruby case-insensitive matching bugs
/// - Go's case-insensitive JSON unmarshaling by default
/// - Database COLLATION mismatches (utf8_general_ci vs utf8_bin)
fn casing_variants(s: &str) -> Vec<Value> {
    let mut variants = Vec::new();
    let upper = s.to_uppercase();
    let lower = s.to_lowercase();

    // Only add variants that differ from original
    if upper != s {
        variants.push(json!(upper));
    }
    if lower != s {
        variants.push(json!(lower));
    }

    // Title Case: "active" → "Active", "ACTIVE" → "Active"
    let title: String = {
        let mut chars = lower.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    };
    if title != s && title != upper && title != lower {
        variants.push(json!(title));
    }

    // Leading/trailing whitespace (trim bugs)
    variants.push(json!(format!(" {s}")));
    variants.push(json!(format!("{s} ")));

    variants
}

fn random_alnum(rng: &mut impl Rng, len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    fn rng() -> SmallRng {
        SmallRng::seed_from_u64(42)
    }

    fn empty_components() -> Value {
        json!({})
    }

    #[test]
    fn gen_string_basic() {
        let schema = json!({"type": "string"});
        let val = generate(&schema, &empty_components(), &mut rng());
        assert!(val.is_string());
        assert!(!val.as_str().unwrap().is_empty());
    }

    #[test]
    fn gen_string_email() {
        let schema = json!({"type": "string", "format": "email"});
        let val = generate(&schema, &empty_components(), &mut rng());
        assert!(val.as_str().unwrap().contains('@'));
    }

    #[test]
    fn gen_integer_range() {
        let schema = json!({"type": "integer", "minimum": 10, "maximum": 20});
        let val = generate(&schema, &empty_components(), &mut rng());
        let n = val.as_i64().unwrap();
        assert!((10..=20).contains(&n));
    }

    #[test]
    fn gen_boolean() {
        let schema = json!({"type": "boolean"});
        let val = generate(&schema, &empty_components(), &mut rng());
        assert!(val.is_boolean());
    }

    #[test]
    fn gen_array() {
        let schema =
            json!({"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 4});
        let val = generate(&schema, &empty_components(), &mut rng());
        let arr = val.as_array().unwrap();
        assert!(arr.len() >= 2 && arr.len() <= 4);
        assert!(arr.iter().all(|v| v.is_number()));
    }

    #[test]
    fn gen_object_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name"]
        });
        let val = generate(&schema, &empty_components(), &mut rng());
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("name"));
    }

    #[test]
    fn gen_ref_resolution() {
        let schema = json!({"$ref": "#/components/schemas/Foo"});
        let components = json!({"Foo": {"type": "integer", "minimum": 1, "maximum": 1}});
        let val = generate(&schema, &components, &mut rng());
        assert_eq!(val, json!(1));
    }

    #[test]
    fn gen_any_of() {
        let schema = json!({"anyOf": [{"type": "string"}, {"type": "null"}]});
        let val = generate(&schema, &empty_components(), &mut rng());
        assert!(val.is_string()); // non-null preferred
    }

    #[test]
    fn gen_enum() {
        let schema = json!({"type": "string", "enum": ["a", "b", "c"]});
        let val = generate(&schema, &empty_components(), &mut rng());
        assert!(["a", "b", "c"].contains(&val.as_str().unwrap()));
    }

    #[test]
    fn gen_all_of() {
        let schema = json!({
            "allOf": [
                {"type": "object", "properties": {"a": {"type": "integer", "minimum": 1, "maximum": 1}}, "required": ["a"]},
                {"type": "object", "properties": {"b": {"type": "string"}}, "required": ["b"]}
            ]
        });
        let val = generate(&schema, &empty_components(), &mut rng());
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("a"));
        assert!(obj.contains_key("b"));
    }

    #[test]
    fn gen_string_length_constraints() {
        let schema = json!({"type": "string", "minLength": 5, "maxLength": 10});
        let val = generate(&schema, &empty_components(), &mut rng());
        let s = val.as_str().unwrap();
        assert!(s.len() >= 5 && s.len() <= 10);
    }
}
