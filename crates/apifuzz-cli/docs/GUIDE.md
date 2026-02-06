# apifuzz Usage Guide

Pure Rust API fuzzer. Validates API responses with 6 checks (5xx, status
conformance, negative testing, response time, schema validation, content-type)
by generating requests from an OpenAPI spec using a multi-phase strategy.

## Quick Start

```bash
# 1. Initialize config
apifuzz init

# 2. Edit .apifuzz.toml (set spec path and base_url)

# 3. Run
apifuzz fuzz
```

## Configuration (.apifuzz.toml)

```toml
spec = "openapi.yaml"          # OpenAPI 3.x spec (JSON or YAML)
base_url = "http://localhost:8080"

[headers]
Authorization = "Bearer token"  # Auth headers

[path_params]
user_id = "1"                   # Fixed path param values

# Response time limit in seconds (disabled by default)
# response_time_limit = 5.0

# Success criteria for status code evaluation:
#   "default"      - warn on 2xx=0%, auto-detect auth/rate-limit patterns
#   "require_2xx"  - fail if 2xx rate < min_success_rate (default 10%)
#   "any_response" - record distribution, never fail on status alone
# success_criteria = "default"
# min_success_rate = 0.1

# Dump all request/response pairs to JSONL files (default: false)
# dump = true
# dump_dir = ".apifuzz/dumps"

# Custom probes: known-buggy values (highest priority, Phase 0)
[[probes]]
operation = "POST /orders"      # "METHOD /path" exact match
target = "quantity"             # parameter or body property name
int = [0, -1, 999999]          # integer values to inject
# float = [0.0, -1.0]          # float values
# string = ["", "null"]        # string values
# bool = [true, false]         # boolean values
# null = true                  # inject null
```

### Spec Format

Both JSON and YAML OpenAPI specs are supported. Detection order:
1. File extension (`.json`, `.yaml`, `.yml`)
2. Content sniffing (leading `{` → JSON, otherwise YAML)

### Probe Types

| Field    | TOML Type    | JSON Result          |
|----------|-------------|----------------------|
| `int`    | `[0, -1]`   | `0`, `-1`            |
| `float`  | `[3.14]`    | `3.14`               |
| `string` | `["", "x"]` | `""`, `"x"`          |
| `bool`   | `[true]`    | `true`               |
| `null`   | `true`      | `null`               |

## Fuzz Levels & Fine-Tuning

```bash
# Presets (start here)
apifuzz fuzz --level quick    # 100 neighborhood+random per op (fast CI)
apifuzz fuzz --level normal   # 1000 per op (default)
apifuzz fuzz --level heavy    # 5000 per op (thorough)

# Fine-tuning (overrides --level for neighborhood+random count)
apifuzz fuzz -n 200           # exact iteration count
apifuzz fuzz --level heavy -n 200  # -n wins over level

# Per-operation hard cap across ALL phases (probe+boundary+tc+near+rand)
apifuzz fuzz --limit 50
```

The `--level` preset controls neighborhood (Phase 2) and random (Phase 3)
iteration counts. Deterministic phases (probe, boundary, type-confusion)
always run fully unless `--limit` caps total requests per operation.

## 5-Phase Fuzzing Strategy

Each operation is tested in 5 phases, in order:

### Phase 0: Custom Probes (deterministic)
User-defined values from `[[probes]]` in TOML config.
Use for known regression values or domain-specific edge cases.

### Phase 1: Boundary Values (deterministic)
Auto-generated from schema. Always runs regardless of level.

**Integer presets (~40 values):**
- Pragmatic bug zone: `-10` to `10` (off-by-one, sign errors, division-by-zero)
- Application thresholds: `100, 255, 256, 1000, 1024, 4096, 10000, 65535, 65536`
- 32-bit boundaries: `i32::MIN`, `i32::MAX`, `u32::MAX` and +/-1
  (Java Jackson, Go encoding/json, MySQL INT, Protobuf sint32)
- 64-bit boundaries: `i64::MIN`, `i64::MAX`
- JS safe integer: `2^53-1` (9007199254740991), `2^53` (precision loss in browsers)
- Schema min/max and off-by-one

**Number (float) presets (~18 values):**
- IEEE 754: `0.0`, `-0.0`, `epsilon`, `MIN_POSITIVE`
- Currency precision: `0.001`, `0.005`, `99.99`, `99.999`
- Overflow: `1e38` (f32 limit), `1e39`, `1e308` (f64 limit)
- Schema min/max and off-by-one (including epsilon)

**String presets (~30+ values):**
- Empty/whitespace: `""`, `" "`, `"\t\n"`
- Type-confusion: `"0"`, `"1"`, `"true"`, `"false"`, `"null"`, `"NaN"`, `"Infinity"`
  (Python bool("false")==True, JS "0" is falsy, Go ParseBool accepts "0"/"1")
- Null byte: `"abc\0def"` (C/Go terminate, PHP path split)
- Unicode: BOM `\uFEFF`, zero-width space `\u200B`, RTL override `\u202E`
- CRLF: `"line1\r\nline2"` (HTTP header injection, log forging)
- Template injection: `"{{7*7}}"`, `"${7*7}"`, `"#{7*7}"`
- Path traversal: `"../../../etc/passwd"`
- Long string: `"a" * 10000`
- JSON-in-string: `"{\"key\":\"value\"}"` (double-encoding)
- Schema minLength/maxLength and off-by-one

**Format-specific string presets:**

*date (ISO 8601):*
- Year zero `0000-01-01`, max `9999-12-31`, 5-digit `10000-01-01`
- Invalid month/day: `2024-13-01`, `2024-02-30`, `2024-01-32`
- Leap year: `2024-02-29` (valid), `2023-02-29` (invalid), `1900-02-29` (century)
- Alt formats: `2024/01/15`, `01-15-2024` (US), `20240115` (compact)

*date-time (ISO 8601 / RFC 3339):*
- Epoch: `1970-01-01T00:00:00Z`, pre-epoch: `1969-12-31T23:59:59Z`
- Y2K38: `2038-01-19T03:14:07Z` (i32 max), `2038-01-19T03:14:08Z` (overflow)
- Leap second: `2016-12-31T23:59:60Z`
- End-of-day: `T24:00:00` (valid ISO 8601, many parsers reject)
- Precision: `.0Z`, `.000000Z` (us), `.000000000Z` (ns), `.9999999999Z` (excess)
- Timezone: `+14:00` (Kiribati max), `-12:00` (Baker min), `-00:00` (RFC 3339 unknown)
- Missing TZ: `2024-01-15T12:00:00` (local? UTC?), space separator: `2024-01-15 12:00:00Z`

*time / duration:*
- `24:00:00` (end-of-day), `23:59:60` (leap), invalid: `25:00:00`, `12:60:00`
- Duration: `P0D`, `PT0S`, `P999999D`, `P-1D` (negative)

*uuid (RFC 4122 / RFC 9562):*
- Nil: `00000000-...`, Max: `ffffffff-...`
- Case: uppercase, mixed, lowercase
- Format: no dashes, wrong dash positions, braces `{...}`, URN `urn:uuid:...`

**Enum presets:**
- All declared values
- Casing variants: UPPER, lower, Title (catches case-sensitivity mismatches)
- Whitespace: `" value"`, `"value "` (trim bugs)
- Invalid: `__INVALID_ENUM_VALUE__`

### Phase 1b: Type Confusion (deterministic)
Sends wrong JSON types for each parameter:
- Integer field gets `"123"`, `true`, `null`, `[]`, `{}`
- String field gets `42`, `3.14`, `null`, `[]`, `{}`
- Detects serializer coercion bugs and type-handling crashes.
- **Negative testing**: if the API returns 2xx for type-confused input,
  flagged as `NegativeTestAccepted` (Warning severity).

### Phase 2: Boundary Neighborhood (random)
Random values near boundaries (boundary +/- small noise).
Concentrates effort around bug-prone regions. 1/3 of max_examples.

### Phase 3: Full Random (random)
Standard random generation from schema. 2/3 of max_examples.

## Response Checks

Every response is checked for:

| Check | Condition | Severity | Type |
|-------|-----------|----------|------|
| Server error | Status 5xx | Critical | `ServerError` |
| Status conformance | Status not declared in OpenAPI spec | Warning | `StatusCodeConformance` |
| Negative testing | Type-confused input accepted (2xx) | Warning | `NegativeTestAccepted` |
| Response time | Elapsed > `response_time_limit` | Warning | `ResponseTimeExceeded` |
| Schema validation | Response body violates OpenAPI schema | Warning | `SchemaViolation` |
| Content-Type | Response Content-Type not in OpenAPI spec | Warning | `ContentTypeMismatch` |

Response bodies are captured (truncated at 4KB) for debugging.

### Schema Validation

Response bodies are validated against the JSON Schema defined in the OpenAPI
spec's `responses.<status>.content.application/json.schema`. `$ref` references
are resolved recursively. Validation uses `jsonschema` crate (Draft 2020-12,
compatible with OpenAPI 3.1). Up to 5 validation errors are reported per
response.

### Content-Type Conformance

The response `Content-Type` header is compared against the media types
declared in `responses.<status>.content` for the matching status code.
Only the media type portion is compared (charset parameters are ignored).

## Dry Run

Preview the execution plan without sending any HTTP requests:

```bash
apifuzz fuzz --dry-run              # terminal summary
apifuzz fuzz --dry-run --output json  # machine-readable plan
```

Shows per-operation phase counts, matched probes, and config validation.
Useful for verifying setup before a real run.

## Request/Response Dumps

Save all interactions (not just failures) to per-operation JSONL files:

```bash
apifuzz fuzz --dump                        # writes to .apifuzz/dumps/
apifuzz fuzz --dump --dump-dir ./my-dumps  # custom directory
```

Or enable permanently in `.apifuzz.toml`:

```toml
dump = true
dump_dir = ".apifuzz/dumps"
```

Sensitive headers (`Authorization`, `Cookie`, etc.) are automatically masked.
An `index.json` summarizes all dumped files.

## Stop on Failure

```bash
apifuzz fuzz --stop-on-failure    # halt on first failure (fast CI feedback)
```

## Status Code Analysis

apifuzz analyzes the status code distribution across all operations and
auto-detects problematic patterns:

| Pattern | Trigger | Action |
|---------|---------|--------|
| Authentication issue | ≥90% are 401/403 | Warn (or fail with `require_2xx`) |
| Rate limited | ≥90% are 429 | Warn |
| Endpoint not found | ≥90% are 404 | Warn |
| No successful responses | 0% 2xx | Warn |
| Low success rate | Below `min_success_rate` | Fail (only with `require_2xx`) |

Configure with `success_criteria` in `.apifuzz.toml` (see Configuration above).

## Output Formats

```bash
apifuzz fuzz                        # terminal (human-readable)
apifuzz fuzz --output json          # JSON (CI integration)
apifuzz fuzz --output silent        # exit code only
```

## Exit Codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | PASS - no failures                   |
| 1    | FAIL - warnings in strict mode       |
| 2    | FAIL - critical/error failures found |
| 3    | Tool error (config, network, etc.)   |

## Reproduction Files

Failed requests are saved to `.apifuzz/reproductions.http`.
Compatible with VS Code REST Client and IntelliJ HTTP Client.

## CI Example

```yaml
# Quick check
- run: apifuzz fuzz --level quick --output json --strict true

# Fast-fail with dump for debugging
- run: apifuzz fuzz --level quick --stop-on-failure --dump --output json
```

## Subcommands

| Command          | Purpose                            |
|------------------|------------------------------------|
| `apifuzz fuzz`   | Run fuzzing                        |
| `apifuzz init`   | Create .apifuzz.toml template      |
| `apifuzz doctor` | Check config and dependencies      |
| `apifuzz schema` | Export JSON Schema                 |
| `apifuzz guide`  | Show this guide                    |

## Adding Custom Probes (Workflow)

1. Run `apifuzz fuzz` and find a bug
2. Note the operation and parameter from the failure output
3. Add a `[[probes]]` entry in `.apifuzz.toml`
4. The value is now tested deterministically on every run (regression test)

Example: fuzzer found `POST /orders` crashes with `quantity=0`:

```toml
[[probes]]
operation = "POST /orders"
target = "quantity"
int = [0]
```

## For AI Agents

This tool is designed to be used by both humans and AI agents.
Key points for programmatic use:

- `--output json` returns structured results (verdict, stats, status analysis, failures)
- `--output silent` + exit code for pass/fail checks
- `--dry-run --output json` for pre-flight validation without HTTP
- `--dump` saves all request/response pairs for post-hoc analysis
- `--stop-on-failure` for fast CI feedback
- `-n 50` for minimal smoke tests
- `apifuzz guide` prints this reference (no network needed)
- `apifuzz doctor` validates setup before running
- Probes in TOML allow declarative regression tests
