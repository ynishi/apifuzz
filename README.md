# apifuzz

Pure Rust API fuzzer. Generates requests from OpenAPI specs using a
multi-phase strategy with 6 response validation checks (5xx detection,
status conformance, negative testing, response time, schema validation,
content-type conformance).

## Install

```bash
cargo install --path crates/apifuzz-cli
```

## Usage

```bash
apifuzz init                    # create .apifuzz.toml
apifuzz fuzz --level quick      # run (quick/normal/heavy)
apifuzz guide                   # full usage reference
```

## Fuzzing Phases

| Phase | Strategy | Source |
|-------|----------|--------|
| 0 | Custom probes | `[[probes]]` in TOML |
| 1 | Boundary values | Auto from schema |
| 1b | Type confusion | Wrong types injected |
| 2 | Near-boundary random | Boundary +/- noise |
| 3 | Full random | Schema-conformant |

## Documentation

- **[Usage Guide](docs/GUIDE.md)** - Config, phases, probes, CI, exit codes
- `apifuzz guide` - Same content from CLI (works offline)

## Project Structure

```
crates/
  apifuzz-core/     # Types, verdict logic, config
  apifuzz-runner/   # Fuzzing engine (datagen, HTTP, phases)
  apifuzz-cli/      # CLI (clap)
docs/
  GUIDE.md          # Canonical usage guide (embedded in binary)
```
