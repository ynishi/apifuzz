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

## Try with Examples

Example target servers with intentional bugs are included for testing.

### Python (FastAPI)

```bash
cd examples/python-server
pip install fastapi uvicorn pydantic[email]
python main.py &                # starts on :8080
apifuzz fuzz -c apifuzz.toml --level quick
```

### Node.js (Express)

```bash
cd examples/node-server
npm install
node server.js &                # starts on :3000
apifuzz fuzz -c apifuzz.toml --level quick
```

Each example directory contains multiple config variants
(`apifuzz-probes.toml`, `apifuzz-boundary.toml`, etc.) for different
fuzzing scenarios.

## Fuzzing Phases

| Phase | Strategy | Source |
|-------|----------|--------|
| 0 | Custom probes | `[[probes]]` in TOML |
| 1 | Boundary values | Auto from schema |
| 1b | Type confusion | Wrong types injected |
| 2 | Near-boundary random | Boundary +/- noise |
| 3 | Full random | Schema-conformant |

## Documentation

- **[Usage Guide](crates/apifuzz-cli/docs/GUIDE.md)** - Config, phases, probes, CI, exit codes
- `apifuzz guide` - Same content from CLI (works offline)

## Project Structure

```
crates/
  apifuzz-core/     # Types, verdict logic, config
  apifuzz-runner/   # Fuzzing engine (datagen, HTTP, phases)
  apifuzz-cli/      # CLI (clap)
crates/apifuzz-cli/docs/
  GUIDE.md          # Canonical usage guide (embedded in binary)
examples/
  python-server/    # FastAPI buggy API (port 8080)
  node-server/      # Express buggy API (port 3000)
```
