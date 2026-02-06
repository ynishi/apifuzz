//! apifuzz CLI - Robust API fuzzing with strict failure detection

mod storage;

use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use apifuzz_core::status;
use apifuzz_core::{Config, VerdictPolicy, VerdictStatus, classify_failures, to_http_file};
use apifuzz_runner::{FuzzLevel, NativeRunner};

#[derive(Parser)]
#[command(name = "apifuzz")]
#[command(about = "Robust API fuzzing with strict failure detection")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(long, global = true, default_value = "terminal")]
    output: OutputFormat,

    /// Strict mode (warnings become errors). Use --no-strict to disable.
    #[arg(long, global = true, default_value_t = true, action = ArgAction::Set)]
    strict: bool,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run API fuzzing
    Fuzz {
        /// Fuzz intensity level
        #[arg(short, long, default_value = "normal")]
        level: FuzzLevelArg,

        /// Output directory
        #[arg(short, long, default_value = ".apifuzz")]
        output_dir: String,

        /// Config file (default: .apifuzz.toml)
        #[arg(short, long)]
        config: Option<String>,

        /// Show execution plan without sending requests
        #[arg(long)]
        dry_run: bool,

        /// Dump all request/response pairs to JSONL files
        #[arg(long)]
        dump: bool,

        /// Directory for dump files (default: .apifuzz/dumps)
        #[arg(long)]
        dump_dir: Option<String>,

        /// Stop on first failure detection (fast-fail for CI)
        #[arg(long)]
        stop_on_failure: bool,

        /// Max requests per operation (across all phases)
        #[arg(long)]
        limit: Option<u32>,
    },

    /// Initialize config file
    Init,

    /// Show version and check dependencies
    Doctor,

    /// Export JSON Schema for the interchange format
    Schema,

    /// Show usage guide (config, phases, probes, CI integration)
    Guide,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FuzzLevelArg {
    Quick,
    Normal,
    Heavy,
}

impl From<FuzzLevelArg> for FuzzLevel {
    fn from(arg: FuzzLevelArg) -> Self {
        match arg {
            FuzzLevelArg::Quick => FuzzLevel::Quick,
            FuzzLevelArg::Normal => FuzzLevel::Normal,
            FuzzLevelArg::Heavy => FuzzLevel::Heavy,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Terminal,
    Json,
    Silent,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(3)
        }
    }
}

fn format_pct_display(rate: f64) -> String {
    let pct = rate * 100.0;
    if pct == 0.0 || pct == 100.0 {
        format!("{pct:.0}")
    } else {
        format!("{pct:.1}")
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Fuzz {
            level,
            output_dir,
            config,
            dry_run,
            dump,
            dump_dir,
            stop_on_failure,
            limit,
        } => {
            // Load config
            let cfg = if let Some(path) = config {
                Config::load(std::path::Path::new(&path))?
            } else {
                Config::load_default()?
            };

            let runner = NativeRunner::from_config(&cfg)
                .with_level(level.into())
                .with_stop_on_failure(stop_on_failure)
                .with_limit(limit);

            // Dry run: show plan and exit
            if dry_run {
                let plan = runner.plan(&cfg)?;
                match cli.output {
                    OutputFormat::Terminal => {
                        println!("{}", plan.to_terminal());
                    }
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&plan)?);
                    }
                    OutputFormat::Silent => {}
                }
                return Ok(if plan.has_errors() { 1 } else { 0 });
            }

            if cli.output != OutputFormat::Silent {
                eprintln!("Config:");
                eprintln!("  spec:     {}", cfg.spec.display());
                eprintln!("  base_url: {}", cfg.base_url);
                if !cfg.headers.is_empty() {
                    eprintln!("  headers:  {} configured", cfg.headers.len());
                }
                eprintln!("  level:    {level:?}");
                eprintln!();
            }

            let fuzz_start = Instant::now();
            let output = runner.run()?;
            let duration_secs = fuzz_start.elapsed().as_secs_f64();

            // Report errors
            if !output.errors.is_empty() && cli.output != OutputFormat::Silent {
                eprintln!("Errors:");
                for err in &output.errors {
                    eprintln!("  - {err}");
                }
                eprintln!();
            }

            // Safety check: no requests made → tool error
            if output.total == 0 {
                eprintln!("Error: No requests were made. Check spec and base_url.");
                if !output.errors.is_empty() {
                    eprintln!(
                        "  errors: {}",
                        output
                            .errors
                            .iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("\n  ")
                    );
                }
                return Ok(3);
            }

            // Convert raw types → Rust verdict types
            let classified = classify_failures(&output);

            // Safety check: failures reported but classification produced nothing
            if output.failure_count > 0 && classified.is_empty() {
                eprintln!(
                    "Warning: {} failures reported but classification produced 0.",
                    output.failure_count
                );
                eprintln!("  This may indicate a parsing issue. Treating as tool error.");
                return Ok(3);
            }

            // Apply policy
            let policy = VerdictPolicy {
                strict: cli.strict,
                ..Default::default()
            };

            let filtered = policy.filter(classified);

            // Status code distribution analysis
            let status_analysis = status::analyze(
                &output.interactions,
                cfg.success_criteria,
                cfg.min_success_rate,
            );

            // If require_2xx produced failures, escalate verdict
            let has_status_failures = status_analysis.warnings.iter().any(|w| w.is_failure);

            let verdict = policy.verdict(&filtered);

            // Escalate exit code if status analysis found failures
            let final_exit_code = if has_status_failures && verdict.exit_code == 0 {
                1 // Warning-level exit
            } else {
                verdict.exit_code
            };

            let final_verdict = if final_exit_code != verdict.exit_code {
                apifuzz_core::Verdict {
                    status: VerdictStatus::Fail,
                    exit_code: final_exit_code,
                    reason: format!(
                        "{} + status analysis: {}",
                        verdict.reason,
                        status_analysis
                            .warnings
                            .iter()
                            .map(|w| w.message.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                }
            } else {
                verdict
            };

            // Output
            match cli.output {
                OutputFormat::Terminal => {
                    let icon = if final_verdict.status == VerdictStatus::Pass {
                        "PASS"
                    } else {
                        "FAIL"
                    };
                    println!("\n{icon}: {}", final_verdict.reason);
                    println!(
                        "  Requests: {} total, {} success, {} failures",
                        output.total, output.success, output.failure_count
                    );
                    println!("  Exit code: {}", final_verdict.exit_code);

                    // Status distribution per operation
                    if !status_analysis.operations.is_empty() {
                        println!("\nStatus distribution:");
                        for op in &status_analysis.operations {
                            println!(
                                "  {}: {} ({}% 2xx)",
                                op.operation,
                                status::format_distribution(&op.status_distribution),
                                format_pct_display(op.success_rate),
                            );
                        }
                        // Global summary
                        println!(
                            "  Total: {} ({}% 2xx)",
                            status::format_distribution(
                                &status_analysis.global.status_distribution
                            ),
                            format_pct_display(status_analysis.global.success_rate),
                        );
                    }

                    // Status warnings
                    for w in &status_analysis.warnings {
                        if w.is_failure {
                            println!("  FAIL: {}", w.message);
                        } else {
                            println!("  WARNING: {}", w.message);
                        }
                    }

                    if !filtered.is_empty() {
                        println!("\nFailures ({}):", filtered.len());
                        for f in &filtered {
                            println!(
                                "  [{:?}] {} {} -> {} ({})",
                                f.severity, f.method, f.path, f.status_code, f.failure_type
                            );
                            if let Some(msg) = f.context.get("message") {
                                if !msg.is_empty() {
                                    println!("         {msg}");
                                }
                            }
                        }
                    }

                    // Generate .http reproduction file
                    if !filtered.is_empty() {
                        let http_path =
                            std::path::Path::new(&output_dir).join("reproductions.http");
                        let http_content = to_http_file(&filtered, "base_url");
                        if let Err(e) = std::fs::write(&http_path, &http_content) {
                            eprintln!("Warning: failed to write .http file: {e}");
                        } else {
                            println!("Reproductions: {}", http_path.display());
                        }
                    }
                }
                OutputFormat::Json => {
                    let json_output = serde_json::json!({
                        "verdict": {
                            "status": format!("{}", final_verdict.status),
                            "exit_code": final_verdict.exit_code,
                        },
                        "stats": {
                            "total": output.total,
                            "success": output.success,
                            "failures": output.failure_count,
                        },
                        "status_analysis": {
                            "global": status_analysis.global,
                            "operations": status_analysis.operations,
                            "warnings": status_analysis.warnings,
                        },
                        "failures": filtered,
                    });
                    println!("{}", serde_json::to_string_pretty(&json_output)?);
                }
                OutputFormat::Silent => {}
            }

            // Dump all interactions if requested (CLI flag or config)
            let should_dump = dump || cfg.dump;
            if should_dump {
                let dump_path = dump_dir
                    .as_deref()
                    .map(std::path::PathBuf::from)
                    .or(cfg.dump_dir.clone())
                    .unwrap_or_else(|| std::path::PathBuf::from(".apifuzz/dumps"));

                match apifuzz_core::dump::write_dump(
                    &output.interactions,
                    &dump_path,
                    true, // mask sensitive headers
                ) {
                    Ok(index) => {
                        if cli.output != OutputFormat::Silent {
                            eprintln!(
                                "Dump: {} interactions → {} ({})",
                                index.total,
                                dump_path.display(),
                                index
                                    .operations
                                    .iter()
                                    .map(|e| e.file.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to write dump: {e}");
                    }
                }
            }

            // Persist report to ~/.apifuzz/reports/
            let level_str = match level {
                FuzzLevelArg::Quick => "quick",
                FuzzLevelArg::Normal => "normal",
                FuzzLevelArg::Heavy => "heavy",
            };
            let report_data = storage::ReportData {
                config: &cfg,
                output: &output,
                failures: &filtered,
                verdict_status: final_verdict.status,
                verdict_exit_code: final_verdict.exit_code,
                verdict_reason: &final_verdict.reason,
                level: level_str,
                duration_secs,
            };
            match storage::save_report(&report_data) {
                Ok(path) => {
                    if cli.output != OutputFormat::Silent {
                        eprintln!("Report saved: {}", path.display());
                    }
                }
                Err(e) => eprintln!("Warning: failed to save report: {e}"),
            }

            Ok(final_verdict.exit_code)
        }

        Commands::Init => {
            let config_path = ".apifuzz.toml";
            if std::path::Path::new(config_path).exists() {
                eprintln!("{config_path} already exists");
                return Ok(1);
            }

            std::fs::write(config_path, Config::example())?;
            println!("Created {config_path}");
            println!("\nEdit the file to configure:");
            println!("  - spec: path to your OpenAPI spec");
            println!("  - base_url: server to test");
            println!("  - headers: auth tokens, API keys");
            println!("  - path_params: entity IDs for testing");
            Ok(0)
        }

        Commands::Doctor => {
            println!("apifuzz doctor");
            println!("==============\n");

            // Check for config
            let config_ok = Config::load_default().is_ok();
            println!(
                "[{}] Config file (.apifuzz.toml)",
                if config_ok { "OK" } else { "--" }
            );

            if let Ok(cfg) = Config::load_default() {
                let spec_ok = cfg.spec.exists();
                println!(
                    "[{}] Spec file ({})",
                    if spec_ok { "OK" } else { "NG" },
                    cfg.spec.display()
                );
            }

            println!("[OK] Pure Rust engine (no Python required)");

            if !config_ok {
                println!("\nCreate config file:");
                println!("  apifuzz init");
            }

            println!("\nReady to fuzz!");
            Ok(0)
        }

        Commands::Schema => {
            let schema = apifuzz_core::schema::generate_schema();
            println!("{schema}");
            Ok(0)
        }

        Commands::Guide => {
            print!("{}", include_str!("../docs/GUIDE.md"));
            Ok(0)
        }
    }
}
