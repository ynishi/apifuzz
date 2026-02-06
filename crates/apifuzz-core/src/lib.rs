//! apifuzz-core: Core types and verdict logic for API fuzzing
//!
//! This crate provides the fundamental types for representing API test failures,
//! their severity levels, and policies for determining pass/fail verdicts.

pub mod config;
pub mod convert;
pub mod dryrun;
pub mod dump;
pub mod generator;
pub mod schema;
pub mod status;
pub mod verdict;

pub use config::{Config, ConfigError, Probe};
pub use convert::classify_failures;
pub use dryrun::DryRunPlan;
pub use dump::{DumpError, DumpIndex};
pub use generator::to_http_file;
pub use schema::SchemathesisOutput;
pub use status::StatusAnalysis;
pub use verdict::{
    Failure, FailureType, RequestSnapshot, ResponseSnapshot, Severity, Verdict, VerdictPolicy,
    VerdictStatus,
};
