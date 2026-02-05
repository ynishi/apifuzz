//! Verdict module - failure classification, severity, and policy

mod failure;
mod policy;
mod severity;

pub use failure::{Failure, FailureType, RequestSnapshot, ResponseSnapshot};
pub use policy::{Verdict, VerdictPolicy, VerdictStatus};
pub use severity::Severity;
