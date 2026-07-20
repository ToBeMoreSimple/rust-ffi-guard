//! ffi-guard — AI-native Rust FFI safety auditor.
//!
//! Scans Rust projects for FFI boundary issues with C/C++:
//! - `extern "C"` function signature mismatches
//! - `#[repr(C)]` struct layout consistency
//! - Unsafe block sprawl and missing safety docs
//! - Ownership leaks across FFI boundaries
//! - Null pointer dereference risks

pub mod checks;
pub mod mcp;
pub mod report;
pub mod scanner;
pub mod trophy;

pub use scanner::Scanner;
pub use report::{Issue, Report, Severity};
