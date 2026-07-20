//! `check_ffi_callback_panic` — detect `extern "C" fn(...)` types used as callbacks
//! that can panic across the FFI boundary.
//!
//! When Rust code panics inside an `extern "C" fn` callback invoked from C,
//! the panic unwind crosses the FFI boundary — this is **immediate undefined behavior**
//! per Rust's ABI rules. The compiler does not catch this.

use crate::report::{Issue, Severity};
use crate::scanner::ExternFn;

/// Check for function types declared as `extern "C" fn(...)` that are likely callbacks.
/// Also checks `type Foo = extern "C" fn(...)` type aliases.
pub fn check_callback_types(
    file_path: &str,
    file_source: &str,
    has_extern_c_types: bool,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    if !has_extern_c_types {
        return issues;
    }

    // Scan source text for `type ... = extern "C" fn(...)` patterns
    // and `Option<extern "C" fn(...)>` patterns which are classic callback types
    for (line_num, line) in file_source.lines().enumerate() {
        let line_num = line_num + 1;
        let trimmed = line.trim();

        // Pattern 1: type Alias = extern "C" fn(args) -> ret;
        // Pattern 2: Option<extern "C" fn(args)>
        // Pattern 3: *const extern "C" fn    (raw function pointers)
        if (trimmed.contains("type ") && trimmed.contains("extern \"C\" fn"))
            || trimmed.contains("Option<extern \"C\" fn")
            || trimmed.contains("*const extern \"C\" fn")
            || trimmed.contains("*mut extern \"C\" fn")
        {
            // Extract the type name if it's a type alias
            let type_name = if trimmed.starts_with("type ") {
                trimmed
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "callback".to_string()
            };

            issues.push(Issue {
                severity: Severity::Warning,
                check: "ffi-callback-panic",
                file: file_path.to_string(),
                line: line_num,
                column: 1,
                message: format!(
                    "`extern \"C\" fn(...)` type `{type_name}` is likely used as a C callback — \
                     if this callback panics, the unwind crosses FFI boundary (undefined behavior)"
                ),
                suggestion: Some(
                    "Wrap the callback body in `std::panic::catch_unwind()` or use \
                     `std::panic::set_hook()` to abort on panic. \
                     Alternatively, mark the function with `#[panic_handler]` or \
                     use `extern \"C-unwind\"` (unstable) to allow unwinding across FFI."
                        .to_string(),
                ),
            });
        }
    }

    issues
}

/// Check extern "C" functions for `panic!()` / `unwrap()` / `expect()` calls
/// inside their body — these can unwind across FFI if the function is invoked as a callback.
pub fn check_callback_body_panics(
    ef: &ExternFn,
    file_source: &str,
    file_path: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Only check extern "C" functions (not extern "Rust" etc.)
    if ef.abi != "C" {
        return issues;
    }

    // Extract the function body from source (approximate)
    let fn_start = ef.line;
    let lines: Vec<&str> = file_source.lines().collect();

    // Find the function's span (heuristic: from fn line to matching closing brace)
    let mut depth = 0;
    let mut started = false;
    for (i, line) in lines.iter().enumerate() {
        let i = i + 1;
        if i < fn_start {
            continue;
        }
        if !started {
            if line.contains('{') {
                started = true;
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
            }
            continue;
        }

        // Check for panic-prone calls
        let trimmed = line.trim();
        if trimmed.contains("panic!") || trimmed.contains("unreachable!")
            || trimmed.contains(".unwrap()") || trimmed.contains(".expect(")
        {
            issues.push(Issue {
                severity: Severity::Warning,
                check: "ffi-callback-panic",
                file: file_path.to_string(),
                line: i,
                column: 1,
                message: format!(
                    "extern \"C\" fn `{}` contains `{}` — \
                     if called from C, this panic crosses FFI boundary (UB)",
                    ef.name,
                    if trimmed.contains("panic!") {
                        "panic!()"
                    } else if trimmed.contains("unreachable!") {
                        "unreachable!()"
                    } else if trimmed.contains(".unwrap()") {
                        ".unwrap()"
                    } else {
                        ".expect()"
                    }
                ),
                suggestion: Some(
                    "Replace panicking calls with error handling that returns an error code \
                     to C. For truly unrecoverable errors inside FFI callbacks, use \
                     `std::process::abort()` instead of `panic!()`."
                        .to_string(),
                ),
            });
        }

        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if depth <= 0 {
            break;
        }
    }

    issues
}
