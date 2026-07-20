use crate::report::{Issue, Severity};
use crate::scanner::ExternFn;

/// extern "C" functions returning `*mut T` or `*const T` need null-check guidance.
pub fn check_extern_fn_null_return(ef: &ExternFn, file: &str) -> Vec<Issue> {
    let mut issues = Vec::new();

    let returns_ptr = ef.ret_type.contains("*mut ") || ef.ret_type.contains("*const ");
    if !returns_ptr || ef.ret_type.is_empty() {
        return issues;
    }

    issues.push(Issue {
        severity: Severity::Warning,
        check: "extern-fn-null-return",
        file: file.to_string(),
        line: ef.line,
        column: ef.column,
        message: format!(
            "extern \"{}\" fn `{}` returns a raw pointer `{}` — callers may not null-check it",
            ef.abi, ef.name, ef.ret_type.trim()
        ),
        suggestion: Some(format!(
            "Wrap in a safe function that returns `Option<&T>` or `Result<&T, ...>`: \
             check for null immediately after the FFI call and convert to a safe Rust type."
        )),
    });

    if !ef.is_unsafe {
        issues.push(Issue {
            severity: Severity::Error,
            check: "extern-fn-not-unsafe",
            file: file.to_string(),
            line: ef.line,
            column: ef.column,
            message: format!(
                "extern \"{}\" fn `{}` is not marked `unsafe` — calling it is always unsafe",
                ef.abi, ef.name
            ),
            suggestion: Some("Add `unsafe` keyword before `fn`.".to_string()),
        });
    }

    issues
}
