//! `check_ffi_ptr_deref` — detect raw pointer dereferences in FFI contexts
//! without preceding null checks.
//!
//! Pattern: `*ptr` or `&*ptr` inside unsafe blocks where `ptr` comes from C FFI.
//! If the C side passes NULL, this is immediate UB.

use crate::report::{Issue, Severity};
use crate::scanner::UnsafeBlock;

/// Check an unsafe block for raw pointer dereferences without null guards.
pub fn check_ffi_ptr_deref(
    block: &UnsafeBlock,
    block_text: &str,
    file: &str,
    has_ffi_ptrs: bool,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    if !has_ffi_ptrs {
        return issues;
    }

    let lines: Vec<&str> = block_text.lines().collect();

    // Scan for patterns like:
    //   *ptr
    //   &*ptr
    //   &mut *ptr
    //   ptr.read()
    //   ptr.add(offset)
    for (i, line) in lines.iter().enumerate() {
        let line_num = block.line + i;
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }

        let has_ptr_deref = trimmed.contains("&*") || trimmed.contains("&mut *")
            || (trimmed.contains('*') && !trimmed.contains("//") && !trimmed.contains("*/"));

        let has_destructive = trimmed.contains(".read()") || trimmed.contains(".add(")
            || trimmed.contains(".offset(") || trimmed.contains(".sub(");

        if !has_ptr_deref && !has_destructive {
            continue;
        }

        // Check if preceding lines in this block have a null check
        let has_null_check = lines[..i].iter().any(|l| {
            let lt = l.trim();
            lt.contains("is_null()") || lt.contains("is_null")
                || lt.contains(".is_none()") || lt.contains("== 0")
                || lt.contains("== null") || lt.contains("!= 0")
        });

        if !has_null_check {
            let op = if has_destructive {
                lines[i].trim().to_string()
            } else {
                "raw pointer dereference".to_string()
            };

            issues.push(Issue {
                severity: Severity::Error,
                check: "ffi-ptr-deref-no-nullcheck",
                file: file.to_string(),
                line: line_num,
                column: 1,
                message: format!(
                    "FFI raw pointer operation without preceding null check: `{op}`. \
                     If the C side passes NULL, this causes immediate undefined behavior."
                ),
                suggestion: Some(
                    "Add `if !ptr.is_null() { ... }` or `ptr.as_ref()` with a check before \
                     dereferencing. For optional FFI pointers, use `NonNull<T>` to enforce \
                     non-null at the type level."
                        .to_string(),
                ),
            });
        }
    }

    issues
}
