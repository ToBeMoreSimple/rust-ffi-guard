//! `check_cstring_unwrap` — detect `CString::new(...).unwrap()` calls
//! in FFI contexts where the string comes from user/external input.
//!
//! If the string contains an interior null byte (\0), CString::new returns Err,
//! and .unwrap() panics — crossing the FFI boundary with a panic is UB.

use crate::report::{Issue, Severity};
use crate::scanner::UnsafeBlock;

/// Check unsafe blocks for CString::new(...).unwrap() / .expect() patterns
/// that could panic on strings with interior null bytes.
pub fn check_cstring_unwrap(
    block: &UnsafeBlock,
    block_text: &str,
    file: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    if !block_text.contains("CString::new") {
        return issues;
    }

    for (i, line) in block_text.lines().enumerate() {
        let line_num = block.line + i;
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }

        // Pattern: CString::new(something).unwrap()
        // Pattern: CString::new(something).expect("...")
        if (trimmed.contains("CString::new(") || trimmed.contains("CStr::from_bytes_with_nul("))
            && (trimmed.contains(".unwrap()") || trimmed.contains(".expect("))
        {
            issues.push(Issue {
                severity: Severity::Warning,
                check: "ffi-cstring-unwrap",
                file: file.to_string(),
                line: line_num,
                column: 1,
                message: format!(
                    "`CString::new(...).unwrap()` in unsafe FFI context — \
                     if the string contains an interior null byte (\\0), \
                     this panics. Panic across FFI = UB."
                ),
                suggestion: Some(
                    "Use `CString::new(s).expect(\"reason\")` to document why \
                     this can't fail, or handle the error: \
                     `let cstr = CString::new(s).map_err(|e| ...)?;`"
                        .to_string(),
                ),
            });
        }
    }

    issues
}
