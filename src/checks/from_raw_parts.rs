//! `check_ffi_from_raw_parts` — detect `slice::from_raw_parts` and similar
//! unsafe pointer-to-slice conversions where the pointer and/or length come
//! from FFI (C/C++) sources.
//!
//! These are the most dangerous FFI operations:
//! - Invalid pointer → UB
//! - Wrong length → buffer overread
//! - C side controls both pointer AND length — zero compile-time guarantees

use crate::report::{Issue, Severity};
use crate::scanner::UnsafeBlock;

/// Known unsafe slice-from-pointer functions.
/// Ordered longest-first to avoid substring false matches.
const FROM_RAW_FUNCTIONS: &[&str] = &[
    "slice::from_raw_parts_mut",
    "slice::from_raw_parts",
    "str::from_utf8_unchecked",
    "CStr::from_ptr",
];

/// Check unsafe blocks for `from_raw_parts` / `from_ptr` calls that operate on FFI data.
pub fn check_ffi_from_raw_parts(
    block: &UnsafeBlock,
    block_text: &str,
    file: &str,
    has_ffi_ptr_params: bool, // true if the enclosing function takes raw pointers
) -> Vec<Issue> {
    let mut issues = Vec::new();

    for func in FROM_RAW_FUNCTIONS {
        if block_text.contains(func) {
            let severity = if has_ffi_ptr_params {
                Severity::Error
            } else {
                Severity::Warning
            };

            issues.push(Issue {
                severity,
                check: "ffi-from-raw-parts",
                file: file.to_string(),
                line: block.line,
                column: 1,
                message: format!(
                    "`{func}()` called inside unsafe block — \
                     pointer and/or length likely originate from C FFI. \
                     A wrong value from the C side causes immediate undefined behavior.",
                ),
                suggestion: Some(
                    "Add explicit bounds checks before constructing the slice/str. \
                     Verify: pointer non-null, length within expected bounds, \
                     data valid for the target type."
                        .to_string(),
                ),
            });
            break; // only flag once per block per function group
        }
    }

    issues
}
