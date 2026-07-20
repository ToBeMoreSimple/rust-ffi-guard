//! `check_repr_transparent` — detect `#[repr(C)]` structs with a single
//! non-ZST field that should use `#[repr(transparent)]` instead.
//!
//! `#[repr(transparent)]` guarantees that the struct has the same ABI as its
//! single field — critical for FFI wrappers. Without it, the compiler may
//! add padding or reorder (though unlikely with repr(C), explicit is safer).

use crate::report::{Issue, Severity};
use crate::scanner::ReprCStruct;

/// Check if a `#[repr(C)]` struct with exactly one non-ZST field should
/// use `#[repr(transparent)]` instead.
///
/// This is especially important for FFI wrapper types like:
/// ```rust
/// #[repr(C)]  // should be #[repr(transparent)]
/// struct ForeignRef(*mut c_void);
/// ```
pub fn check_repr_transparent(rs: &ReprCStruct, file: &str) -> Vec<Issue> {
    if rs.field_count != 1 {
        return Vec::new();
    }

    vec![Issue {
        severity: Severity::Warning,
        check: "repr-c-should-be-transparent",
        file: file.to_string(),
        line: rs.line,
        column: 1,
        message: format!(
            "#[repr(C)] struct `{}` has only one field — \
             consider using #[repr(transparent)] instead for \
             guaranteed ABI compatibility with the inner type",
            rs.name
        ),
        suggestion: Some(
            "Replace #[repr(C)] with #[repr(transparent)]. \
             This guarantees the wrapper has identical ABI to its inner field, \
             which is what you typically want for FFI newtype wrappers."
                .to_string(),
        ),
    }]
}
