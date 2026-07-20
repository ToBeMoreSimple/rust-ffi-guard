use crate::report::{Issue, Severity};
use crate::scanner::ReprCStruct;

/// #[repr(C)] structs with raw pointer fields should probably have a Drop impl
/// or explicit documentation about ownership.
pub fn check_repr_c_missing(s: &ReprCStruct, file: &str) -> Vec<Issue> {
    let mut issues = Vec::new();

    if !s.has_drop_impl {
        issues.push(Issue {
            severity: Severity::Warning,
            check: "repr-c-no-drop",
            file: file.to_string(),
            line: s.line,
            column: 1,
            message: format!(
                "#[repr(C)] struct `{}` contains raw pointer fields but has no Drop impl — \
                 ensure ownership of the pointed-to memory is documented",
                s.name
            ),
            suggestion: Some(format!(
                "Consider implementing Drop for `{}`, or document: \
                 who allocates and who frees the pointed-to memory.",
                s.name
            )),
        });
    }

    if s.field_count == 0 {
        issues.push(Issue {
            severity: Severity::Info,
            check: "repr-c-empty",
            file: file.to_string(),
            line: s.line,
            column: 1,
            message: format!(
                "#[repr(C)] struct `{}` has zero fields — typically used as an opaque handle. \
                 This is fine if intentional.",
                s.name
            ),
            suggestion: None,
        });
    }

    issues
}
