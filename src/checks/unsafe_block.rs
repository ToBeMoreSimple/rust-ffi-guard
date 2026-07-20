use crate::report::{Issue, Severity};
use crate::scanner::UnsafeBlock;

/// Large unsafe blocks should be split into smaller, auditable pieces.
pub fn check_unsafe_sprawl(ub: &UnsafeBlock, file: &str) -> Vec<Issue> {
    if ub.line_count <= 10 {
        return Vec::new();
    }

    vec![Issue {
        severity: Severity::Warning,
        check: "unsafe-sprawl",
        file: file.to_string(),
        line: ub.line,
        column: 1,
        message: format!(
            "unsafe block spans {} lines — \
             consider splitting into smaller unsafe blocks \
             around only the operations that truly require unsafe",
            ub.line_count
        ),
        suggestion: Some(
            "Extract safe wrappers for each unsafe operation. \
             Each unsafe block should ideally be 1-3 lines, \
             with a // SAFETY: comment explaining the invariant."
                .to_string(),
        ),
    }]
}

/// unsafe blocks without a // SAFETY: comment.
pub fn check_unsafe_without_safety_doc(ub: &UnsafeBlock, file: &str) -> Vec<Issue> {
    if ub.has_safety_comment {
        return Vec::new();
    }

    vec![Issue {
        severity: Severity::Warning,
        check: "unsafe-no-safety-doc",
        file: file.to_string(),
        line: ub.line,
        column: 1,
        message: "unsafe block missing // SAFETY: comment explaining the invariant upheld"
            .to_string(),
        suggestion: Some(
            "Add a // SAFETY: comment above this block explaining \
             which unsafe invariant is being upheld and why it's sound."
                .to_string(),
        ),
    }]
}
