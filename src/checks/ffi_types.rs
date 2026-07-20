use crate::report::{Issue, Severity};
use crate::scanner::FileInfo;

/// Check for common FFI ownership anti-patterns:
/// - `*mut T` used as a field without clear ownership semantics
/// - extern fns that both take and return pointers (ownership confusion)
pub fn check_ffi_ownership(info: &FileInfo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for ef in &info.extern_fns {
        let has_ptr_param = ef.params.iter().any(|p| p.is_mut_ptr || p.is_const_ptr);
        let returns_ptr = ef.ret_type.contains("*mut ") || ef.ret_type.contains("*const ");

        if has_ptr_param && returns_ptr {
            issues.push(Issue {
                severity: Severity::Warning,
                check: "ffi-ownership-ambiguous",
                file: info.path.clone(),
                line: ef.line,
                column: ef.column,
                message: format!(
                    "extern fn `{}` both accepts and returns raw pointers — \
                     ownership semantics are ambiguous. \
                     Who allocates? Who frees?",
                    ef.name
                ),
                suggestion: Some(format!(
                    "Document the ownership contract in a doc comment: \
                     /// # Safety \
                     /// The caller must ensure `input` is valid and will be freed by the callee. \
                     /// The returned pointer is owned by the caller and must be freed with `...`."
                )),
            });
        }
    }

    issues
}
