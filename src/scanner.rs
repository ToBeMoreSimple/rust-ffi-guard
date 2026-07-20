use crate::checks::{
    check_callback_body_panics, check_callback_types, check_extern_fn_null_return,
    check_ffi_from_raw_parts, check_ffi_ownership, check_ffi_ptr_deref, check_repr_c_layout,
    check_repr_c_missing, check_repr_transparent, check_unsafe_sprawl,
    check_unsafe_without_safety_doc,
};
use crate::report::{Issue, Report};
use anyhow::Result;
use std::path::{Path, PathBuf};
use tree_sitter::Parser;

/// Information extracted from a single Rust source file.
#[derive(Debug, Default)]
pub struct FileInfo {
    pub path: String,
    /// extern "C" function signatures found.
    pub extern_fns: Vec<ExternFn>,
    /// unsafe blocks found.
    pub unsafe_blocks: Vec<UnsafeBlock>,
    /// #[repr(C)] structs found.
    pub repr_c_structs: Vec<ReprCStruct>,
    /// Functions taking or returning raw C pointers.
    pub ffi_typenames: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExternFn {
    pub name: String,
    pub line: usize,
    pub column: usize,
    pub abi: String,        // "C", "C++", "system", etc.
    pub params: Vec<FnParam>,
    pub ret_type: String,
    pub is_unsafe: bool,
}

#[derive(Debug, Clone)]
pub struct FnParam {
    pub name: String,
    pub ty: String,
    pub is_mut_ptr: bool,
    pub is_const_ptr: bool,
}

#[derive(Debug, Clone)]
pub struct UnsafeBlock {
    pub line: usize,
    pub line_count: usize,
    pub has_safety_comment: bool,
    pub block_text: String,
}

#[derive(Debug, Clone)]
pub struct ReprCStruct {
    pub name: String,
    pub line: usize,
    pub field_count: usize,
    pub field_names: Vec<String>,
    pub has_drop_impl: bool,
}

pub struct Scanner {
    parser: Parser,
}

impl Scanner {
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_rust::LANGUAGE.into())?;
        Ok(Self { parser })
    }

    /// Scan a Rust project directory for FFI boundary issues.
    /// If `header_dir` is provided, also validates #[repr(C)] structs against C headers.
    pub fn scan_with_headers(&mut self, project_root: &Path, header_dir: Option<&Path>) -> Result<Report> {
        let ctf = cargo_toml_find(project_root)?;
        let project_name = {
            let default_name = project_root.to_string_lossy().to_string();
            ctf.get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or(&default_name)
                .to_string()
        };

        let mut report = Report::new(project_name);
        let mut project_findings = Vec::new();

        // Walk all .rs files
        for entry in walkdir::WalkDir::new(project_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                // skip target/ and hidden dirs
                let path = e.path();
                path.extension().map_or(false, |ext| ext == "rs")
                    && !path.to_string_lossy().contains("/target/")
                    && !path.to_string_lossy().contains("/.git/")
            })
        {
            let source = std::fs::read_to_string(entry.path())?;
            let info = self.parse_file(entry.path().to_string_lossy().as_ref(), &source);
            let issues = self.check_file(&info, &source);
            project_findings.push((info, issues));
        }

        // Aggregate stats
        for (info, issues) in project_findings {
            report.stats.ffi_functions += info.extern_fns.len();
            report.stats.unsafe_blocks += info.unsafe_blocks.len();
            report.stats.repr_c_structs += info.repr_c_structs.len();
            for issue in issues {
                report.add(issue);
            }

            // Run C header layout check for this file's repr(C) structs
            if !info.repr_c_structs.is_empty() {
                let layout_issues = check_repr_c_layout(
                    &info.repr_c_structs,
                    header_dir,
                    &info.path,
                );
                for issue in layout_issues {
                    report.add(issue);
                }
            }
        }

        Ok(report)
    }

    /// Backward-compatible scan without header validation.
    pub fn scan(&mut self, project_root: &Path) -> Result<Report> {
        self.scan_with_headers(project_root, None)
    }

    /// Parse a single Rust source file with tree-sitter, extracting FFI-relevant info.
    pub fn parse_file(&mut self, path: &str, source: &str) -> FileInfo {
        let tree = self.parser.parse(source, None);
        let Some(tree) = tree else {
            return FileInfo {
                path: path.to_string(),
                ..Default::default()
            };
        };

        let root = tree.root_node();
        let source_bytes = source.as_bytes();
        let mut info = FileInfo {
            path: path.to_string(),
            ..Default::default()
        };

        self.walk_node(root, source_bytes, &mut info);
        info
    }

    fn walk_node(&self, node: tree_sitter::Node, source: &[u8], info: &mut FileInfo) {
        let kind = node.kind();

        match kind {
            "function_item" | "function_signature_item" => {
                self.extract_extern_fn(node, source, info);
            }
            "unsafe_block" => {
                self.extract_unsafe_block(node, source, info);
            }
            "struct_item" => {
                self.extract_repr_c_struct(node, source, info);
            }
            _ => {}
        }

        for child in node.named_children(&mut node.walk()) {
            self.walk_node(child, source, info);
        }
    }

    fn extract_extern_fn(&self, node: tree_sitter::Node, source: &[u8], info: &mut FileInfo) {
    // Check if this function has extern "C" ABI — either inside extern {} block
    // OR a standalone `extern "C" fn name(...)` declaration
    let mut parent = node.parent();
    let is_extern = loop {
        match parent {
            Some(p) if matches!(p.kind(), "foreign_mod_item" | "extern_block" | "extern_modifier") => {
                break true;
            }
            Some(p) if p.kind() == "source_file" || p.kind() == "block" => break false,
            Some(p) => parent = p.parent(),
            None => break false,
        }
    };

    // Also check if this is a standalone extern fn (has extern_modifier as sibling/child)
    let is_standalone_extern = if !is_extern {
        let mut cursor = node.walk();
        let mut has_ext_mod = false;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "extern_modifier" {
                has_ext_mod = true;
                break;
            }
        }
        has_ext_mod
    } else {
        false
    };

    if !is_extern && !is_standalone_extern {
        return;
    }

        let mut ef = ExternFn {
            name: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            abi: self.extract_abi(node, source),
            params: Vec::new(),
            ret_type: String::new(),
            is_unsafe: false,
        };

        // Extract function name, params, return type using fields
        if let Some(name_node) = node.child_by_field_name("name") {
            ef.name = name_node.utf8_text(source).unwrap_or("").to_string();
        }
        if let Some(params_node) = node.child_by_field_name("parameters") {
            self.extract_params(params_node, source, &mut ef.params);
        }
        if let Some(ret_node) = node.child_by_field_name("return_type") {
            ef.ret_type = ret_node.utf8_text(source).unwrap_or("").to_string();
        }

        // Check for 'unsafe' modifier (function_modifiers is a named child, not a field)
        let mut cursor = node.walk();
        ef.is_unsafe = node
            .named_children(&mut cursor)
            .any(|c| c.kind() == "function_modifiers" 
                 && c.utf8_text(source).unwrap_or("").contains("unsafe"));

        info.extern_fns.push(ef);
    }

    fn extract_abi(&self, node: tree_sitter::Node, source: &[u8]) -> String {
        // Check node itself for extern_modifier children (standalone extern fn)
        {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "extern_modifier" {
                    let text = child.utf8_text(source).unwrap_or("\"C\"");
                    if let Some(start) = text.find('"') {
                        let rest = &text[start + 1..];
                        if let Some(end) = rest.find('"') {
                            return rest[..end].to_string();
                        }
                    }
                    return "C".to_string();
                }
            }
        }

        // Walk up to find containing foreign_mod_item / extern_block
        let mut parent = node.parent();
        while let Some(p) = parent {
            match p.kind() {
                "foreign_mod_item" | "extern_block" | "extern_modifier" => {
                    let mut cursor = p.walk();
                    for child in p.named_children(&mut cursor) {
                        if child.kind() == "extern_modifier" || child.kind() == "string_literal" {
                            let text = child.utf8_text(source).unwrap_or("\"C\"");
                            if let Some(start) = text.find('"') {
                                let rest = &text[start + 1..];
                                if let Some(end) = rest.find('"') {
                                    return rest[..end].to_string();
                                }
                            }
                        }
                    }
                    return "C".to_string();
                }
                _ => parent = p.parent(),
            }
        }
        "C".to_string()
    }

    fn extract_params(&self, node: tree_sitter::Node, source: &[u8], params: &mut Vec<FnParam>) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "parameter" {
                let param_text = child.utf8_text(source).unwrap_or("");
                let is_mut_ptr = param_text.contains("*mut ");
                let is_const_ptr = param_text.contains("*const ");

                let name = child
                    .named_children(&mut child.walk())
                    .find(|c| c.kind() == "identifier")
                    .map(|c| c.utf8_text(source).unwrap_or("").to_string())
                    .unwrap_or_default();

                params.push(FnParam {
                    name,
                    ty: param_text.to_string(),
                    is_mut_ptr,
                    is_const_ptr,
                });
            }
        }
    }

    fn extract_unsafe_block(&self, node: tree_sitter::Node, source: &[u8], info: &mut FileInfo) {
        let block_text = node.utf8_text(source).unwrap_or("");
        let line_count = block_text.lines().count();
        let line = node.start_position().row + 1;

        // Check for safety comment above the block
        let has_safety_comment = self.has_safety_comment(node, source);

        info.unsafe_blocks.push(UnsafeBlock {
            line,
            line_count,
            has_safety_comment,
            block_text: block_text.to_string(),
        });
    }

    fn has_safety_comment(&self, node: tree_sitter::Node, source: &[u8]) -> bool {
        let start_byte = node.start_byte();
        if start_byte == 0 {
            return false;
        }
        // Look at text before the node for a // SAFETY: or // Safety: comment
        let max_lookback = start_byte.min(2048);
        let pre_text = &source[start_byte - max_lookback..start_byte];
        let pre_str = String::from_utf8_lossy(pre_text);
        let pre_str_lower = pre_str.to_lowercase();
        pre_str_lower.contains("// safety")
            || pre_str_lower.contains("// safety:")
            || pre_str_lower.contains("/// # safety")
    }

    fn extract_repr_c_struct(&self, node: tree_sitter::Node, source: &[u8], info: &mut FileInfo) {
        // Check if this struct has #[repr(C)] attribute
        let text_before = self.text_before_node(node, source, 512);
        if !text_before.contains("repr") || !text_before.contains('C') {
            return;
        }

        let mut name = String::new();
        let mut field_count = 0;
        let mut field_names = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "type_identifier" if name.is_empty() => {
                    name = child.utf8_text(source).unwrap_or("").to_string();
                }
                "field_declaration_list" => {
                    let mut f_cursor = child.walk();
                    for fc in child.named_children(&mut f_cursor) {
                        if fc.kind() == "field_declaration" {
                            field_count += 1;
                            // Extract field name: find field_identifier in declaration
                            let mut fc_cursor = fc.walk();
                            let mut fname = None;
                            for fc_child in fc.named_children(&mut fc_cursor) {
                                if fc_child.kind() == "field_identifier" {
                                    fname = fc_child.utf8_text(source).ok().map(|s| s.to_string());
                                    break;
                                }
                            }
                            if let Some(name) = fname {
                                field_names.push(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Check if there's a Drop impl later — we can't know from this file alone,
        // but we flag structs with raw pointers that lack explicit Drop.
        let struct_text = node.utf8_text(source).unwrap_or("");
        let has_raw_ptr = struct_text.contains("*mut ") || struct_text.contains("*const ");
        let has_drop_impl_if_needed = !has_raw_ptr; // heuristic: if no raw ptrs, Drop not critical

        info.repr_c_structs.push(ReprCStruct {
            name,
            line: node.start_position().row + 1,
            field_count,
            field_names,
            has_drop_impl: has_drop_impl_if_needed,
        });
    }

    fn text_before_node(&self, node: tree_sitter::Node, source: &[u8], lookback: usize) -> String {
        let start = node.start_byte();
        let begin = start.saturating_sub(lookback);
        String::from_utf8_lossy(&source[begin..start]).to_string()
    }

    /// Run all safety checks on a parsed file.
    pub fn check_file(&self, info: &FileInfo, file_source: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Check 0: callback types in the file
        let has_extern_c_types = file_source.contains("extern \"C\" fn");
        issues.extend(check_callback_types(&info.path, file_source, has_extern_c_types));

        // Check 1: extern functions returning raw pointers without docs
        for ef in &info.extern_fns {
            issues.extend(check_extern_fn_null_return(ef, &info.path));
            // Check for panics inside extern fn bodies
            issues.extend(check_callback_body_panics(ef, file_source, &info.path));
        }

        // Check 2: #[repr(C)] structs with raw pointers
        for s in &info.repr_c_structs {
            issues.extend(check_repr_c_missing(s, &info.path));
            issues.extend(check_repr_transparent(s, &info.path));
        }

        // Check 3: large unsafe blocks + from_raw_parts audit
        let has_ffi_ptrs = info.extern_fns.iter().any(|ef| {
            ef.params.iter().any(|p| p.is_mut_ptr || p.is_const_ptr)
        });
        for ub in &info.unsafe_blocks {
            issues.extend(check_unsafe_sprawl(ub, &info.path));
            issues.extend(check_unsafe_without_safety_doc(ub, &info.path));
            issues.extend(check_ffi_from_raw_parts(ub, &ub.block_text, &info.path, has_ffi_ptrs));
            issues.extend(check_ffi_ptr_deref(ub, &ub.block_text, &info.path, has_ffi_ptrs));
        }

        // Check 4: FFI ownership patterns
        issues.extend(check_ffi_ownership(info));

        issues
    }
}

fn cargo_toml_find(dir: &Path) -> Result<toml::Table> {
    let ct_path = dir.join("Cargo.toml");
    let content = std::fs::read_to_string(&ct_path)?;
    Ok(toml::from_str(&content)?)
}
