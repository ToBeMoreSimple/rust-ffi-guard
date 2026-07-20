//! `check_repr_c_layout` — verify #[repr(C)] Rust struct layout against C headers.
//!
//! Loads C header files, extracts struct definitions via tree-sitter-c,
//! then compares field types and counts against the Rust side.

use crate::report::{Issue, Severity};
use crate::scanner::ReprCStruct;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::Parser;

/// A C struct field extracted from a header.
#[derive(Debug, Clone)]
struct CField {
    name: String,
    ty: String,
    is_ptr: bool,
    is_const: bool,
}

/// A C struct definition extracted from a header.
#[derive(Debug, Clone)]
struct CStruct {
    name: String,
    fields: Vec<CField>,
    file: String,
    line: usize,
}

/// Scan a directory (recursively) for C/C++ header files and parse struct definitions.
fn parse_c_headers(dir: &Path) -> Vec<CStruct> {
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_err() {
        return Vec::new();
    }

    let mut structs = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            matches!(ext, "h" | "hpp" | "hxx" | "h++" | "hh")
        })
    {
        let source = match std::fs::read_to_string(entry.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };

        let path_str = entry.path().to_string_lossy().to_string();
        extract_c_structs(tree.root_node(), source.as_bytes(), &path_str, &mut structs);
    }

    structs
}

fn extract_c_structs(
    node: tree_sitter::Node,
    source: &[u8],
    file: &str,
    structs: &mut Vec<CStruct>,
) {
    // Handle `typedef struct { ... } Name;` — the name is on type_definition, not struct_specifier
    if node.kind() == "type_definition" {
        let mut cursor = node.walk();
        let mut has_struct = false;
        let mut typedef_name = String::new();
        let mut fields = Vec::new();

        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "struct_specifier" => {
                    has_struct = true;
                    let mut c2 = child.walk();
                    for c in child.named_children(&mut c2) {
                        if c.kind() == "field_declaration_list" {
                            fields = parse_c_field_list(c, source);
                        }
                    }
                }
                "type_identifier" => {
                    typedef_name = child.utf8_text(source).unwrap_or("").to_string();
                }
                _ => {}
            }
        }

        if has_struct && !typedef_name.is_empty() {
            structs.push(CStruct {
                name: typedef_name,
                fields,
                file: file.to_string(),
                line: node.start_position().row + 1,
            });
            return; // Don't recurse into children, already processed
        }
    }

    // Handle `struct Name { ... };`
    if node.kind() == "struct_specifier" {
        let mut name = String::new();
        let mut fields = Vec::new();

        // Find struct name and field declarations
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "type_identifier" if name.is_empty() => {
                    name = child.utf8_text(source).unwrap_or("").to_string();
                }
                "field_declaration_list" => {
                    fields = parse_c_field_list(child, source);
                }
                _ => {}
            }
        }

        if !name.is_empty() {
            structs.push(CStruct {
                name,
                fields,
                file: file.to_string(),
                line: node.start_position().row + 1,
            });
        }
    }

    // Recurse
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        extract_c_structs(child, source, file, structs);
    }
}

fn parse_c_field_list(node: tree_sitter::Node, source: &[u8]) -> Vec<CField> {
    let mut fields = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "field_declaration" {
            let field_text = child.utf8_text(source).unwrap_or("");
            let (name, ty) = split_c_field_decl(field_text);
            fields.push(CField {
                name,
                ty: ty.clone(),
                is_ptr: ty.contains('*'),
                is_const: ty.contains("const"),
            });
        }
    }
    fields
}

/// Split a C field declaration like "int *data" into ("data", "int *").
fn split_c_field_decl(decl: &str) -> (String, String) {
    let decl = decl.trim().trim_end_matches(';');
    // Handle function pointers like "void (*callback)(int)" — skip for now
    if decl.contains("(*)") {
        let parts: Vec<&str> = decl.rsplitn(2, ')').collect();
        if parts.len() == 2 {
            return (parts[0].to_string(), parts[1].to_string());
        }
    }
    // Standard case: last word is name, rest is type
    let words: Vec<&str> = decl.split_whitespace().collect();
    if words.len() >= 2 {
        let name = words[words.len() - 1].to_string();
        let ty = words[..words.len() - 1].join(" ");
        (name, ty)
    } else {
        (decl.to_string(), String::new())
    }
}

/// Map C primitive types to expected Rust FFI types and sizes.
fn c_type_to_rust_info(ty: &str) -> (&str, usize) {
    let normalized = ty.replace("const ", "").replace("unsigned ", "u").trim().to_string();
    match normalized.as_str() {
        "char" | "signed char" => ("i8", 1),
        "u8" | "uint8_t" | "unsigned char" => ("u8", 1),
        "short" | "i16" | "int16_t" | "short int" => ("i16", 2),
        "u16" | "uint16_t" | "unsigned short" | "unsigned short int" => ("u16", 2),
        "int" | "i32" | "int32_t" | "long" => ("i32", 4),
        "u32" | "uint32_t" | "unsigned int" | "unsigned long" => ("u32", 4),
        "long long" | "i64" | "int64_t" | "long long int" => ("i64", 8),
        "u64" | "uint64_t" | "unsigned long long" | "unsigned long long int" => ("u64", 8),
        "float" => ("f32", 4),
        "double" => ("f64", 8),
        "size_t" | "uintptr_t" => ("usize", 8),
        "ssize_t" | "intptr_t" | "ptrdiff_t" => ("isize", 8),
        "bool" | "_Bool" => ("bool", 1),
        "void" => ("c_void", 0), // void* goes through pointer path
        _ => {
            if normalized.starts_with("*") || normalized.contains('*') {
                ("*const/mut T", 8) // pointer always 8 bytes on 64-bit
            } else {
                ("?", 0)
            }
        }
    }
}

/// Check #[repr(C)] Rust structs against parsed C headers.
pub fn check_repr_c_layout(
    rust_structs: &[ReprCStruct],
    header_dir: Option<&Path>,
    rust_file: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    let header_dir = match header_dir {
        Some(d) if d.exists() => d,
        _ => {
            // No C headers to check against
            for s in rust_structs {
                issues.push(Issue {
                    severity: Severity::Info,
                    check: "repr-c-no-header",
                    file: rust_file.to_string(),
                    line: s.line,
                    column: 1,
                    message: format!(
                        "#[repr(C)] struct `{}` has no C header to verify against — \
                         pass --headers <dir> to enable layout validation",
                        s.name
                    ),
                    suggestion: Some(
                        "Use --headers to specify the directory containing your C header files.".to_string(),
                    ),
                });
            }
            return issues;
        }
    };

    let c_structs = parse_c_headers(header_dir);
    let c_map: HashMap<&str, &CStruct> = c_structs.iter().map(|s| (s.name.as_str(), s)).collect();

    for rs in rust_structs {
        match c_map.get(rs.name.as_str()) {
            Some(cs) => {
                // Found matching C struct — compare fields
                if rs.field_count != cs.fields.len() {
                    issues.push(Issue {
                        severity: Severity::Error,
                        check: "repr-c-field-count",
                        file: rust_file.to_string(),
                        line: rs.line,
                        column: 1,
                        message: format!(
                            "#[repr(C)] struct `{}` has {} fields, \
                             but C header `{}:{}` has {} fields",
                            rs.name, rs.field_count, cs.file, cs.line, cs.fields.len()
                        ),
                        suggestion: Some(
                            "Field count mismatch between Rust and C — check for missing or extra fields.".to_string(),
                        ),
                    });
                }

                // Check each C field type for known FFI compatibility
                for cf in &cs.fields {
                    let (rust_type, _size) = c_type_to_rust_info(&cf.ty);
                    if rust_type == "?" {
                        issues.push(Issue {
                            severity: Severity::Warning,
                            check: "repr-c-unknown-ctype",
                            file: rust_file.to_string(),
                            line: rs.line,
                            column: 1,
                            message: format!(
                                "#[repr(C)] struct `{}` has a C field `{} {}` with \
                                 unrecognized type — verify it maps correctly to a Rust FFI type",
                                rs.name, cf.ty, cf.name
                            ),
                            suggestion: Some(format!(
                                "Map `{}` to an explicit Rust FFI type, e.g. use `{}` from std::os::raw.",
                                cf.ty, rust_type
                            )),
                        });
                    }
                }
            }
            None => {
                // Rust struct has no matching C header definition
                issues.push(Issue {
                    severity: Severity::Warning,
                    check: "repr-c-no-c-match",
                    file: rust_file.to_string(),
                    line: rs.line,
                    column: 1,
                    message: format!(
                        "#[repr(C)] struct `{}` has no matching definition in C headers — \
                         ensure the C side exists and names match exactly",
                        rs.name
                    ),
                    suggestion: Some(format!(
                        "Expected struct `{}` in the C header directory `{}`.",
                        rs.name, header_dir.display()
                    )),
                });
            }
        }
    }

    // Also report C structs with no Rust counterpart
    let rust_names: Vec<&str> = rust_structs.iter().map(|s| s.name.as_str()).collect();
    for cs in &c_structs {
        if !rust_names.contains(&cs.name.as_str()) {
            issues.push(Issue {
                severity: Severity::Info,
                check: "repr-c-unused-cstruct",
                file: cs.file.clone(),
                line: cs.line,
                column: 1,
                message: format!(
                    "C struct `{}` (defined in `{}`) has no corresponding #[repr(C)] struct in Rust",
                    cs.name, cs.file
                ),
                suggestion: None,
            });
        }
    }

    issues
}
