//! Raw JSON-RPC MCP server. No framework dependency.
//! Talks the Model Context Protocol over stdin/stdout.

use crate::Scanner;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

pub fn run_mcp_server() -> anyhow::Result<()> {
    let scanner = Mutex::new(Scanner::new()?);

    eprintln!("ffi-guard MCP server v0.1.0 started");

    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc":"2.0","error":{"code":-32700,"message":format!("Parse error: {e}")},"id":null});
                let mut out = stdout.lock();
                let _ = writeln!(out, "{}", serde_json::to_string(&err).unwrap_or_default());
                let _ = out.flush();
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned();

        let response = match method {
            "initialize" => handle_initialize(id),
            "tools/list" => handle_tools_list(id),
            "tools/call" => handle_tool_call(id, params, &scanner),
            "notifications/initialized" => continue, // no response needed
            _ => json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {method}")},
                "id": id
            }),
        };

        let mut out = stdout.lock();
        let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap_or_default());
        let _ = out.flush();
    }

    Ok(())
}

fn handle_initialize(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "ffi-guard",
                "version": "0.1.0"
            }
        },
        "id": id
    })
}

fn handle_tools_list(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "tools": [
                {
                    "name": "scan_project",
                    "description": "Scan a Rust project directory for FFI boundary safety issues. Returns a report of all found issues with severity levels, file locations, and fix suggestions.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "project_path": {
                                "type": "string",
                                "description": "Absolute path to the Rust project root (must contain Cargo.toml)"
                            },
                            "headers_dir": {
                                "type": "string",
                                "description": "Optional path to C/C++ header directory for #[repr(C)] layout validation"
                            }
                        },
                        "required": ["project_path"]
                    }
                },
                {
                    "name": "list_checks",
                    "description": "List all available FFI safety check categories and what each one looks for.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "check_file",
                    "description": "Analyze a specific Rust file for FFI issues. Returns detailed findings for that file only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Absolute path to the Rust source file"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            ]
        },
        "id": id
    })
}

fn handle_tool_call(id: Option<Value>, params: Option<Value>, scanner: &Mutex<Scanner>) -> Value {
    let tool_name = params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let arguments = params
        .as_ref()
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);

    match tool_name {
        "scan_project" => {
            let project_path = arguments
                .get("project_path")
                .and_then(|v| v.as_str())
                .unwrap_or(".");

            let path = std::path::Path::new(project_path);
            let headers_dir = arguments
                .get("headers_dir")
                .and_then(|v| v.as_str())
                .map(|h| std::path::Path::new(h));

            if !path.join("Cargo.toml").exists() {
                return json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [{"type": "text", "text": format!("Error: No Cargo.toml found at {project_path}")}]
                    },
                    "id": id
                });
            }

            let mut s = scanner.lock().unwrap();
            match s.scan_with_headers(path, headers_dir) {
                Ok(report) => {
                    let text = serde_json::to_string_pretty(&report)
                        .unwrap_or_else(|e| format!("Serialization error: {e}"));
                    json!({
                        "jsonrpc": "2.0",
                        "result": { "content": [{"type": "text", "text": text}] },
                        "id": id
                    })
                }
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "result": { "content": [{"type": "text", "text": format!("Scan error: {e}")}] },
                    "id": id
                }),
            }
        }

        "list_checks" => {
            let checks = json!({
                "checks": [
                    {"id": "extern-fn-null-return", "severity": "warning",
                     "desc": "extern C fn returns raw pointer — callers may not null-check"},
                    {"id": "extern-fn-not-unsafe", "severity": "error",
                     "desc": "extern fn not marked unsafe — calling it is always UB"},
                    {"id": "repr-c-no-drop", "severity": "warning",
                     "desc": "#[repr(C)] struct with raw pointer fields — who frees the memory?"},
                    {"id": "unsafe-sprawl", "severity": "warning",
                     "desc": "unsafe block spans >10 lines — split into smaller, auditable blocks"},
                    {"id": "unsafe-no-safety-doc", "severity": "warning",
                     "desc": "unsafe block missing // SAFETY: comment"},
                    {"id": "ffi-ownership-ambiguous", "severity": "warning",
                     "desc": "extern fn both takes and returns raw pointers — ownership unclear"}
                ]
            });
            json!({
                "jsonrpc": "2.0",
                "result": { "content": [{"type": "text", "text": serde_json::to_string_pretty(&checks).unwrap_or_default()}] },
                "id": id
            })
        }

        "check_file" => {
            let file_path = arguments
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let path = std::path::Path::new(file_path);
            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    return json!({
                        "jsonrpc": "2.0",
                        "result": { "content": [{"type": "text", "text": format!("Error: {e}")}] },
                        "id": id
                    });
                }
            };

            let mut s = scanner.lock().unwrap();
            let info = s.parse_file(file_path, &source);
            let issues: Vec<_> = s.check_file(&info);

            let result = json!({
                "file": file_path,
                "extern_functions": info.extern_fns.len(),
                "unsafe_blocks": info.unsafe_blocks.len(),
                "repr_c_structs": info.repr_c_structs.len(),
                "issues": issues
            });

            json!({
                "jsonrpc": "2.0",
                "result": { "content": [{"type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default()}] },
                "id": id
            })
        }

        _ => json!({
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": format!("Unknown tool: {tool_name}")},
            "id": id
        }),
    }
}
