# rust-ffi-guard

AI-native Rust FFI safety auditor — catches what clippy misses across C/C++ boundaries.

[![Crates.io](https://img.shields.io/crates/v/ffi-guard)](https://crates.io/crates/ffi-guard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```
$ ffi-guard scan

══ ffi-guard audit report ══
  Project: my-ffi-lib

  ✗ [extern-fn-not-unsafe] src/ffi.rs:7 — extern "C" fn `get_buffer` is not marked `unsafe`
    → Add `unsafe` keyword before `fn`.

  ⚠ [ffi-ownership-ambiguous] src/ffi.rs:56 — extern fn `transform` both accepts and returns
    raw pointers — ownership semantics are ambiguous. Who allocates? Who frees?

  ⚠ [repr-c-no-drop] src/types.rs:23 — #[repr(C)] struct `Context` contains raw pointer
    fields but has no Drop impl

── Summary ──
  FFI functions: 12   unsafe blocks: 5   repr(C) structs: 3
  3 errors   8 warnings   1 info   — 12 total issues
```

## What it catches

| Check | Severity | What |
|-------|----------|------|
| `extern-fn-not-unsafe` | ✗ error | extern fn missing `unsafe` keyword |
| `extern-fn-null-return` | ⚠ warning | extern fn returns raw pointer — callers skip null check |
| `repr-c-no-drop` | ⚠ warning | `#[repr(C)]` struct with raw ptrs, no Drop impl |
| `unsafe-sprawl` | ⚠ warning | unsafe block > 10 lines — split into auditable pieces |
| `unsafe-no-safety-doc` | ⚠ warning | unsafe block missing `// SAFETY:` comment |
| `ffi-ownership-ambiguous` | ⚠ warning | extern fn both accepts and returns raw pointers |

## Quick start

```bash
cargo install ffi-guard

# Scan a project
cd your-rust-ffi-project
ffi-guard scan

# JSON output (for CI)
ffi-guard scan --json

# List all checks
ffi-guard checks
```

## MCP server mode (AI agent integration)

```bash
ffi-guard mcp
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ffi-guard": {
      "command": "ffi-guard",
      "args": ["mcp"]
    }
  }
}
```

Then ask your AI agent:

> "Check my FFI boundaries for safety issues"

## vs. existing tools

| Tool | Sees Rust side | Sees C/C++ side | Cross-boundary | FFI-specific |
|------|:---:|:---:|:---:|:---:|
| clippy | ✓ | ✗ | ✗ | ✗ |
| Miri | runtime only | ✗ | ✗ | ✗ |
| bindgen | codegen only | headers only | ✗ | ✗ |
| **ffi-guard** | ✓ | planned | ✓ | ✓ |

## Build from source

```bash
git clone https://github.com/yinyaode/rust-ffi-guard.git
cd rust-ffi-guard
cargo build --release
```

## License

MIT
