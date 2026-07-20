# rust-ffi-guard

AI-native Rust FFI safety auditor — catches what clippy misses across C/C++ boundaries.

[![GitHub stars](https://img.shields.io/github/stars/ToBeMoreSimple/rust-ffi-guard?style=social)](https://github.com/ToBeMoreSimple/rust-ffi-guard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Tested against real OpenHarmony Rust codebases — 88 FFI functions, 126 unsafe blocks, 240+ findings.

```
$ ffi-guard scan

══ ffi-guard audit report ══
  Project: my-ffi-lib

  ✗ [extern-fn-not-unsafe] src/ffi.rs:7 — extern "C" fn `get_buffer` is not marked `unsafe`
    → Add `unsafe` keyword before `fn`.

  ✗ [repr-c-field-order] src/types.rs:61 — struct `Triplet` same fields but WRONG ORDER
    C order:   x, y, z
    Rust order: z, x, y
    → Silent memory corruption at runtime!

  ✗ [ffi-ptr-deref-no-nullcheck] src/ffi.rs:23 — raw pointer deref without null check

── Summary ──
  FFI functions: 24   unsafe blocks: 26   repr(C) structs: 3
  8 errors   48 warnings   3 info   — 59 total issues
```

## 17 safety checks

### FFI Function Safety (5)
| Check | Severity | What |
|-------|----------|------|
| `extern-fn-not-unsafe` | ✗ error | extern fn missing `unsafe` keyword |
| `extern-fn-null-return` | ⚠ warning | extern fn returns raw pointer — callers skip null check |
| `ffi-ownership-ambiguous` | ⚠ warning | extern fn both accepts and returns raw pointers |
| `ffi-callback-panic` | ⚠ warning | extern C fn callbacks that may panic across FFI boundary |
| `ffi-cstring-unwrap` | ⚠ warning | CString::new().unwrap() in FFI — interior null byte panics |

### repr(C) Validation (7)
| Check | Severity | What |
|-------|----------|------|
| `repr-c-no-drop` | ⚠ warning | Struct with raw pointers, no Drop impl |
| `repr-c-should-be-transparent` | ⚠ warning | Single-field struct — use #[repr(transparent)] |
| `repr-c-field-count` | ✗ error | Field count mismatch Rust vs C header |
| `repr-c-field-order` | ✗ error | Same field names, wrong order — silent UB |
| `repr-c-field-names` | ⚠ warning | Field names partially mismatch C header |
| `repr-c-unknown-ctype` | ⚠ warning | C field type unrecognized — verify FFI mapping |
| `repr-c-no-c-match` | ⚠ warning | Rust struct has no matching C header definition |
| `repr-c-unused-cstruct` | ℹ info | C header struct with no Rust counterpart |

### Unsafe Block Audit (4)
| Check | Severity | What |
|-------|----------|------|
| `unsafe-sprawl` | ⚠ warning | unsafe block > 10 lines — split into smaller blocks |
| `unsafe-no-safety-doc` | ⚠ warning | unsafe block missing `// SAFETY:` comment |
| `ffi-from-raw-parts` | ✗ error | slice::from_raw_parts / CStr::from_ptr on FFI data |
| `ffi-ptr-deref-no-nullcheck` | ✗ error | FFI raw pointer deref without null check |

## Quick start

```bash
cargo install ffi-guard

# Scan a project
ffi-guard scan

# With C header validation
ffi-guard scan --headers ./include

# JSON output (for CI)
ffi-guard scan --json

# List all checks
ffi-guard checks
```

## MCP server mode

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

Then ask your AI agent: "Check my FFI boundaries for safety issues"

## Trophy hunter

Auto-scan crates.io for FFI bugs:

```bash
ffi-guard trophy --count 50 --keyword ffi
ffi-guard trophy --count 100 --json > findings.json
```

## vs. existing tools

| Tool | Rust side | C/C++ side | Cross-boundary | FFI-specific | Setup |
|------|:---:|:---:|:---:|:---:|------|
| clippy | ✓ | ✗ | ✗ | ✗ | built-in |
| Miri | runtime | ✗ | ✗ | ✗ | nightly |
| bindgen | codegen | headers | ✗ | ✗ | clang |
| FFIChecker | ✓ | ✓ | ✓ | ✓ | nightly+LLVM |
| **ffi-guard** | ✓ | ✓ | ✓ | ✓ | **stable Rust** |

FFIChecker (ESORICS 2022) is unmaintained, requires nightly+LLVM 13.
ffi-guard runs on stable Rust, no external deps, MCP integration.

## Build from source

```bash
git clone https://github.com/ToBeMoreSimple/rust-ffi-guard.git
cd rust-ffi-guard
cargo build --release
```

## License

MIT
