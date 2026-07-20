use clap::{Parser, Subcommand};
use colored::Colorize;
use ffi_guard::{report::Severity, Scanner};

#[derive(Parser)]
#[command(name = "ffi-guard", version, about = "AI-native Rust FFI safety auditor — catches what clippy misses across C/C++ boundaries")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Rust project for FFI safety issues
    Scan {
        #[arg(default_value = ".")]
        path: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Start as an MCP server (stdin/stdout JSON-RPC)
    Mcp,

    /// List all available safety checks
    Checks,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan { path, json } => {
            let project_root = std::path::Path::new(&path).canonicalize()?;
            let mut scanner = Scanner::new()?;
            let report = scanner.scan(&project_root)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }

            if report.stats.errors > 0 {
                std::process::exit(1);
            }
        }

        Command::Mcp => {
            ffi_guard::mcp::run_mcp_server()?;
        }

        Command::Checks => {
            println!("ffi-guard — safety checks:\n");
            for check in CHECKS {
                let icon = match check.severity {
                    "error" => "✗".red(),
                    "warning" => "⚠".yellow(),
                    _ => "ℹ".dimmed(),
                };
                println!(
                    "  {icon} {:<30} {}",
                    check.id.bold(),
                    check.description.dimmed()
                );
            }
        }
    }

    Ok(())
}

struct CheckInfo {
    id: &'static str,
    severity: &'static str,
    description: &'static str,
}

const CHECKS: &[CheckInfo] = &[
    CheckInfo { id: "extern-fn-null-return", severity: "warning", description: "extern fn returns raw pointer — callers may not null-check" },
    CheckInfo { id: "extern-fn-not-unsafe", severity: "error", description: "extern fn not marked unsafe" },
    CheckInfo { id: "repr-c-no-drop", severity: "warning", description: "#[repr(C)] struct with raw pointers, no Drop impl" },
    CheckInfo { id: "unsafe-sprawl", severity: "warning", description: "unsafe block >10 lines — split into smaller blocks" },
    CheckInfo { id: "unsafe-no-safety-doc", severity: "warning", description: "unsafe block missing // SAFETY: comment" },
    CheckInfo { id: "ffi-ownership-ambiguous", severity: "warning", description: "extern fn accepts AND returns raw pointers — who owns what?" },
];

fn print_report(report: &ffi_guard::Report) {
    println!();
    println!("{}", "══ ffi-guard audit report ══".bold().cyan());
    println!("  Project: {}\n", report.project.bold());

    if report.issues.is_empty() {
        println!("  {}\n", "✓ No FFI safety issues found.".green());
        return;
    }

    for issue in &report.issues {
        let icon = match issue.severity {
            Severity::Error => "✗".red().bold(),
            Severity::Warning => "⚠".yellow().bold(),
            Severity::Info => "ℹ".blue().bold(),
        };
        println!(
            "  {} {} {}:{} — {}",
            icon,
            format!("[{}]", issue.check).dimmed(),
            issue.file,
            issue.line.to_string().yellow(),
            issue.message
        );
        if let Some(ref s) = issue.suggestion {
            println!("    {} {}", "→".dimmed(), s.dimmed());
        }
        println!();
    }

    let s = &report.stats;
    println!("{}", "── Summary ──".bold());
    println!("  FFI functions: {}   unsafe blocks: {}   repr(C) structs: {}",
        s.ffi_functions, s.unsafe_blocks, s.repr_c_structs);
    println!(
        "  {} errors   {} warnings   {} info   — {} total issues\n",
        s.errors.to_string().red().bold(),
        s.warnings.to_string().yellow().bold(),
        s.infos.to_string().blue().bold(),
        s.total_issues
    );
}
