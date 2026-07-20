//! Trophy hunter — automatically scans crates.io for FFI bugs.
//!
//! Downloads popular crates that use FFI, runs ffi-guard on them,
//! and reports findings. Inspired by FFIChecker's trophy case.

use crate::{Report, Scanner};
use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct CrateResponse {
    crates: Vec<CrateInfo>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    name: String,
    max_stable_version: String,
    description: Option<String>,
    downloads: u64,
}

/// Result of scanning a single crate.
#[derive(Debug, serde::Serialize)]
pub struct TrophyEntry {
    pub crate_name: String,
    pub version: String,
    pub downloads: u64,
    pub description: String,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub issues: Vec<super::report::Issue>,
    pub error: Option<String>,
}

/// Hunt for FFI bugs across crates.io.
pub fn hunt(
    count: usize,
    filter_keyword: &str,
    cache_dir: &Path,
) -> Result<Vec<TrophyEntry>> {
    eprintln!("Hunting FFI bugs across top {count} crates matching '{filter_keyword}'...\n");

    let client = reqwest::blocking::Client::new();
    let url = format!(
        "https://crates.io/api/v1/crates?page=1&per_page={count}&q={filter_keyword}&sort=downloads"
    );

    let resp: CrateResponse = client
        .get(&url)
        .header("User-Agent", "ffi-guard-trophy/0.1")
        .send()?
        .json()?;

    eprintln!("Found {} crates matching query.\n", resp.crates.len());

    let mut results = Vec::new();
    for (i, ci) in resp.crates.iter().enumerate() {
        eprintln!(
            "[{}/{}] {} v{} ({} downloads)",
            i + 1,
            resp.crates.len(),
            ci.name,
            ci.max_stable_version,
            ci.downloads
        );

        match scan_crate(ci, cache_dir, &client) {
            Ok(entry) => results.push(entry),
            Err(e) => {
                results.push(TrophyEntry {
                    crate_name: ci.name.clone(),
                    version: ci.max_stable_version.clone(),
                    downloads: ci.downloads,
                    description: ci.description.clone().unwrap_or_default(),
                    errors: 0,
                    warnings: 0,
                    infos: 0,
                    issues: Vec::new(),
                    error: Some(format!("{e}")),
                });
            }
        }
    }

    // Filter: only crates with findings
    let with_findings: Vec<_> = results
        .into_iter()
        .filter(|e| e.errors > 0 || e.warnings > 0 || e.error.is_some())
        .collect();

    eprintln!(
        "\nDone. {}/{} crates had FFI issues.",
        with_findings.len(),
        resp.crates.len()
    );

    Ok(with_findings)
}

fn scan_crate(
    ci: &CrateInfo,
    cache_dir: &Path,
    client: &reqwest::blocking::Client,
) -> Result<TrophyEntry> {
    // Download crate
    let dl_url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        ci.name, ci.max_stable_version
    );

    let crate_dir = cache_dir.join(format!("{}-{}", ci.name, ci.max_stable_version));
    if crate_dir.exists() {
        std::fs::remove_dir_all(&crate_dir)?;
    }
    std::fs::create_dir_all(&crate_dir)?;

    let tgz_path = crate_dir.join("crate.tar.gz");
    let resp = client
        .get(&dl_url)
        .header("User-Agent", "ffi-guard-trophy/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .send()?;
    let bytes = resp.bytes()?;
    std::fs::write(&tgz_path, &bytes)?;

    // Extract
    let file = std::fs::File::open(&tgz_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(&crate_dir)?;

    // Find the actual source dir (crates.io wraps in crate-name-version/)
    let src_dir = find_src_dir(&crate_dir)?;

    // Quick check: does it have extern "C" blocks?
    if !has_ffi_code(&src_dir) {
        return Ok(TrophyEntry {
            crate_name: ci.name.clone(),
            version: ci.max_stable_version.clone(),
            downloads: ci.downloads,
            description: ci.description.clone().unwrap_or_default(),
            errors: 0,
            warnings: 0,
            infos: 0,
            issues: Vec::new(),
            error: None,
        });
    }

    // Scan
    let mut scanner = Scanner::new()?;
    let report = scanner.scan(&src_dir)?;

    Ok(TrophyEntry {
        crate_name: ci.name.clone(),
        version: ci.max_stable_version.clone(),
        downloads: ci.downloads,
        description: ci.description.clone().unwrap_or_default(),
        errors: report.stats.errors,
        warnings: report.stats.warnings,
        infos: report.stats.infos,
        issues: report.issues,
        error: None,
    })
}

fn find_src_dir(crate_dir: &Path) -> Result<PathBuf> {
    // crates.io extracts to: crate_dir/crate-name-version/
    for entry in std::fs::read_dir(crate_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let p = entry.path();
            if p.join("Cargo.toml").exists() {
                return Ok(p);
            }
        }
    }
    // Fallback: maybe the crate_dir itself has Cargo.toml
    if crate_dir.join("Cargo.toml").exists() {
        return Ok(crate_dir.to_path_buf());
    }
    anyhow::bail!("no Cargo.toml found in extracted crate")
}

fn has_ffi_code(dir: &Path) -> bool {
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            if content.contains("extern \"C\"") || content.contains("extern \"C++\"") {
                return true;
            }
        }
    }
    false
}
