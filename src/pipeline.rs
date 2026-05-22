//! TEM Pipeline Orchestrator
//!
//! Ties TFEA → Markov → TCGE → AISE → CQSF together with fail-closed logic.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aise;
use crate::cqsf::{self, TEMReport, Verdict};
use crate::markov;
use crate::tcge;
use crate::tfea;

/// Execute full TEM pipeline on a single file.
///
/// Returns the consolidated numeric-only report.
pub fn scan_file(path: &Path) -> io::Result<TEMReport> {
    let pipeline_start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0;

    let data = fs::read(path)?;

    // Stage 1: TFEA — Thermodynamic Free Energy Audit
    let tfea_profile = tfea::analyze_bytes(&data);

    // Stage 2: Markov — Transition Matrix Microstructure
    let markov_profile = markov::analyze_bytes(&data);

    // Stage 3: TCGE — Topological Code Geometry
    let tcge_profile = tcge::analyze_bytes(&data);

    // Stage 4: AISE — Axiomatic Intent Scoring
    let aise_profile = aise::analyze_bytes(&data);

    // Stage 5: CQSF — Semantic Firewall consolidation
    let report = cqsf::consolidate(
        &data,
        &tfea_profile,
        &markov_profile,
        &tcge_profile,
        &aise_profile,
        pipeline_start,
    );

    Ok(report)
}

/// Results for a directory scan.
#[derive(Debug, serde::Serialize)]
pub struct DirectoryScanResult {
    pub total_files: usize,
    pub scanned: usize,
    pub skipped: usize,
    pub errors: usize,
    pub verdicts: VerdictCounts,
    pub flagged_files: Vec<TEMReport>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct VerdictCounts {
    pub clear: usize,
    pub monitor: usize,
    pub quarantine: usize,
    pub destroy: usize,
}

/// Scan a directory recursively with the full TEM pipeline.
pub fn scan_directory(
    dir: &Path,
    extensions: Option<&[&str]>,
    max_files: usize,
) -> io::Result<DirectoryScanResult> {
    let mut result = DirectoryScanResult {
        total_files: 0,
        scanned: 0,
        skipped: 0,
        errors: 0,
        verdicts: VerdictCounts::default(),
        flagged_files: Vec::new(),
    };

    let mut file_count = 0usize;

    for entry in walkdir(dir)? {
        let path = entry;
        if !path.is_file() {
            continue;
        }
        result.total_files += 1;

        // Extension filter
        if let Some(exts) = extensions {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e.to_lowercase()));
            match ext {
                Some(ref e) if exts.iter().any(|x| x == e) => {}
                _ => {
                    result.skipped += 1;
                    continue;
                }
            }
        }

        if file_count >= max_files {
            result.skipped += 1;
            continue;
        }

        match scan_file(&path) {
            Ok(report) => {
                result.scanned += 1;
                file_count += 1;

                let verdict = match report.quarantine_verdict {
                    0 => {
                        result.verdicts.clear += 1;
                        Verdict::Clear
                    }
                    1 => {
                        result.verdicts.monitor += 1;
                        Verdict::Monitor
                    }
                    2 => {
                        result.verdicts.quarantine += 1;
                        Verdict::Quarantine
                    }
                    3 => {
                        result.verdicts.destroy += 1;
                        Verdict::Destroy
                    }
                    _ => {
                        result.verdicts.clear += 1;
                        Verdict::Clear
                    }
                };

                if matches!(
                    verdict,
                    Verdict::Monitor | Verdict::Quarantine | Verdict::Destroy
                ) {
                    result.flagged_files.push(report);
                }

                if result.scanned.is_multiple_of(10) {
                    eprint!(
                        "\r[TEM] Scanned: {} | Flagged: {} | Q: {}",
                        result.scanned,
                        result.flagged_files.len(),
                        result.verdicts.quarantine,
                    );
                }
            }
            Err(_) => {
                result.errors += 1;
            }
        }
    }

    eprintln!(); // Final newline after progress

    Ok(result)
}

/// Simple recursive directory walker.
fn walkdir(dir: &Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();

    fn walk_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    walk_recursive(&path, files)?;
                } else {
                    files.push(path);
                }
            }
        }
        Ok(())
    }

    walk_recursive(dir, &mut files)?;
    Ok(files)
}
