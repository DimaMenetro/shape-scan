//! `shape-scan` — entropy + topological-shape file scanner.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use walkdir::WalkDir;

use shape_scan::{scan_path, FileReport, RiskLevel};

#[derive(Parser, Debug)]
#[command(
    name = "shape-scan",
    version,
    about = "Measure the entropy and topological shape of files to flag suspicious binaries.",
    long_about = "shape-scan analyses every byte of a file (and, where possible, every section \
        of an executable) to produce two complementary signals: a Shannon-entropy profile and a \
        byte-bigram-graph (\"shape\") profile. It then combines them into a heuristic risk score. \
        This is a triage signal, not a verdict — sophisticated malware can be tuned to evade \
        entropy and shape heuristics."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compute entropy + shape + risk score for one or more paths.
    Scan {
        /// Files or directories to scan.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Recurse into directories.
        #[arg(short, long)]
        recursive: bool,
        /// Skip files larger than this many MiB (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        max_size_mib: u64,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Only show files at or above this risk level.
        #[arg(long, value_enum)]
        min_risk: Option<RiskFilter>,
        /// Number of parallel workers (0 = auto).
        #[arg(short, long, default_value_t = 0)]
        jobs: usize,
    },
    /// Print only the topological shape report for a single file.
    Shape {
        path: PathBuf,
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Print only the entropy report for a single file.
    Entropy {
        path: PathBuf,
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Sliding-window size in bytes.
        #[arg(short, long, default_value_t = 4096)]
        window: usize,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum RiskFilter {
    Low,
    Medium,
    High,
}

impl RiskFilter {
    fn includes(self, r: RiskLevel) -> bool {
        let order = |x| match x {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
        };
        let threshold = match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        };
        order(r) >= threshold
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Scan {
            paths,
            recursive,
            max_size_mib,
            format,
            min_risk,
            jobs,
        } => run_scan(paths, recursive, max_size_mib, format, min_risk, jobs),
        Command::Shape { path, format } => run_shape(&path, format),
        Command::Entropy {
            path,
            format,
            window,
        } => run_entropy(&path, format, window),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("shape-scan: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run_scan(
    paths: Vec<PathBuf>,
    recursive: bool,
    max_size_mib: u64,
    format: Format,
    min_risk: Option<RiskFilter>,
    jobs: usize,
) -> Result<ExitCode> {
    if jobs > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .ok();
    }

    let max_bytes = if max_size_mib == 0 {
        u64::MAX
    } else {
        max_size_mib * 1024 * 1024
    };

    let targets = collect_targets(&paths, recursive, max_bytes)?;

    let reports: Vec<FileReport> = targets
        .par_iter()
        .filter_map(|p| match scan_path(p) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("shape-scan: skipping {}: {e:#}", p.display());
                None
            }
        })
        .filter(|r| match min_risk {
            Some(filter) => filter.includes(r.risk_level),
            None => true,
        })
        .collect();

    let mut sorted = reports;
    sorted.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&sorted)?);
        }
        Format::Text => print_text(&sorted),
        Format::Markdown => print_markdown(&sorted),
    }

    let any_high = sorted.iter().any(|r| r.risk_level == RiskLevel::High);
    Ok(if any_high {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn collect_targets(paths: &[PathBuf], recursive: bool, max_bytes: u64) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if !p.exists() {
            anyhow::bail!("path does not exist: {}", p.display());
        }
        if p.is_file() {
            if file_size(p)? <= max_bytes {
                out.push(p.clone());
            }
            continue;
        }
        if p.is_dir() {
            let walker = WalkDir::new(p).follow_links(false);
            let walker = if recursive {
                walker
            } else {
                walker.max_depth(1)
            };
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path().to_path_buf();
                    if file_size(&path).unwrap_or(0) <= max_bytes {
                        out.push(path);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn file_size(p: &Path) -> Result<u64> {
    Ok(std::fs::metadata(p)
        .with_context(|| format!("stat {}", p.display()))?
        .len())
}

fn run_shape(path: &Path, format: Format) -> Result<ExitCode> {
    let report = scan_path(path)?;
    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report.shape)?),
        Format::Text | Format::Markdown => {
            let s = &report.shape;
            println!("shape report for {}", path.display());
            println!("  distinct bytes      : {}", s.distinct_bytes);
            println!("  distinct bigrams    : {}", s.distinct_bigrams);
            println!("  edge density        : {:.4}", s.edge_density);
            println!(
                "  bigram entropy      : {:.4} bits/pair",
                s.bigram_entropy_bits
            );
            println!(
                "  conditional entropy : {:.4} bits/byte",
                s.conditional_entropy_bits
            );
            println!(
                "  mean row entropy    : {:.4} ± {:.4} bits/byte",
                s.mean_row_entropy_bits, s.row_entropy_stddev
            );
            println!("  fingerprint         : {}", s.structural_fingerprint);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_entropy(path: &Path, format: Format, window: usize) -> Result<ExitCode> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let report = shape_scan::EntropyReport::from_bytes_with_window(&data, window);
    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Text | Format::Markdown => {
            println!("entropy report for {}", path.display());
            println!("  size              : {} bytes", report.size);
            println!(
                "  Shannon entropy   : {:.4} bits/byte ({:.2}% of max)",
                report.shannon_bits_per_byte,
                report.normalised * 100.0
            );
            if let Some(w) = report.windows {
                println!("  window size       : {} bytes", w.window_size);
                println!("  windows           : {}", w.count);
                println!(
                    "  per-window mean   : {:.4} ± {:.4} bits/byte",
                    w.mean, w.stddev
                );
                println!("  per-window range  : [{:.4}, {:.4}]", w.min, w.max);
                println!(
                    "  high-entropy frac : {:.2}% (windows ≥ 7.5 bits/byte)",
                    w.high_entropy_fraction * 100.0
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_text(reports: &[FileReport]) {
    if reports.is_empty() {
        println!("(no files matched)");
        return;
    }
    for r in reports {
        println!(
            "[{level:^6}] score={score:.2} entropy={ent:.2} bits/byte density={dens:.2} {path}",
            level = r.risk_level.as_str(),
            score = r.risk_score,
            ent = r.entropy.shannon_bits_per_byte,
            dens = r.shape.edge_density,
            path = r.path.display()
        );
        for ind in &r.indicators {
            println!("    - {ind}");
        }
    }
}

fn print_markdown(reports: &[FileReport]) {
    println!("# shape-scan report");
    println!();
    println!("| risk | score | entropy | density | path |");
    println!("|------|-------|---------|---------|------|");
    for r in reports {
        println!(
            "| {} | {:.2} | {:.2} | {:.2} | `{}` |",
            r.risk_level.as_str(),
            r.risk_score,
            r.entropy.shannon_bits_per_byte,
            r.shape.edge_density,
            r.path.display()
        );
    }
    println!();
    for r in reports {
        if r.indicators.is_empty() {
            continue;
        }
        println!("## `{}`", r.path.display());
        for ind in &r.indicators {
            println!("- {ind}");
        }
        println!();
    }
}
