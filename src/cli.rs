//! shape-scan CLI interface
//!
//! Subcommands:
//!   scan    — Full TEM pipeline (TFEA + Markov + TCGE + AISE + CQSF)
//!   entropy — TFEA only
//!   shape   — TCGE + Markov only
//!   intent  — AISE only

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::{aise, markov, pipeline, tcge, tfea};

#[derive(Parser)]
#[command(
    name = "shape-scan",
    version = "2.0.0-alpha",
    about = "Geometric threat analysis — measures the mathematical shape of files.",
    long_about = "TEM v2.0: Detects malware through topology, entropy, Markov microstructure, and intent.\nNo signatures. No heuristics. Pure geometry."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full TEM pipeline scan
    Scan {
        /// File or directory to scan
        path: PathBuf,

        /// Scan directories recursively
        #[arg(short, long)]
        recursive: bool,

        /// Output format
        #[arg(short, long, default_value = "summary")]
        format: OutputFormat,

        /// Minimum verdict to display (for directory scans)
        #[arg(long, default_value = "clear")]
        min_verdict: VerdictFilter,

        /// Maximum files to scan in directory mode
        #[arg(long, default_value = "10000")]
        max_files: usize,
    },

    /// Entropy analysis only (TFEA)
    Entropy {
        /// File to analyze
        path: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "summary")]
        format: OutputFormat,

        /// Window size in bytes
        #[arg(long, default_value = "256")]
        window: usize,
    },

    /// Topological shape analysis (TCGE + Markov)
    Shape {
        /// File to analyze
        path: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "summary")]
        format: OutputFormat,
    },

    /// Intent analysis only (AISE)
    Intent {
        /// File to analyze
        path: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "summary")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Summary,
    Table,
}

#[derive(Clone, ValueEnum)]
enum VerdictFilter {
    Clear,
    Monitor,
    Quarantine,
}

// ============================================================
// Entry point
// ============================================================

pub fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            recursive,
            format,
            min_verdict: _,
            max_files,
        } => {
            if path.is_file() {
                let report = pipeline::scan_file(&path)?;
                print_report(&report, &format);
                Ok(report.quarantine_verdict.min(1) as i32)
            } else if path.is_dir() && recursive {
                let result = pipeline::scan_directory(&path, None, max_files)?;
                print_directory_result(&result, &format);
                if result.verdicts.quarantine > 0 || result.verdicts.destroy > 0 {
                    Ok(1)
                } else {
                    Ok(0)
                }
            } else if path.is_dir() {
                eprintln!("[TEM] Target is a directory. Use --recursive (-r) to scan recursively.");
                Ok(2)
            } else {
                eprintln!("[TEM] Target not found: {}", path.display());
                Ok(2)
            }
        }

        Commands::Entropy {
            path,
            format,
            window: _,
        } => {
            let profile = tfea::analyze(&path)?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
                _ => print_entropy_summary(&profile),
            }
            Ok(if profile.anomaly_detected { 1 } else { 0 })
        }

        Commands::Shape { path, format } => {
            let tcge_profile = tcge::analyze(&path)?;
            let markov_profile = markov::analyze(&path)?;

            #[derive(serde::Serialize)]
            struct ShapeResult {
                topology: tcge::TopologyProfile,
                markov: markov::MarkovProfile,
            }
            let result = ShapeResult {
                topology: tcge_profile.clone(),
                markov: markov_profile.clone(),
            };

            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                _ => {
                    print_topology_summary(&tcge_profile);
                    print_markov_summary(&markov_profile);
                }
            }
            Ok(if tcge_profile.topology_anomaly { 1 } else { 0 })
        }

        Commands::Intent { path, format } => {
            let profile = aise::analyze(&path)?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&profile)?),
                _ => print_intent_summary(&profile),
            }
            Ok(if profile.intent_anomaly { 1 } else { 0 })
        }
    }
}

// ============================================================
// Output formatting
// ============================================================

fn verdict_indicator(verdict: u8) -> &'static str {
    match verdict {
        0 => "\x1b[32m✓ CLEAR\x1b[0m",
        1 => "\x1b[33m⚠ MONITOR\x1b[0m",
        2 => "\x1b[31m✗ QUARANTINE\x1b[0m",
        3 => "\x1b[31;1m☠ DESTROY\x1b[0m",
        _ => "? UNKNOWN",
    }
}

fn score_bar(score: f64, width: usize) -> String {
    let filled = (score * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let color = if score > 0.7 {
        "\x1b[31m"
    } else if score > 0.3 {
        "\x1b[33m"
    } else {
        "\x1b[32m"
    };
    format!(
        "{color}{}{}  {:.1}%\x1b[0m",
        "█".repeat(filled),
        "░".repeat(empty),
        score * 100.0
    )
}

fn print_report(report: &crate::cqsf::TEMReport, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_default()
            );
        }
        _ => {
            println!();
            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║               TEM v2.0 — Scan Report                    ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!(
                "║  File size:  {:>10} bytes                           ║",
                report.file_size
            );
            println!(
                "║  SHA-256:    {:016x}                   ║",
                report.file_sha256_prefix
            );
            println!(
                "║  Duration:   {:>8.1} ms                                ║",
                report.pipeline_duration_ms
            );
            println!("╠══════════════════════════════════════════════════════════╣");
            println!(
                "║  VERDICT:    {}                             ║",
                verdict_indicator(report.quarantine_verdict)
            );
            println!(
                "║  Confidence: {:.1}%                                       ║",
                report.quarantine_confidence * 100.0
            );
            println!("╠══════════════════════════════════════════════════════════╣");
            println!(
                "║  Entropy:    {} ║",
                score_bar(report.entropy_threat_score, 30)
            );
            println!(
                "║  Topology:   {} ║",
                score_bar(report.topology_threat_score, 30)
            );
            println!(
                "║  Intent:     {} ║",
                score_bar(report.intent_threat_score, 30)
            );
            println!(
                "║  Composite:  {} ║",
                score_bar(report.composite_threat_score, 30)
            );
            println!("╠══════════════════════════════════════════════════════════╣");
            println!(
                "║  Fingerprint: {:016x}                  ║",
                report.markov_structural_fingerprint
            );

            if report.header_mismatch_detected > 0 {
                println!(
                    "║  ⚠ Header-entropy mismatch ({:.1}σ)                      ║",
                    report.tfea_mismatch_sigma
                );
            }
            if report.backdoor_pattern_detected > 0 {
                println!("║  ⚠ Backdoor pattern (shell + decode)                    ║");
            }
            if report.dropper_pattern_detected > 0 {
                println!("║  ⚠ Dropper pattern (network + filesystem)               ║");
            }
            if report.webshell_pattern_detected > 0 {
                println!("║  ⚠ Webshell pattern (eval + obfuscation)                ║");
            }

            println!("╚══════════════════════════════════════════════════════════╝");
            println!();
        }
    }
}

fn print_directory_result(result: &pipeline::DirectoryScanResult, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
        _ => {
            println!();
            println!("╔══════════════════════════════════════════════════╗");
            println!("║         TEM v2.0 — Directory Scan               ║");
            println!("╠══════════════════════════════════════════════════╣");
            println!(
                "║  Total files:  {:>6}                            ║",
                result.total_files
            );
            println!(
                "║  Scanned:      {:>6}                            ║",
                result.scanned
            );
            println!(
                "║  Skipped:      {:>6}                            ║",
                result.skipped
            );
            println!(
                "║  Errors:       {:>6}                            ║",
                result.errors
            );
            println!("╠══════════════════════════════════════════════════╣");
            println!(
                "║  CLEAR:        {:>6}                            ║",
                result.verdicts.clear
            );
            println!(
                "║  MONITOR:      {:>6}                            ║",
                result.verdicts.monitor
            );
            println!(
                "║  QUARANTINE:   {:>6}                            ║",
                result.verdicts.quarantine
            );
            println!(
                "║  DESTROY:      {:>6}                            ║",
                result.verdicts.destroy
            );
            println!("╚══════════════════════════════════════════════════╝");

            if !result.flagged_files.is_empty() {
                println!();
                println!("Flagged files:");
                for report in &result.flagged_files {
                    println!(
                        "  {} | sha:{:016x} | score:{:.2} | {}",
                        verdict_indicator(report.quarantine_verdict),
                        report.file_sha256_prefix,
                        report.composite_threat_score,
                        if report.backdoor_pattern_detected > 0 {
                            "BACKDOOR"
                        } else if report.dropper_pattern_detected > 0 {
                            "DROPPER"
                        } else if report.webshell_pattern_detected > 0 {
                            "WEBSHELL"
                        } else {
                            ""
                        }
                    );
                }
            }
            println!();
        }
    }
}

fn print_entropy_summary(profile: &tfea::EntropyProfile) {
    println!();
    println!("  Entropy Profile");
    println!("  ─────────────────────────────");
    println!("  File size:     {} bytes", profile.file_size);
    println!(
        "  Bulk entropy:  {:.4} bits/byte",
        profile.measured_bulk_entropy
    );
    println!(
        "  Windows:       {} ({}-byte, {}-step)",
        profile.num_windows, profile.window_size, profile.step_size
    );
    println!("  Mean:          {:.4}", profile.mean_entropy);
    println!("  Std dev:       {:.4}", profile.std_entropy);
    println!("  Min:           {:.4}", profile.min_entropy);
    println!("  Max:           {:.4}", profile.max_entropy);
    println!(
        "  High ratio:    {:.1}% (>7.0)",
        profile.high_entropy_ratio * 100.0
    );
    println!(
        "  Anomaly:       {}",
        if profile.anomaly_detected {
            "YES"
        } else {
            "no"
        }
    );
    if profile.header_mismatch {
        println!("  ⚠ Header mismatch: {:.1}σ", profile.mismatch_sigma);
    }
    println!();
}

fn print_topology_summary(profile: &tcge::TopologyProfile) {
    println!();
    println!("  Topology Profile");
    println!("  ─────────────────────────────");
    println!(
        "  Format:        {}",
        match profile.format_detected {
            1 => "PE",
            2 => "ELF",
            3 => "Mach-O",
            _ => "Generic",
        }
    );
    println!("  Nodes:         {}", profile.node_count);
    println!("  Edges:         {}", profile.edge_count);
    println!(
        "  Back edges:    {} ({:.1}%)",
        profile.back_edge_count,
        profile.back_edge_ratio * 100.0
    );
    println!("  Density:       {:.4}", profile.graph_density);
    println!(
        "  SCCs:          {} (largest: {})",
        profile.strongly_connected_count, profile.largest_scc_size
    );
    println!("  Cycles:        {}", profile.cycle_count);
    println!("  Self-loops:    {}", profile.self_loop_count);
    println!(
        "  Anomaly:       {}",
        if profile.topology_anomaly {
            "YES"
        } else {
            "no"
        }
    );
    println!();
}

fn print_markov_summary(profile: &markov::MarkovProfile) {
    println!();
    println!("  Markov Transition Profile");
    println!("  ─────────────────────────────");
    println!("  Distinct bytes:     {}/256", profile.distinct_bytes);
    println!("  Distinct pairs:     {}/65536", profile.distinct_pairs);
    println!("  Edge density:       {:.4}", profile.edge_density);
    println!(
        "  Bigram entropy:     {:.4} bits/pair",
        profile.bigram_entropy
    );
    println!(
        "  Conditional H:      {:.4} bits/byte",
        profile.conditional_entropy
    );
    println!(
        "  Row entropy mean:   {:.4} ± {:.4}",
        profile.mean_row_entropy, profile.std_row_entropy
    );
    println!(
        "  Fingerprint:        {:016x}",
        profile.structural_fingerprint
    );
    println!();
}

fn print_intent_summary(profile: &aise::IntentProfile) {
    println!();
    println!("  Intent Profile");
    println!("  ─────────────────────────────");
    println!("  Composite:     {:.2}", profile.composite_intent_score);
    println!("  Vectors:       {}/10 active", profile.intent_vector_count);
    println!(
        "  Pattern hits:  {} ({:.1}/KB)",
        profile.total_pattern_hits, profile.pattern_density
    );

    let categories = [
        ("Shell exec", profile.shell_execution_score),
        ("Code eval", profile.code_evaluation_score),
        ("Decoding", profile.data_decoding_score),
        ("Network", profile.network_communication_score),
        ("Filesystem", profile.filesystem_manipulation_score),
        ("Process", profile.process_control_score),
        ("Credential", profile.credential_access_score),
        ("Obfuscation", profile.obfuscation_indicator_score),
        ("Persistence", profile.persistence_mechanism_score),
        ("Info gather", profile.information_gathering_score),
    ];

    for (name, score) in &categories {
        if *score > 0.0 {
            println!("  {:14} {}", name, score_bar(*score, 20));
        }
    }

    if profile.shell_plus_decode {
        println!("  ⚠ BACKDOOR pattern");
    }
    if profile.network_plus_filesystem {
        println!("  ⚠ DROPPER pattern");
    }
    if profile.eval_plus_obfuscation {
        println!("  ⚠ WEBSHELL pattern");
    }
    println!();
}
