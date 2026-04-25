//! High-level per-file scanning + risk scoring.
//!
//! The scoring function combines several entropy and shape features
//! into a single `risk_score` in `[0.0, 1.0]`. This is **not** a
//! malware classifier — it is a heuristic ranking signal that
//! highlights files which look statistically similar to packed,
//! encrypted, or otherwise obfuscated content. Use it as input to
//! human review, not as a verdict.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::entropy::EntropyReport;
use crate::sections::SectionReport;
use crate::shape::ShapeReport;

/// Coarse risk bucket derived from `risk_score`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub fn from_score(s: f64) -> Self {
        if s >= 0.75 {
            Self::High
        } else if s >= 0.45 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Full per-file analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub entropy: EntropyReport,
    pub shape: ShapeReport,
    pub sections: SectionReport,
    /// Heuristic indicators that contributed to the score.
    pub indicators: Vec<String>,
    /// Combined risk score in `[0.0, 1.0]`.
    pub risk_score: f64,
    pub risk_level: RiskLevel,
}

impl FileReport {
    pub fn analyse_bytes(path: impl Into<PathBuf>, data: &[u8]) -> Self {
        let entropy = EntropyReport::from_bytes(data);
        let shape = ShapeReport::from_bytes(data);
        let sections = SectionReport::from_bytes(data);
        let (indicators, risk_score) = score(&entropy, &shape, &sections);
        Self {
            path: path.into(),
            size: data.len() as u64,
            entropy,
            shape,
            sections,
            indicators,
            risk_score,
            risk_level: RiskLevel::from_score(risk_score),
        }
    }
}

/// Read `path` from disk and analyse it.
pub fn scan_path(path: &Path) -> Result<FileReport> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(FileReport::analyse_bytes(path, &data))
}

fn score(e: &EntropyReport, s: &ShapeReport, sec: &SectionReport) -> (Vec<String>, f64) {
    let mut indicators = Vec::new();
    let mut score = 0.0f64;

    // 1. Whole-file entropy. >7.0 is suspicious, >7.5 is strongly so.
    if e.shannon_bits_per_byte >= 7.5 {
        indicators.push(format!(
            "high overall entropy ({:.2} bits/byte) — typical of packed or encrypted data",
            e.shannon_bits_per_byte
        ));
        score += 0.35;
    } else if e.shannon_bits_per_byte >= 7.0 {
        indicators.push(format!(
            "elevated overall entropy ({:.2} bits/byte)",
            e.shannon_bits_per_byte
        ));
        score += 0.15;
    }

    // 2. Sliding window: a high fraction of high-entropy windows is the
    //    most reliable single signal.
    if let Some(w) = &e.windows {
        if w.high_entropy_fraction >= 0.5 {
            indicators.push(format!(
                "{:.0}% of {}-byte windows are high-entropy",
                w.high_entropy_fraction * 100.0,
                w.window_size
            ));
            score += 0.2;
        }
        if w.stddev >= 1.5 {
            indicators.push(format!(
                "highly variable entropy across the file (stddev={:.2})",
                w.stddev
            ));
            score += 0.05;
        }
    }

    // 3. Topological density: random-looking data fills the bigram graph.
    if s.edge_density >= 0.85 {
        indicators.push(format!(
            "near-complete byte-bigram graph (edge density {:.2})",
            s.edge_density
        ));
        score += 0.15;
    }
    if s.conditional_entropy_bits >= 7.5 {
        indicators.push(format!(
            "uniform conditional entropy ({:.2} bits/byte) — bytes are nearly memoryless",
            s.conditional_entropy_bits
        ));
        score += 0.1;
    }

    // 4. Section-level red flags: any executable section with high
    //    entropy is a classic packing indicator.
    if sec.format == "pe" || sec.format == "elf" || sec.format == "mach" {
        for sec_e in &sec.sections {
            if sec_e.size >= 256 && sec_e.shannon_bits_per_byte >= 7.5 {
                indicators.push(format!(
                    "{} section `{}` has high entropy ({:.2} bits/byte, {} B)",
                    sec.format.to_uppercase(),
                    sec_e.name,
                    sec_e.shannon_bits_per_byte,
                    sec_e.size
                ));
                score += 0.15;
                // Only credit once per file to avoid runaway scores on
                // many-section binaries.
                break;
            }
        }
    }

    // 5. Tiny files don't carry meaningful statistics — dampen the score.
    if e.size < 1024 {
        score *= 0.4;
        indicators.push(format!(
            "small file ({} B) — entropy/shape signals are less reliable",
            e.size
        ));
    }

    (indicators, score.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scoring_low_for_text() {
        let s = b"Lorem ipsum dolor sit amet. ".repeat(512);
        let r = FileReport::analyse_bytes("text.txt", &s);
        assert_eq!(r.risk_level, RiskLevel::Low);
        assert!(r.risk_score < 0.45, "score was {}", r.risk_score);
    }

    #[test]
    fn scoring_high_for_random() {
        // Pseudorandom data via SplitMix64 — much better quality than
        // raw xorshift's low bits. 256 KiB is enough for the bigram
        // graph to saturate and for conditional entropy to converge.
        let mut state: u64 = 0xdead_beef_cafe_babe;
        let n = 256 * 1024;
        let mut data = Vec::with_capacity(n);
        while data.len() < n {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            data.extend_from_slice(&z.to_le_bytes());
        }
        data.truncate(n);
        let r = FileReport::analyse_bytes("rand.bin", &data);
        assert!(
            r.risk_score >= 0.75,
            "expected high risk, got {} ({:?})",
            r.risk_score,
            r.indicators
        );
        assert_eq!(r.risk_level, RiskLevel::High);
    }

    #[test]
    fn scan_path_reads_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello shape-scan").unwrap();
        let r = scan_path(f.path()).unwrap();
        assert_eq!(r.size, 16);
    }
}
