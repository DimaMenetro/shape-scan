//! Markov Transition Matrix Analysis
//!
//! TEM Module 1b — Thermodynamic microstructure layer.
//!
//! Captures sequential byte structure invisible to bulk entropy.
//! Treats the byte stream as a Markov chain over its 256 byte values
//! and computes the 256×256 transition probability matrix.
//!
//! This fills the gap between TFEA (macro entropy) and TCGE (execution geometry):
//! two files can have identical Shannon entropy but completely different
//! transition matrices (e.g. encrypted data vs natural language).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ============================================================
// Output type — strictly numeric
// ============================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct MarkovProfile {
    pub file_size: usize,

    /// Number of distinct byte values present (≤ 256)
    pub distinct_bytes: usize,

    /// Number of distinct adjacent byte pairs (≤ 65536)
    pub distinct_pairs: usize,

    /// Edge density: distinct_pairs / 65536, in [0, 1]
    pub edge_density: f64,

    /// Joint Shannon entropy of the 256×256 transition matrix (bits/pair)
    pub bigram_entropy: f64,

    /// Conditional entropy H(b_{i+1} | b_i) — bits/byte
    pub conditional_entropy: f64,

    /// Per-row entropy statistics across the 256 rows of the transition matrix
    pub mean_row_entropy: f64,
    pub std_row_entropy: f64,
    pub min_row_entropy: f64,
    pub max_row_entropy: f64,

    /// Stable 64-bit hash of the quantized transition matrix.
    /// Acts as a "file DNA" — structurally similar files produce similar fingerprints.
    pub structural_fingerprint: u64,
}

// ============================================================
// Core engine
// ============================================================

/// Build the 256×256 transition count matrix from a byte stream.
/// Uses heap allocation to avoid blowing the Windows 1MB default stack.
fn build_transition_matrix(data: &[u8]) -> Vec<Vec<u64>> {
    let mut matrix = vec![vec![0u64; 256]; 256];

    if data.len() < 2 {
        return matrix;
    }

    for window in data.windows(2) {
        let from = window[0] as usize;
        let to = window[1] as usize;
        matrix[from][to] += 1;
    }

    matrix
}

/// Compute Shannon entropy for a probability distribution given as counts.
fn entropy_from_counts(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let total_f = total as f64;
    let mut h = 0.0_f64;
    for &c in counts {
        if c > 0 {
            let p = c as f64 / total_f;
            h -= p * p.log2();
        }
    }
    h
}

/// Compute a stable 64-bit structural fingerprint from the transition matrix.
///
/// Quantizes each row's transition probabilities into 4 buckets (2 bits each),
/// producing a deterministic hash that is stable across runs.
fn compute_fingerprint(matrix: &[Vec<u64>]) -> u64 {
    // Quantize: for each row, compute the probability distribution and
    // bucket each transition into 4 levels (0-3).
    let mut quantized = Vec::with_capacity(256 * 256 / 4);

    for row in matrix.iter() {
        let row_total: u64 = row.iter().sum();
        if row_total == 0 {
            // Empty row — all zeros
            quantized.extend_from_slice(&[0u8; 64]); // 256 * 2 bits = 512 bits = 64 bytes
            continue;
        }

        let row_f = row_total as f64;
        let mut packed = [0u8; 64];

        for (i, &count) in row.iter().enumerate() {
            let p = count as f64 / row_f;
            // Quantize to 2 bits: 0=zero, 1=low(<0.01), 2=medium(<0.1), 3=high(>=0.1)
            let q: u8 = if count == 0 {
                0
            } else if p < 0.01 {
                1
            } else if p < 0.1 {
                2
            } else {
                3
            };

            let byte_idx = i / 4;
            let bit_shift = (i % 4) * 2;
            packed[byte_idx] |= q << bit_shift;
        }

        quantized.extend_from_slice(&packed);
    }

    let mut hasher = DefaultHasher::new();
    quantized.hash(&mut hasher);
    hasher.finish()
}

// ============================================================
// Main analysis function
// ============================================================

/// Perform Markov transition matrix analysis on raw bytes.
pub fn analyze_bytes(data: &[u8]) -> MarkovProfile {
    let file_size = data.len();

    if data.len() < 2 {
        return MarkovProfile {
            file_size,
            distinct_bytes: if data.is_empty() { 0 } else { 1 },
            distinct_pairs: 0,
            edge_density: 0.0,
            bigram_entropy: 0.0,
            conditional_entropy: 0.0,
            mean_row_entropy: 0.0,
            std_row_entropy: 0.0,
            min_row_entropy: 0.0,
            max_row_entropy: 0.0,
            structural_fingerprint: 0,
        };
    }

    let matrix = build_transition_matrix(data);

    // Distinct byte values
    let mut byte_present = [false; 256];
    for &b in data {
        byte_present[b as usize] = true;
    }
    let distinct_bytes = byte_present.iter().filter(|&&p| p).count();

    // Distinct byte pairs
    let mut distinct_pairs = 0usize;
    for row in &matrix {
        for &count in row.iter() {
            if count > 0 {
                distinct_pairs += 1;
            }
        }
    }

    let edge_density = distinct_pairs as f64 / 65536.0;

    // Bigram entropy: joint Shannon entropy of the transition matrix
    // Flatten all counts into a single distribution
    let flat_counts: Vec<u64> = matrix.iter().flat_map(|row| row.iter().copied()).collect();
    let bigram_entropy = entropy_from_counts(&flat_counts);

    // Per-row entropy (conditional entropy computation)
    let mut row_entropies = Vec::with_capacity(256);
    let mut row_weights = Vec::with_capacity(256);

    for row in &matrix {
        let row_total: u64 = row.iter().sum();
        if row_total > 0 {
            let h = entropy_from_counts(row);
            row_entropies.push(h);
            row_weights.push(row_total);
        }
    }

    // Conditional entropy H(b_{i+1} | b_i) = weighted average of per-row entropies
    let conditional_entropy = if !row_weights.is_empty() {
        let total_weight: u64 = row_weights.iter().sum();
        let total_f = total_weight as f64;
        row_entropies
            .iter()
            .zip(row_weights.iter())
            .map(|(h, w)| h * (*w as f64 / total_f))
            .sum()
    } else {
        0.0
    };

    // Per-row entropy statistics (only for non-empty rows)
    let (mean_row, std_row, min_row, max_row) = if !row_entropies.is_empty() {
        let n = row_entropies.len() as f64;
        let mean = row_entropies.iter().sum::<f64>() / n;

        let variance = row_entropies
            .iter()
            .map(|h| (h - mean).powi(2))
            .sum::<f64>()
            / n;
        let std_dev = variance.sqrt();

        let min = row_entropies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = row_entropies
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        (mean, std_dev, min, max)
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };

    // Structural fingerprint
    let fingerprint = compute_fingerprint(&matrix);

    MarkovProfile {
        file_size,
        distinct_bytes,
        distinct_pairs,
        edge_density,
        bigram_entropy,
        conditional_entropy,
        mean_row_entropy: mean_row,
        std_row_entropy: std_row,
        min_row_entropy: min_row,
        max_row_entropy: max_row,
        structural_fingerprint: fingerprint,
    }
}

/// Perform Markov analysis on a file at the given path.
pub fn analyze(path: &std::path::Path) -> std::io::Result<MarkovProfile> {
    let data = std::fs::read(path)?;
    Ok(analyze_bytes(&data))
}
