//! Topological / structural "shape" features of a byte stream.
//!
//! We treat the file as a Markov chain over its bytes: each byte is a
//! node, and each adjacent pair `(b_i, b_{i+1})` is a directed edge.
//! The resulting 256-node transition graph is dense for random data
//! and sparse / clumpy for structured data, which makes a number of
//! simple graph statistics useful as a fingerprint.

use serde::Serialize;

use crate::entropy::entropy_from_histogram;

/// 256-bin byte histogram (re-export friendly helper).
pub fn byte_histogram(data: &[u8]) -> [u64; 256] {
    crate::entropy::histogram(data)
}

/// Topological summary of a byte stream.
#[derive(Debug, Clone, Serialize)]
pub struct ShapeReport {
    /// Number of distinct byte values present (`|V|`, max 256).
    pub distinct_bytes: u32,
    /// Number of distinct adjacent byte pairs present (`|E|`, max 65_536).
    pub distinct_bigrams: u32,
    /// Edge density: `|E| / 65_536` in `[0, 1]`.
    pub edge_density: f64,
    /// Joint Shannon entropy of the bigram distribution, in bits per
    /// pair. Maxes out at 16 bits for a uniform 256×256 distribution.
    pub bigram_entropy_bits: f64,
    /// Conditional entropy `H(b_{i+1} | b_i)` in bits per byte.
    pub conditional_entropy_bits: f64,
    /// Spectral-style summary of the row-stochastic transition matrix:
    /// the mean Shannon entropy of each row that has any outgoing
    /// transitions, in bits per byte.
    pub mean_row_entropy_bits: f64,
    /// Standard deviation of per-row entropies.
    pub row_entropy_stddev: f64,
    /// Stable 64-bit fingerprint derived from the bigram graph.
    pub structural_fingerprint: String,
}

impl ShapeReport {
    /// Compute the full shape report. Cost is `O(n + 65_536)`.
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.len() < 2 {
            return Self::empty();
        }

        // 1. Byte histogram and bigram matrix.
        let unigram = byte_histogram(data);
        let mut bigram = vec![0u64; 256 * 256];
        for w in data.windows(2) {
            let i = (w[0] as usize) * 256 + (w[1] as usize);
            bigram[i] += 1;
        }
        let pair_total: u64 = (data.len() as u64) - 1;

        // 2. Vertex / edge counts.
        let distinct_bytes = unigram.iter().filter(|&&c| c > 0).count() as u32;
        let distinct_bigrams = bigram.iter().filter(|&&c| c > 0).count() as u32;
        let edge_density = distinct_bigrams as f64 / 65_536.0;

        // 3. Joint entropy of the bigram distribution.
        let pair_total_f = pair_total as f64;
        let mut bigram_entropy = 0.0f64;
        for &c in &bigram {
            if c == 0 {
                continue;
            }
            let p = c as f64 / pair_total_f;
            bigram_entropy -= p * p.log2();
        }

        // 4. Per-row stats: H(b_{i+1} | b_i = r) for each row r.
        let mut row_entropies = Vec::with_capacity(256);
        let mut weighted_conditional = 0.0f64;
        for row in 0..256 {
            let row_slice = &bigram[row * 256..(row + 1) * 256];
            let row_total: u64 = row_slice.iter().sum();
            if row_total == 0 {
                continue;
            }
            let mut row_counts = [0u64; 256];
            row_counts.copy_from_slice(row_slice);
            let h = entropy_from_histogram(&row_counts, row_total);
            row_entropies.push(h);
            weighted_conditional += (row_total as f64 / pair_total_f) * h;
        }
        let row_count = row_entropies.len().max(1) as f64;
        let mean_row_entropy = row_entropies.iter().sum::<f64>() / row_count;
        let row_var = row_entropies
            .iter()
            .map(|e| {
                let d = e - mean_row_entropy;
                d * d
            })
            .sum::<f64>()
            / row_count;

        // 5. Cheap, stable fingerprint of the bigram graph (FNV-1a over
        //    quantised counts).
        let fingerprint = fingerprint_from_bigram(&bigram, pair_total);

        Self {
            distinct_bytes,
            distinct_bigrams,
            edge_density,
            bigram_entropy_bits: bigram_entropy,
            conditional_entropy_bits: weighted_conditional,
            mean_row_entropy_bits: mean_row_entropy,
            row_entropy_stddev: row_var.sqrt(),
            structural_fingerprint: fingerprint,
        }
    }

    fn empty() -> Self {
        Self {
            distinct_bytes: 0,
            distinct_bigrams: 0,
            edge_density: 0.0,
            bigram_entropy_bits: 0.0,
            conditional_entropy_bits: 0.0,
            mean_row_entropy_bits: 0.0,
            row_entropy_stddev: 0.0,
            structural_fingerprint: format!("{:016x}", 0u64),
        }
    }
}

fn fingerprint_from_bigram(bigram: &[u64], total: u64) -> String {
    // Quantise each cell to 8 buckets of probability and hash.
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    let total_f = (total as f64).max(1.0);
    for (i, &c) in bigram.iter().enumerate() {
        let p = c as f64 / total_f;
        // 0..=7 bucket: log-spaced so common pairs dominate the hash.
        let bucket = if c == 0 {
            0u8
        } else {
            ((-p.log2()).clamp(0.0, 16.0) / 16.0 * 7.0).round() as u8 + 1
        };
        h ^= (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h = h.wrapping_mul(FNV_PRIME);
        h ^= bucket as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{:016x}", h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_of_short_input_is_empty() {
        let r = ShapeReport::from_bytes(b"");
        assert_eq!(r.distinct_bytes, 0);
        assert_eq!(r.distinct_bigrams, 0);
    }

    #[test]
    fn shape_of_constant_collapses() {
        let data = vec![0x41u8; 4096];
        let r = ShapeReport::from_bytes(&data);
        assert_eq!(r.distinct_bytes, 1);
        assert_eq!(r.distinct_bigrams, 1);
        assert!(r.bigram_entropy_bits.abs() < 1e-12);
        assert!(r.conditional_entropy_bits.abs() < 1e-12);
    }

    #[test]
    fn shape_of_text_is_low_density() {
        let s = b"the quick brown fox jumps over the lazy dog. ".repeat(64);
        let r = ShapeReport::from_bytes(&s);
        assert!(r.distinct_bytes < 40);
        assert!(r.edge_density < 0.05);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let data: Vec<u8> = (0..1024).map(|i| (i * 31) as u8).collect();
        let a = ShapeReport::from_bytes(&data);
        let b = ShapeReport::from_bytes(&data);
        assert_eq!(a.structural_fingerprint, b.structural_fingerprint);
    }
}
