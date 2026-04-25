//! Shannon-entropy primitives.
//!
//! All entropy values are in **bits per byte** and therefore lie in the
//! closed interval `[0.0, 8.0]`. A uniform distribution over the 256
//! possible byte values reaches the maximum of 8 bits/byte.

use serde::Serialize;

/// Default sliding-window size used by `WindowEntropy::from_bytes`.
///
/// 4 KiB is the de-facto industry default for "block entropy" analysis —
/// it's large enough that uniform-random bytes saturate near 8.0
/// (small-sample bias is ≲ 0.05 bits/byte) but small enough that local
/// regions of structured data still stand out.
pub const DEFAULT_WINDOW: usize = 4096;

/// Compute the byte-frequency histogram of `data`.
#[inline]
pub fn histogram(data: &[u8]) -> [u64; 256] {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
}

/// Shannon entropy of a byte histogram, in bits per byte.
pub fn entropy_from_histogram(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total_f;
        h -= p * p.log2();
    }
    h
}

/// Shannon entropy of `data`, in bits per byte.
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let counts = histogram(data);
    entropy_from_histogram(&counts, data.len() as u64)
}

/// Aggregated entropy statistics for a byte slice.
#[derive(Debug, Clone, Serialize)]
pub struct EntropyReport {
    /// Total number of bytes analysed.
    pub size: u64,
    /// Shannon entropy of the entire slice.
    pub shannon_bits_per_byte: f64,
    /// Normalised entropy (`shannon / 8`), in `[0, 1]`.
    pub normalised: f64,
    /// Sliding-window analysis (omitted for empty inputs).
    pub windows: Option<WindowEntropy>,
}

impl EntropyReport {
    /// Compute a full entropy report using the default window size.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::from_bytes_with_window(data, DEFAULT_WINDOW)
    }

    /// Compute a full entropy report with a caller-specified window size.
    pub fn from_bytes_with_window(data: &[u8], window: usize) -> Self {
        let shannon = shannon_entropy(data);
        let windows = if data.is_empty() {
            None
        } else {
            Some(WindowEntropy::from_bytes(data, window))
        };
        Self {
            size: data.len() as u64,
            shannon_bits_per_byte: shannon,
            normalised: shannon / 8.0,
            windows,
        }
    }
}

/// Sliding-window entropy summary.
#[derive(Debug, Clone, Serialize)]
pub struct WindowEntropy {
    /// Window size in bytes.
    pub window_size: usize,
    /// Number of windows analysed.
    pub count: usize,
    /// Mean per-window entropy (bits/byte).
    pub mean: f64,
    /// Min per-window entropy.
    pub min: f64,
    /// Max per-window entropy.
    pub max: f64,
    /// Standard deviation across windows.
    pub stddev: f64,
    /// Fraction of windows with entropy >= 7.5 bits/byte (typical
    /// "high entropy" threshold for compressed/encrypted data).
    pub high_entropy_fraction: f64,
}

impl WindowEntropy {
    /// Compute sliding-window entropy. Windows are non-overlapping and
    /// the trailing partial window (if any) is included.
    pub fn from_bytes(data: &[u8], window: usize) -> Self {
        let window = window.max(1);
        if data.is_empty() {
            return Self {
                window_size: window,
                count: 0,
                mean: 0.0,
                min: 0.0,
                max: 0.0,
                stddev: 0.0,
                high_entropy_fraction: 0.0,
            };
        }
        let mut entropies = Vec::with_capacity(data.len().div_ceil(window));
        for chunk in data.chunks(window) {
            entropies.push(shannon_entropy(chunk));
        }
        let count = entropies.len();
        let mean = entropies.iter().sum::<f64>() / count as f64;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        let mut high = 0usize;
        for &e in &entropies {
            if e < min {
                min = e;
            }
            if e > max {
                max = e;
            }
            if e >= 7.5 {
                high += 1;
            }
        }
        let var = entropies
            .iter()
            .map(|e| {
                let d = e - mean;
                d * d
            })
            .sum::<f64>()
            / count as f64;
        Self {
            window_size: window,
            count,
            mean,
            min,
            max,
            stddev: var.sqrt(),
            high_entropy_fraction: high as f64 / count as f64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_constant_is_zero() {
        let data = vec![0xAAu8; 1024];
        assert!(shannon_entropy(&data).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_uniform_is_eight() {
        // One copy of each possible byte → perfectly uniform.
        let data: Vec<u8> = (0u16..256).map(|x| x as u8).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 1e-9, "entropy was {h}");
    }

    #[test]
    fn report_contains_window_stats() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 7) as u8).collect();
        let r = EntropyReport::from_bytes(&data);
        assert!(r.shannon_bits_per_byte > 7.0);
        let w = r.windows.expect("windows present for non-empty input");
        assert!(w.count > 0);
        assert!(w.mean > 0.0);
    }
}
