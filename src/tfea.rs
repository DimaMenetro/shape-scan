//! Thermodynamic Free Energy Auditor (TFEA)
//!
//! TEM Module 1 — First-pass entropy filter in the analysis pipeline.
//!
//! Operates on raw binary input exclusively. All outputs are numeric.
//!
//! Methods:
//!   1. Sliding-window Shannon entropy (256-byte windows, 64-byte step)
//!   2. Header-to-Entropy Mismatch Analysis (declared vs actual)
//!   3. Per-file entropy profile generation (numeric-only output)

use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

// ============================================================
// File type codes (numeric only — no strings cross the firewall)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum FileType {
    Unknown = 0,
    PeExe = 1,
    Elf = 2,
    MachO = 3,
    Pdf = 4,
    Zip = 5,
    Gzip = 6,
    Bzip2 = 7,
    Xz = 8,
    Rar = 9,
    SevenZ = 10,
    Png = 11,
    Jpeg = 12,
    Gif = 13,
    Bmp = 14,
    Tiff = 15,
    DocOle = 16,
    DocxOoxml = 17,
    Php = 18,
    Script = 19,
    Plaintext = 20,
    Xml = 21,
    Html = 22,
    Sqlite = 23,
    Tar = 24,
    Iso = 25,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum CompressionState {
    None = 0,
    Compressed = 1,
    Encrypted = 2,
    Unknown = 255,
}

// ============================================================
// Anomaly flags (bitfield)
// ============================================================

pub const ANOMALY_NONE: u32 = 0x0000;
pub const ANOMALY_HEADER_MISMATCH: u32 = 0x0001;
pub const ANOMALY_HIDDEN_ENCRYPTED: u32 = 0x0002;
pub const ANOMALY_ENTROPY_SPIKE: u32 = 0x0004;
pub const ANOMALY_UNIFORM_HIGH: u32 = 0x0008;
pub const ANOMALY_PLAINTEXT_WITH_BLOB: u32 = 0x0010;
pub const ANOMALY_ZOMBIE_ZIP: u32 = 0x0020;

// ============================================================
// Output type — strictly numeric
// ============================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntropyProfile {
    pub file_size: usize,
    pub window_size: usize,
    pub step_size: usize,
    pub num_windows: usize,

    // Global statistics
    pub mean_entropy: f64,
    pub median_entropy: f64,
    pub std_entropy: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub peak_entropy_offset: usize,
    pub peak_entropy_value: f64,

    // Distribution characteristics
    pub high_entropy_ratio: f64, // fraction of windows with H > 7.0
    pub low_entropy_ratio: f64,  // fraction of windows with H < 1.0
    pub entropy_variance: f64,

    // Header-Mismatch Analysis
    pub declared_type: FileType,
    pub declared_compression: CompressionState,
    pub measured_bulk_entropy: f64,
    pub header_mismatch: bool,
    pub mismatch_sigma: f64,

    // Compression ratio (TFEA Extension — Phase 2)
    // DEFLATE-derived measure of structural redundancy.
    // 1.0 = incompressible (encrypted/random), 0.0 = fully redundant.
    pub compression_ratio: f64,

    // Verdict
    pub anomaly_detected: bool,
    pub anomaly_flags: u32,

    // Per-window entropies (for visualization)
    pub window_entropies: Vec<f64>,
}

// ============================================================
// Magic byte table
// ============================================================

struct MagicEntry {
    offset: usize,
    magic: &'static [u8],
    file_type: FileType,
    compression: CompressionState,
}

const MAGIC_TABLE: &[MagicEntry] = &[
    MagicEntry {
        offset: 0,
        magic: b"MZ",
        file_type: FileType::PeExe,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"\x7fELF",
        file_type: FileType::Elf,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"\xfe\xed\xfa",
        file_type: FileType::MachO,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"\xcf\xfa\xed\xfe",
        file_type: FileType::MachO,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"%PDF",
        file_type: FileType::Pdf,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"PK\x03\x04",
        file_type: FileType::Zip,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"PK\x05\x06",
        file_type: FileType::Zip,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"\x1f\x8b",
        file_type: FileType::Gzip,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"BZ",
        file_type: FileType::Bzip2,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"\xfd7zXZ\x00",
        file_type: FileType::Xz,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"Rar!\x1a\x07",
        file_type: FileType::Rar,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"7z\xbc\xaf\x27\x1c",
        file_type: FileType::SevenZ,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"\x89PNG\r\n\x1a\n",
        file_type: FileType::Png,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"\xff\xd8\xff",
        file_type: FileType::Jpeg,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"GIF87a",
        file_type: FileType::Gif,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"GIF89a",
        file_type: FileType::Gif,
        compression: CompressionState::Compressed,
    },
    MagicEntry {
        offset: 0,
        magic: b"BM",
        file_type: FileType::Bmp,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"II\x2a\x00",
        file_type: FileType::Tiff,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"MM\x00\x2a",
        file_type: FileType::Tiff,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        file_type: FileType::DocOle,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"SQLite format",
        file_type: FileType::Sqlite,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 0,
        magic: b"#!",
        file_type: FileType::Script,
        compression: CompressionState::None,
    },
    MagicEntry {
        offset: 257,
        magic: b"ustar",
        file_type: FileType::Tar,
        compression: CompressionState::None,
    },
];

// Expected entropy ranges per file type: (min, max)
fn expected_entropy(ft: FileType) -> (f64, f64) {
    match ft {
        FileType::Unknown => (0.0, 8.0),
        FileType::PeExe => (4.0, 7.5),
        FileType::Elf => (4.0, 7.5),
        FileType::MachO => (4.0, 7.5),
        FileType::Pdf => (3.0, 7.8),
        FileType::Zip => (7.5, 8.0),
        FileType::Gzip => (7.5, 8.0),
        FileType::Bzip2 => (7.5, 8.0),
        FileType::Xz => (7.5, 8.0),
        FileType::Rar => (7.5, 8.0),
        FileType::SevenZ => (7.5, 8.0),
        FileType::Png => (6.0, 8.0),
        FileType::Jpeg => (7.0, 8.0),
        FileType::Gif => (5.0, 7.5),
        FileType::Bmp => (1.0, 6.5),
        FileType::Tiff => (3.0, 7.5),
        FileType::DocOle => (3.0, 6.5),
        FileType::DocxOoxml => (7.5, 8.0),
        FileType::Php => (2.0, 5.5),
        FileType::Script => (2.0, 5.5),
        FileType::Plaintext => (1.0, 5.0),
        FileType::Xml => (2.0, 5.0),
        FileType::Html => (2.5, 5.5),
        FileType::Sqlite => (3.0, 6.0),
        FileType::Tar => (4.0, 7.0),
        FileType::Iso => (4.0, 7.0),
    }
}

// ============================================================
// Core engine
// ============================================================

/// Compute Shannon entropy H (bits/byte) for a byte sequence.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compute sliding-window entropy across a byte sequence.
///
/// Returns vector of H scores (bits/byte) for each window position.
pub fn sliding_window_entropy(data: &[u8], window_size: usize, step_size: usize) -> Vec<f64> {
    if data.len() < window_size {
        return vec![shannon_entropy(data)];
    }

    let num_windows = (data.len() - window_size) / step_size + 1;
    let mut entropies = Vec::with_capacity(num_windows);

    for i in 0..num_windows {
        let start = i * step_size;
        let end = start + window_size;
        entropies.push(shannon_entropy(&data[start..end]));
    }

    entropies
}

/// Identify file type and compression state from magic bytes.
pub fn identify_file_type(data: &[u8]) -> (FileType, CompressionState) {
    if data.len() < 4 {
        return (FileType::Unknown, CompressionState::Unknown);
    }

    for entry in MAGIC_TABLE {
        let end = entry.offset + entry.magic.len();
        if end <= data.len() && data[entry.offset..end] == *entry.magic {
            return (entry.file_type, entry.compression);
        }
    }

    // Heuristic: check if content is predominantly ASCII (text file)
    let sample_len = data.len().min(4096);
    let sample = &data[..sample_len];
    let printable = sample
        .iter()
        .filter(|&&b| (32..=126).contains(&b) || b == 9 || b == 10 || b == 13)
        .count();

    if printable as f64 / sample_len as f64 > 0.85 {
        let header_1k = &data[..data.len().min(1024)];
        if header_1k.windows(5).any(|w| w == b"<?php") || header_1k.windows(3).any(|w| w == b"<?=")
        {
            return (FileType::Php, CompressionState::None);
        }
        let lower: Vec<u8> = data[..data.len().min(256)]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect();
        if lower.windows(5).any(|w| w == b"<?xml") {
            return (FileType::Xml, CompressionState::None);
        }
        if lower.windows(5).any(|w| w == b"<html")
            || lower.windows(15).any(|w| w == b"<!doctype html>")
        {
            return (FileType::Html, CompressionState::None);
        }
        return (FileType::Plaintext, CompressionState::None);
    }

    (FileType::Unknown, CompressionState::Unknown)
}

/// Header-to-Entropy Mismatch Analysis.
///
/// Returns (is_mismatch, sigma_deviation).
fn header_entropy_mismatch(
    file_type: FileType,
    _compression: CompressionState,
    measured: f64,
    sigma_threshold: f64,
) -> (bool, f64) {
    let (min_exp, max_exp) = expected_entropy(file_type);
    let range = max_exp - min_exp;

    if range == 0.0 {
        return (false, 0.0);
    }

    let sigma = range / 2.5;

    let deviation = if measured > max_exp {
        (measured - max_exp) / sigma
    } else if measured < min_exp {
        (min_exp - measured) / sigma
    } else {
        0.0
    };

    (deviation > sigma_threshold, deviation)
}

// ============================================================
// Main analysis function
// ============================================================

/// Perform full TFEA analysis on a file at the given path.
pub fn analyze(path: &Path) -> io::Result<EntropyProfile> {
    let data = fs::read(path)?;
    Ok(analyze_bytes(&data))
}

/// Perform full TFEA analysis on raw bytes.
pub fn analyze_bytes(data: &[u8]) -> EntropyProfile {
    let file_size = data.len();
    let window_size = 256;
    let step_size = 64;
    let sigma_threshold = 2.5;
    let spike_threshold = 7.2;

    // Identify file type
    let (file_type, compression) = identify_file_type(data);

    // Sliding-window entropy
    let window_entropies = sliding_window_entropy(data, window_size, step_size);
    let num_windows = window_entropies.len();

    // Global statistics
    let (mean, median, std_dev, min_val, max_val, peak_idx) = if num_windows > 0 {
        let sum: f64 = window_entropies.iter().sum();
        let mean = sum / num_windows as f64;

        let mut sorted = window_entropies.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if num_windows.is_multiple_of(2) {
            (sorted[num_windows / 2 - 1] + sorted[num_windows / 2]) / 2.0
        } else {
            sorted[num_windows / 2]
        };

        let variance: f64 = window_entropies
            .iter()
            .map(|e| (e - mean).powi(2))
            .sum::<f64>()
            / num_windows as f64;
        let std_dev = variance.sqrt();

        let min_val = sorted[0];
        let max_val = sorted[num_windows - 1];

        let peak_idx = window_entropies
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        (mean, median, std_dev, min_val, max_val, peak_idx)
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0)
    };

    let peak_offset = peak_idx * step_size;
    let peak_value = if num_windows > 0 {
        window_entropies[peak_idx]
    } else {
        0.0
    };

    // Distribution characteristics
    let high_ratio = if num_windows > 0 {
        window_entropies.iter().filter(|&&e| e > 7.0).count() as f64 / num_windows as f64
    } else {
        0.0
    };

    let low_ratio = if num_windows > 0 {
        window_entropies.iter().filter(|&&e| e < 1.0).count() as f64 / num_windows as f64
    } else {
        0.0
    };

    let variance = if num_windows > 0 {
        let m = mean;
        window_entropies
            .iter()
            .map(|e| (e - m).powi(2))
            .sum::<f64>()
            / num_windows as f64
    } else {
        0.0
    };

    // Bulk entropy
    let bulk_entropy = shannon_entropy(data);

    // Header mismatch
    let (is_mismatch, mismatch_sigma) =
        header_entropy_mismatch(file_type, compression, bulk_entropy, sigma_threshold);

    // Anomaly detection
    let mut anomaly_flags: u32 = ANOMALY_NONE;

    if is_mismatch {
        anomaly_flags |= ANOMALY_HEADER_MISMATCH;
    }

    // Localized entropy spikes (embedded payload indicator)
    if num_windows > 10 {
        let spike_count = window_entropies
            .iter()
            .filter(|&&e| e > spike_threshold)
            .count();
        let non_spike = num_windows - spike_count;
        if spike_count > 0 && non_spike > 0 {
            let spike_ratio = spike_count as f64 / num_windows as f64;
            if spike_ratio > 0.05 && spike_ratio < 0.5 {
                anomaly_flags |= ANOMALY_ENTROPY_SPIKE;
            }
            if spike_ratio > 0.8 {
                anomaly_flags |= ANOMALY_UNIFORM_HIGH;
            }
        }
    }

    // Zombie ZIP detection
    if matches!(compression, CompressionState::None) && bulk_entropy > 7.2 {
        match file_type {
            FileType::Php
            | FileType::Script
            | FileType::Plaintext
            | FileType::Xml
            | FileType::Html => {
                anomaly_flags |= ANOMALY_ZOMBIE_ZIP;
            }
            FileType::Bmp => {
                anomaly_flags |= ANOMALY_HIDDEN_ENCRYPTED;
            }
            _ => {}
        }
    }

    // Text file with binary blob
    if matches!(
        file_type,
        FileType::Php | FileType::Script | FileType::Plaintext
    ) && num_windows > 10
        && std_dev > 2.0
        && max_val > 7.0
    {
        anomaly_flags |= ANOMALY_PLAINTEXT_WITH_BLOB;
    }

    let anomaly_detected = anomaly_flags != ANOMALY_NONE;

    // Compression ratio: DEFLATE the raw data and compare sizes.
    // This is the "entropy lie-detector" — a file can have high Shannon
    // entropy but still be compressible if the entropy is structured
    // (e.g., base64-encoded payloads). A truly random/encrypted file
    // will have compression_ratio ≈ 1.0.
    let compression_ratio = if file_size > 0 {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        let _ = encoder.write_all(data);
        match encoder.finish() {
            Ok(compressed) => compressed.len() as f64 / file_size as f64,
            Err(_) => 1.0, // fail-closed: assume incompressible
        }
    } else {
        0.0
    };

    EntropyProfile {
        file_size,
        window_size,
        step_size,
        num_windows,
        mean_entropy: mean,
        median_entropy: median,
        std_entropy: std_dev,
        min_entropy: min_val,
        max_entropy: max_val,
        peak_entropy_offset: peak_offset,
        peak_entropy_value: peak_value,
        high_entropy_ratio: high_ratio,
        low_entropy_ratio: low_ratio,
        entropy_variance: variance,
        declared_type: file_type,
        declared_compression: compression,
        measured_bulk_entropy: bulk_entropy,
        header_mismatch: is_mismatch,
        mismatch_sigma,
        compression_ratio,
        anomaly_detected,
        anomaly_flags,
        window_entropies,
    }
}
