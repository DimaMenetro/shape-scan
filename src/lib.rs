//! Library crate for `shape-scan`.
//!
//! Provides entropy and topological "shape" analysis of arbitrary byte
//! streams, plus section-aware analysis for known executable formats
//! (ELF, PE, Mach-O). Higher-level scoring is exposed via [`scan`].

pub mod entropy;
pub mod scan;
pub mod sections;
pub mod shape;

pub use entropy::{EntropyReport, WindowEntropy};
pub use scan::{scan_path, FileReport, RiskLevel};
pub use sections::{SectionEntropy, SectionReport};
pub use shape::{byte_histogram, ShapeReport};
