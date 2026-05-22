//! # Shape-Scan / TEM v2.0
//!
//! Geometric threat analysis engine. Measures the mathematical shape of files
//! to detect malware through topology, entropy, and intent — not signatures.
//!
//! ## Architecture
//!
//! ```text
//! Raw Binary → TFEA (entropy) → Markov (microstructure) → TCGE (topology)
//!            → AISE (intent) → CQSF (firewall + verdict) → Numeric Report
//! ```
//!
//! The Semantic Firewall (CQSF) ensures only numeric feature vectors
//! leave the analysis pipeline. No decoded strings, no reconstructed
//! code, no natural language crosses this boundary.

pub mod aise;
pub mod cli;
pub mod cqsf;
pub mod markov;
pub mod pipeline;
pub mod tcge;
pub mod tfea;

pub use cqsf::{TEMReport, Verdict};
pub use pipeline::scan_file;
