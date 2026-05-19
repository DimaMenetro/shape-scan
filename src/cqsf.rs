//! Cognitive Quarantine & Semantic Firewall (CQSF)
//!
//! TEM Module 3 — THE MOST CRITICAL COMPONENT.
//!
//! Enforces the hard architectural boundary between the TEM analysis
//! pipeline and any LLM or Cephalon-class agent (including Kytheion).
//!
//! THE SINGLE RULE: Only numeric feature vectors cross this boundary.
//!
//! No raw binary content, decoded strings, reconstructed code, or
//! natural language may pass through. This is architectural enforcement.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aise::IntentProfile;
use crate::markov::MarkovProfile;
use crate::tcge::{self, TopologyProfile};
use crate::tfea::{self, EntropyProfile};

// ============================================================
// Quarantine Verdict
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum Verdict {
    Clear = 0,
    Monitor = 1,
    Quarantine = 2,
    Destroy = 3,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clear => "CLEAR",
            Verdict::Monitor => "MONITOR",
            Verdict::Quarantine => "QUARANTINE",
            Verdict::Destroy => "DESTROY",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Clear => 0,
            Verdict::Monitor => 0,
            Verdict::Quarantine | Verdict::Destroy => 1,
        }
    }
}

// ============================================================
// Consolidated Report — THE FIREWALL OUTPUT
// ============================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct TEMReport {
    // File identification (numeric hash, not filename)
    pub file_sha256_prefix: u64,
    pub file_size: usize,
    pub analysis_timestamp: f64,

    // TFEA Feature Vector
    pub tfea_mean_entropy: f64,
    pub tfea_median_entropy: f64,
    pub tfea_std_entropy: f64,
    pub tfea_min_entropy: f64,
    pub tfea_max_entropy: f64,
    pub tfea_peak_offset: usize,
    pub tfea_high_entropy_ratio: f64,
    pub tfea_low_entropy_ratio: f64,
    pub tfea_entropy_variance: f64,
    pub tfea_bulk_entropy: f64,
    pub tfea_declared_type: u8,
    pub tfea_declared_compression: u8,
    pub tfea_header_mismatch: u8,
    pub tfea_mismatch_sigma: f64,
    pub tfea_anomaly_flags: u32,

    // TFEA Extension (Phase 2)
    pub tfea_compression_ratio: f64,
    pub tfea_window_entropies: Vec<f64>,

    // Markov Feature Vector
    pub markov_distinct_bytes: usize,
    pub markov_distinct_pairs: usize,
    pub markov_edge_density: f64,
    pub markov_bigram_entropy: f64,
    pub markov_conditional_entropy: f64,
    pub markov_mean_row_entropy: f64,
    pub markov_std_row_entropy: f64,
    pub markov_structural_fingerprint: u64,

    // TCGE Feature Vector
    pub tcge_format_detected: u8,
    pub tcge_node_count: usize,
    pub tcge_edge_count: usize,
    pub tcge_back_edge_count: usize,
    pub tcge_back_edge_ratio: f64,
    pub tcge_graph_density: f64,
    pub tcge_avg_degree: f64,
    pub tcge_max_degree: usize,
    pub tcge_self_loop_count: usize,
    pub tcge_connected_components: usize,
    pub tcge_strongly_connected_count: usize,
    pub tcge_largest_scc_size: usize,
    pub tcge_scc_ratio: f64,
    pub tcge_cycle_count: usize,
    pub tcge_anomaly_flags: u32,

    // AISE Feature Vector
    pub aise_shell_execution: f64,
    pub aise_code_evaluation: f64,
    pub aise_data_decoding: f64,
    pub aise_network_communication: f64,
    pub aise_filesystem_manipulation: f64,
    pub aise_process_control: f64,
    pub aise_credential_access: f64,
    pub aise_obfuscation_indicator: f64,
    pub aise_persistence_mechanism: f64,
    pub aise_information_gathering: f64,
    pub aise_composite_intent: f64,
    pub aise_intent_vector_count: usize,
    pub aise_total_pattern_hits: usize,
    pub aise_pattern_density: f64,
    pub aise_unique_categories: usize,
    pub aise_shell_plus_decode: u8,
    pub aise_network_plus_filesystem: u8,
    pub aise_eval_plus_obfuscation: u8,
    pub aise_anomaly_flags: u32,

    // Composite Scores
    pub entropy_threat_score: f64,
    pub topology_threat_score: f64,
    pub intent_threat_score: f64,
    pub composite_threat_score: f64,

    // Phase 2 Extension: Morphology Engine Fields
    pub structured_fraction: f64,
    pub structural_anomaly_index: f64,

    // Classifications
    pub entropy_anomaly: u8,
    pub topology_anomaly: u8,
    pub intent_anomaly: u8,
    pub header_mismatch_detected: u8,
    pub backdoor_pattern_detected: u8,
    pub dropper_pattern_detected: u8,
    pub webshell_pattern_detected: u8,

    // Verdict
    pub quarantine_verdict: u8,
    pub quarantine_verdict_name: &'static str,
    pub quarantine_confidence: f64,

    // Metadata
    pub pipeline_duration_ms: f64,
}

// ============================================================
// Threat Scoring
// ============================================================

#[allow(clippy::manual_clamp)] // intentional: NaN inputs collapse to 0.0, unlike f64::clamp
fn clamp_score(v: f64) -> f64 {
    v.max(0.0).min(1.0)
}

fn compute_entropy_threat_score(tfea: &EntropyProfile) -> f64 {
    let mut score = 0.0;

    if tfea.header_mismatch {
        score += 0.4;
        score += (tfea.mismatch_sigma * 0.05).min(0.2);
    }

    let flag_count = tfea.anomaly_flags.count_ones() as f64;
    score += (flag_count * 0.1).min(0.3);

    if matches!(tfea.declared_compression, tfea::CompressionState::None)
        && tfea.measured_bulk_entropy > 7.0
    {
        score += 0.2;
    }

    if tfea.std_entropy > 2.5 {
        score += 0.1;
    }

    clamp_score(score)
}

fn compute_topology_threat_score(tcge: &TopologyProfile) -> f64 {
    let mut score = 0.0;

    if tcge.back_edge_ratio > 0.3 {
        score += 0.25;
    } else if tcge.back_edge_ratio > 0.15 {
        score += 0.1;
    }

    if tcge.graph_density > 0.1 {
        score += 0.15;
    }
    if tcge.scc_ratio > 0.5 {
        score += 0.2;
    }
    if tcge.cycle_count > 20 {
        score += 0.2;
    } else if tcge.cycle_count > 10 {
        score += 0.1;
    }

    if tcge.anomaly_flags & tcge::TOPO_ANOMALY_FLAT_DISPATCH != 0 {
        score += 0.3;
    }

    let flag_count = tcge.anomaly_flags.count_ones() as f64;
    score += (flag_count * 0.05).min(0.2);

    clamp_score(score)
}

fn compute_intent_threat_score(aise: &IntentProfile) -> f64 {
    clamp_score(aise.composite_intent_score)
}

fn compute_composite_score(entropy: f64, topology: f64, intent: f64) -> f64 {
    let scores = [entropy, topology, intent];
    let non_zero: Vec<f64> = scores.iter().cloned().filter(|&s| s > 0.01).collect();

    if non_zero.is_empty() {
        return 0.0;
    }

    let max_single = scores.iter().cloned().fold(0.0_f64, f64::max);
    let arithmetic = scores.iter().sum::<f64>() / 3.0;

    let geometric = if non_zero.len() >= 2 {
        let product: f64 = non_zero.iter().product();
        product.powf(1.0 / non_zero.len() as f64)
    } else {
        non_zero[0]
    };

    // Weight: 30% geometric + 30% arithmetic + 40% max-single
    clamp_score(0.3 * geometric + 0.3 * arithmetic + 0.4 * max_single)
}

fn determine_verdict(
    composite: f64,
    entropy: f64,
    topology: f64,
    intent: f64,
    tfea_anomaly: bool,
    tcge_anomaly: bool,
    aise: &IntentProfile,
) -> (Verdict, f64) {
    // IMMEDIATE QUARANTINE: co-occurrence patterns
    if aise.shell_plus_decode {
        return (Verdict::Quarantine, intent.max(0.85));
    }
    if aise.eval_plus_obfuscation {
        return (Verdict::Quarantine, intent.max(0.80));
    }
    if aise.network_plus_filesystem {
        return (Verdict::Quarantine, intent.max(0.75));
    }

    // FAIL-CLOSED: any strong single signal
    if entropy > 0.7 || topology > 0.7 || intent > 0.7 {
        let max_score = entropy.max(topology).max(intent);
        return (Verdict::Quarantine, max_score);
    }

    if composite > 0.6 {
        return (Verdict::Quarantine, composite);
    }

    // Two dimensions moderate concern
    let moderate = [entropy, topology, intent]
        .iter()
        .filter(|&&s| s > 0.3)
        .count();
    if moderate >= 2 {
        return (Verdict::Quarantine, composite);
    }

    // Single dimension moderate
    if composite > 0.3 || [entropy, topology, intent].iter().any(|&s| s > 0.4) {
        return (Verdict::Monitor, composite);
    }

    // Any anomaly flags → MONITOR
    if tfea_anomaly || tcge_anomaly || aise.intent_anomaly {
        return (Verdict::Monitor, composite);
    }

    (Verdict::Clear, 1.0 - composite)
}

// ============================================================
// The Firewall Gate
// ============================================================

/// Consolidate all module outputs into a single TEMReport.
///
/// THIS IS THE SEMANTIC FIREWALL GATE.
/// No strings, no code, no language passes through.
pub fn consolidate(
    data: &[u8],
    tfea: &EntropyProfile,
    markov: &MarkovProfile,
    tcge: &TopologyProfile,
    aise: &IntentProfile,
    pipeline_start_ms: f64,
) -> TEMReport {
    // SHA-256 prefix (first 8 bytes as u64)
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let sha256_prefix = u64::from_be_bytes(hash[..8].try_into().unwrap());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    // Threat scores
    let entropy_score = compute_entropy_threat_score(tfea);
    let topology_score = compute_topology_threat_score(tcge);
    let intent_score = compute_intent_threat_score(aise);
    let composite = compute_composite_score(entropy_score, topology_score, intent_score);

    let (verdict, confidence) = determine_verdict(
        composite,
        entropy_score,
        topology_score,
        intent_score,
        tfea.anomaly_detected,
        tcge.topology_anomaly,
        aise,
    );

    let pipeline_end = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0;
    let duration = pipeline_end - pipeline_start_ms;

    TEMReport {
        file_sha256_prefix: sha256_prefix,
        file_size: tfea.file_size,
        analysis_timestamp: now,

        tfea_mean_entropy: tfea.mean_entropy,
        tfea_median_entropy: tfea.median_entropy,
        tfea_std_entropy: tfea.std_entropy,
        tfea_min_entropy: tfea.min_entropy,
        tfea_max_entropy: tfea.max_entropy,
        tfea_peak_offset: tfea.peak_entropy_offset,
        tfea_high_entropy_ratio: tfea.high_entropy_ratio,
        tfea_low_entropy_ratio: tfea.low_entropy_ratio,
        tfea_entropy_variance: tfea.entropy_variance,
        tfea_bulk_entropy: tfea.measured_bulk_entropy,
        tfea_declared_type: tfea.declared_type as u8,
        tfea_declared_compression: tfea.declared_compression as u8,
        tfea_header_mismatch: tfea.header_mismatch as u8,
        tfea_mismatch_sigma: tfea.mismatch_sigma,
        tfea_anomaly_flags: tfea.anomaly_flags,

        tfea_compression_ratio: tfea.compression_ratio,
        tfea_window_entropies: tfea.window_entropies.clone(),

        markov_distinct_bytes: markov.distinct_bytes,
        markov_distinct_pairs: markov.distinct_pairs,
        markov_edge_density: markov.edge_density,
        markov_bigram_entropy: markov.bigram_entropy,
        markov_conditional_entropy: markov.conditional_entropy,
        markov_mean_row_entropy: markov.mean_row_entropy,
        markov_std_row_entropy: markov.std_row_entropy,
        markov_structural_fingerprint: markov.structural_fingerprint,

        tcge_format_detected: tcge.format_detected,
        tcge_node_count: tcge.node_count,
        tcge_edge_count: tcge.edge_count,
        tcge_back_edge_count: tcge.back_edge_count,
        tcge_back_edge_ratio: tcge.back_edge_ratio,
        tcge_graph_density: tcge.graph_density,
        tcge_avg_degree: tcge.avg_degree,
        tcge_max_degree: tcge.max_degree,
        tcge_self_loop_count: tcge.self_loop_count,
        tcge_connected_components: tcge.connected_components,
        tcge_strongly_connected_count: tcge.strongly_connected_count,
        tcge_largest_scc_size: tcge.largest_scc_size,
        tcge_scc_ratio: tcge.scc_ratio,
        tcge_cycle_count: tcge.cycle_count,
        tcge_anomaly_flags: tcge.anomaly_flags,

        aise_shell_execution: aise.shell_execution_score,
        aise_code_evaluation: aise.code_evaluation_score,
        aise_data_decoding: aise.data_decoding_score,
        aise_network_communication: aise.network_communication_score,
        aise_filesystem_manipulation: aise.filesystem_manipulation_score,
        aise_process_control: aise.process_control_score,
        aise_credential_access: aise.credential_access_score,
        aise_obfuscation_indicator: aise.obfuscation_indicator_score,
        aise_persistence_mechanism: aise.persistence_mechanism_score,
        aise_information_gathering: aise.information_gathering_score,
        aise_composite_intent: aise.composite_intent_score,
        aise_intent_vector_count: aise.intent_vector_count,
        aise_total_pattern_hits: aise.total_pattern_hits,
        aise_pattern_density: aise.pattern_density,
        aise_unique_categories: aise.unique_categories,
        aise_shell_plus_decode: aise.shell_plus_decode as u8,
        aise_network_plus_filesystem: aise.network_plus_filesystem as u8,
        aise_eval_plus_obfuscation: aise.eval_plus_obfuscation as u8,
        aise_anomaly_flags: aise.anomaly_flags,

        entropy_threat_score: entropy_score,
        topology_threat_score: topology_score,
        intent_threat_score: intent_score,
        composite_threat_score: composite,

        // Phase 2 Extension: Morphology Engine Fields
        // structured_fraction: proportion of file bytes covered by TCGE basic blocks
        structured_fraction: if tcge.node_count > 0 && !data.is_empty() {
            // Approximate: each TCGE node covers ~avg_degree * avg_block_size bytes
            // Use edge_count * 2 as proxy for total code structure coverage
            let structure_coverage = (tcge.edge_count * 2).min(data.len());
            structure_coverage as f64 / data.len() as f64
        } else {
            0.0
        },
        // structural_anomaly_index: 0-10 composite metric for telemetry sidebar
        // Formula: w1 * block_count_norm + w2 * intent_score + w3 * markov_gradient_norm
        structural_anomaly_index: {
            let block_norm = (tcge.node_count as f64 / 500.0).min(1.0); // normalize to ~500 blocks
            let intent_norm = intent_score;
            let markov_grad_norm = markov.std_row_entropy / 3.0; // normalize std_row_entropy
            let raw = 0.4 * block_norm + 0.4 * intent_norm + 0.2 * markov_grad_norm.min(1.0);
            (raw * 10.0).min(10.0) // scale to 0-10
        },

        entropy_anomaly: tfea.anomaly_detected as u8,
        topology_anomaly: tcge.topology_anomaly as u8,
        intent_anomaly: aise.intent_anomaly as u8,
        header_mismatch_detected: tfea.header_mismatch as u8,
        backdoor_pattern_detected: aise.shell_plus_decode as u8,
        dropper_pattern_detected: aise.network_plus_filesystem as u8,
        webshell_pattern_detected: aise.eval_plus_obfuscation as u8,

        quarantine_verdict: verdict as u8,
        quarantine_verdict_name: verdict.as_str(),
        quarantine_confidence: clamp_score(confidence),

        pipeline_duration_ms: duration.max(0.0),
    }
}
