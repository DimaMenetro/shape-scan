//! Tauri IPC Command Handlers
//!
//! THE SEMANTIC FIREWALL BRIDGE.
//!
//! Each command invokes the shape_scan analysis engine and returns
//! strictly numeric data to the frontend WebView. No raw binary
//! content, decoded strings, or file paths cross this boundary.

use std::path::PathBuf;
use shape_scan::cqsf::TEMReport;
use shape_scan::tfea::EntropyProfile;
use shape_scan::markov::MarkovProfile;
use shape_scan::tcge::TopologyProfile;
use shape_scan::aise::IntentProfile;

use crate::db::ScanDatabase;

/// Full TEM pipeline scan — returns the consolidated numeric report.
#[tauri::command]
pub async fn scan_file(path: String) -> Result<TEMReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        if !p.exists() {
            return Err(format!("File not found: {}", path));
        }
        if !p.is_file() {
            return Err("Target must be a file, not a directory".into());
        }
        shape_scan::pipeline::scan_file(&p).map_err(|e| format!("Scan error: {}", e))
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

/// Entropy-only analysis.
#[tauri::command]
pub async fn scan_entropy(path: String) -> Result<EntropyProfile, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        shape_scan::tfea::analyze(&p).map_err(|e| format!("TFEA error: {}", e))
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

/// Shape analysis (topology + Markov).
#[tauri::command]
pub async fn scan_shape(path: String) -> Result<ShapeResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        let topology = shape_scan::tcge::analyze(&p).map_err(|e| format!("TCGE error: {}", e))?;
        let markov = shape_scan::markov::analyze(&p).map_err(|e| format!("Markov error: {}", e))?;
        Ok(ShapeResult { topology, markov })
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

#[derive(serde::Serialize)]
pub struct ShapeResult {
    pub topology: TopologyProfile,
    pub markov: MarkovProfile,
}

/// Intent-only analysis.
#[tauri::command]
pub async fn scan_intent(path: String) -> Result<IntentProfile, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        shape_scan::aise::analyze(&p).map_err(|e| format!("AISE error: {}", e))
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

/// Returns per-window entropy values for the heatmap visualization.
/// Each value is a f64 in [0, 8] representing Shannon entropy.
#[tauri::command]
pub async fn get_entropy_windows(path: String) -> Result<Vec<f64>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        let profile = shape_scan::tfea::analyze(&p).map_err(|e| format!("TFEA error: {}", e))?;
        Ok(profile.window_entropies)
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

/// Returns the 256×256 Markov transition probability matrix for 3D surface rendering.
/// Each value is a f64 in [0, 1] representing P(byte_j | byte_i).
#[tauri::command]
pub async fn get_markov_matrix(path: String) -> Result<Vec<Vec<f64>>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        let data = std::fs::read(&p).map_err(|e| format!("Read error: {}", e))?;

        if data.len() < 2 {
            return Ok(vec![vec![0.0; 256]; 256]);
        }

        // Build transition count matrix
        let mut counts = vec![vec![0u64; 256]; 256];
        for window in data.windows(2) {
            counts[window[0] as usize][window[1] as usize] += 1;
        }

        // Convert to probabilities
        let matrix: Vec<Vec<f64>> = counts.iter().map(|row| {
            let total: u64 = row.iter().sum();
            if total == 0 {
                vec![0.0; 256]
            } else {
                row.iter().map(|&c| c as f64 / total as f64).collect()
            }
        }).collect();

        Ok(matrix)
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

/// Returns the causal graph structure for 3D force-graph rendering.
/// Only numeric node IDs and edge pairs — no decoded content.
#[tauri::command]
pub async fn get_graph_data(path: String) -> Result<GraphData, String> {
    tauri::async_runtime::spawn_blocking(move || {
    let p = PathBuf::from(&path);
    let data = std::fs::read(&p).map_err(|e| format!("Read error: {}", e))?;

    // Get the full profiles for node coloring
    let _tfea_profile = shape_scan::tfea::analyze_bytes(&data);
    let aise_profile = shape_scan::aise::analyze_bytes(&data);

    // Get topology profile
    let topo = shape_scan::tcge::analyze_bytes(&data);

    // Build a simplified graph representation for the frontend
    // We use section-based blocks for executable files, byte-block based for others
    let file_size = data.len();
    let block_size = (file_size / 256).max(64);
    let num_blocks = (file_size / block_size).min(512);

    let mut nodes = Vec::new();
    let mut links = Vec::new();

    for i in 0..num_blocks {
        let start = i * block_size;
        let end = (start + block_size).min(file_size);
        let block = &data[start..end];

        // Per-block entropy (normalized to 0-1)
        let entropy = block_entropy(block) / 8.0;

        nodes.push(GraphNode {
            id: i,
            entropy,
            intent: aise_profile.composite_intent_score,
            size: (end - start) as f64,
            offset: start,
        });

        // Sequential edge
        if i > 0 {
            links.push(GraphLink {
                source: i - 1,
                target: i,
                is_back_edge: false,
            });
        }
    }

    // Add cross-reference edges (structural jumps)
    for i in 0..num_blocks.min(256) {
        let start = i * block_size;
        let end = (start + block_size).min(file_size);
        let block = &data[start..end];

        for j in (0..block.len().saturating_sub(3)).step_by(8) {
            if j + 4 > block.len() { break; }
            let ref_val = u32::from_le_bytes([block[j], block[j+1], block[j+2], block[j+3]]) as usize;
            let target_block = ref_val / block_size;
            if target_block < num_blocks && target_block != i && target_block > 0 {
                let is_back = target_block < i;
                links.push(GraphLink {
                    source: i,
                    target: target_block,
                    is_back_edge: is_back,
                });
                break; // One cross-ref per block max
            }
        }
    }

    Ok(GraphData {
        nodes,
        links,
        node_count: topo.node_count,
        edge_count: topo.edge_count,
        back_edge_ratio: topo.back_edge_ratio,
        format_detected: topo.format_detected,
    })
    }).await.map_err(|e| format!("Thread error: {}", e))?
}

#[derive(serde::Serialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub links: Vec<GraphLink>,
    pub node_count: usize,
    pub edge_count: usize,
    pub back_edge_ratio: f64,
    pub format_detected: u8,
}

#[derive(serde::Serialize)]
pub struct GraphNode {
    pub id: usize,
    pub entropy: f64,      // 0-1 normalized
    pub intent: f64,        // 0-1 composite intent
    pub size: f64,          // block size in bytes
    pub offset: usize,      // byte offset in file
}

#[derive(serde::Serialize)]
pub struct GraphLink {
    pub source: usize,
    pub target: usize,
    pub is_back_edge: bool,
}

/// Simple per-block Shannon entropy.
fn block_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Returns raw byte values (as u8 integers 0-255) for a specific byte range.
/// Used by the Focus Lens (Step 2D) for fine-grained structural inspection.
///
/// Semantic Firewall compliance: byte values ARE numeric data.
/// The frontend cannot decode or interpret these — it only maps them to
/// heights and colors in a wireframe visualization.
///
/// Length is capped at 4096 bytes to bound memory + rendering cost.
#[tauri::command]
pub async fn get_byte_range_detail(
    path: String,
    offset: usize,
    length: usize,
) -> Result<ByteRangeDetail, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        let data = std::fs::read(&p).map_err(|e| format!("Read error: {}", e))?;

        // Clamp length to 4096 and offset to file bounds
        let actual_offset = offset.min(data.len());
        let actual_length = length.min(4096).min(data.len().saturating_sub(actual_offset));
        let end = actual_offset + actual_length;

        let bytes: Vec<u8> = data[actual_offset..end].to_vec();

        // Compute per-byte rolling entropy (16-byte sliding window)
        let window_size = 16usize;
        let mut rolling_entropy = Vec::with_capacity(actual_length);
        for i in 0..actual_length {
            let win_start = if i >= window_size / 2 {
                (actual_offset + i - window_size / 2).min(data.len().saturating_sub(window_size))
            } else {
                actual_offset
            };
            let win_end = (win_start + window_size).min(data.len());
            rolling_entropy.push(block_entropy(&data[win_start..win_end]));
        }

        Ok(ByteRangeDetail {
            bytes,
            offset: actual_offset,
            length: actual_length,
            rolling_entropy,
        })
    })
    .await
    .map_err(|e| format!("Thread error: {}", e))?
}

#[derive(serde::Serialize)]
pub struct ByteRangeDetail {
    pub bytes: Vec<u8>,
    pub offset: usize,
    pub length: usize,
    /// Per-byte rolling Shannon entropy (16-byte window), values in [0, 8].
    pub rolling_entropy: Vec<f64>,
}

/// Opens a native file dialog and returns the selected path.
/// Returns None (null in JS) if the user cancels.
///
/// MUST be async — a blocking dialog on the main thread deadlocks the event loop.
#[tauri::command]
pub async fn browse_file(window: tauri::Window) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    window.dialog().file()
        .set_title("Select file to analyze")
        .pick_file(move |file_path| {
            let _ = tx.send(file_path.map(|f| f.to_string()));
        });

    // recv blocks this tokio task (not the main thread) until
    // the user picks a file or cancels the dialog
    rx.recv().ok().flatten()
}

// ============================================================
// Persistence Commands (Step 5 — SQLite)
// ============================================================

/// Saves a scan result to the database.
/// Accepts the full TEMReport as a JSON string plus key indexed fields.
#[tauri::command]
pub async fn save_scan(
    db: tauri::State<'_, ScanDatabase>,
    timestamp: f64,
    sha_prefix: u64,
    file_size: i64,
    verdict: u8,
    confidence: f64,
    composite_score: f64,
    mean_entropy: f64,
    intent_score: f64,
    report_json: String,
) -> Result<i64, String> {
    db.save_scan(
        timestamp, sha_prefix, file_size,
        verdict, confidence, composite_score,
        mean_entropy, intent_score, &report_json,
    )
}

/// Lists recent scan history (most recent first).
#[tauri::command]
pub async fn list_scans(
    db: tauri::State<'_, ScanDatabase>,
    limit: Option<usize>,
) -> Result<Vec<crate::db::ScanHistoryEntry>, String> {
    db.list_scans(limit.unwrap_or(50))
}

/// Retrieves a full scan record by ID, including the JSON report blob.
#[tauri::command]
pub async fn get_scan(
    db: tauri::State<'_, ScanDatabase>,
    id: i64,
) -> Result<Option<crate::db::ScanRecord>, String> {
    db.get_scan(id)
}

/// Deletes a scan record by ID.
#[tauri::command]
pub async fn delete_scan(
    db: tauri::State<'_, ScanDatabase>,
    id: i64,
) -> Result<bool, String> {
    db.delete_scan(id)
}
