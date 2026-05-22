//! Tauri application entry point for shape-scan UI.
//!
//! Registers all IPC command handlers and launches the WebView window.
//! Initializes the SQLite scan database on startup (Step 5).

mod ipc;
mod db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize scan database in user home directory
    // MUST be outside the project tree — Tauri's file watcher triggers on
    // SQLite WAL/SHM files, causing an infinite restart loop if the DB
    // is anywhere inside the watched src-tauri/ or project root.
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let db_dir = std::path::PathBuf::from(home).join(".shape-scan");
    if !db_dir.exists() {
        std::fs::create_dir_all(&db_dir)
            .expect("[TEM] Failed to create ~/.shape-scan directory");
    }
    let db_path = db_dir.join("shape_scan.db");
    let scan_db = db::ScanDatabase::open(db_path.to_str().unwrap())
        .expect("[TEM] Failed to initialize scan database");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(scan_db)
        .invoke_handler(tauri::generate_handler![
            // Analysis pipeline
            ipc::scan_file,
            ipc::scan_entropy,
            ipc::scan_shape,
            ipc::scan_intent,
            ipc::get_entropy_windows,
            ipc::get_markov_matrix,
            ipc::get_graph_data,
            ipc::get_byte_range_detail,
            ipc::browse_file,
            // Persistence (Step 5)
            ipc::save_scan,
            ipc::list_scans,
            ipc::get_scan,
            ipc::delete_scan,
        ])
        .run(tauri::generate_context!())
        .expect("[TEM] Error launching Tauri application");
}

fn main() {
    run();
}
