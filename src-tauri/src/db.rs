//! SQLite Telemetry Persistence (Step 5)
//!
//! Stores scan results in a local SQLite database for history,
//! comparative analysis (Step 6), and forensic audit trails.
//!
//! Architecture:
//!   - Hybrid schema: indexed query columns + JSON blob for full TEMReport
//!   - Semantic Firewall compliant: no file paths, no decoded content
//!   - Thread-safe via Mutex<Connection> in Tauri managed state
//!
//! Schema v1:
//!   scans(id, timestamp, sha256_prefix, file_size, verdict, confidence,
//!         composite_score, mean_entropy, intent_score, report_json)

use rusqlite::{Connection, params};
use std::sync::Mutex;

/// Thread-safe database wrapper for Tauri managed state.
pub struct ScanDatabase {
    pub conn: Mutex<Connection>,
}

/// A row from the scan history listing (lightweight, no full report).
#[derive(serde::Serialize)]
pub struct ScanHistoryEntry {
    pub id: i64,
    pub timestamp: f64,
    pub file_sha256_prefix: u64,
    pub file_size: i64,
    pub quarantine_verdict: u8,
    pub quarantine_confidence: f64,
    pub composite_threat_score: f64,
    pub tfea_mean_entropy: f64,
    pub aise_composite_intent: f64,
}

/// A full scan record including the JSON blob.
#[derive(serde::Serialize)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: f64,
    pub file_sha256_prefix: u64,
    pub report_json: String,
}

impl ScanDatabase {
    /// Open or create the database at the given path.
    /// Creates the schema if it doesn't exist.
    pub fn open(db_path: &str) -> Result<Self, String> {
        let conn = Connection::open(db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        // Enable WAL mode for better concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| format!("Failed to set WAL mode: {}", e))?;

        // Create schema (idempotent)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp             REAL    NOT NULL,
                file_sha256_prefix    INTEGER NOT NULL,
                file_size             INTEGER NOT NULL,
                quarantine_verdict    INTEGER NOT NULL,
                quarantine_confidence REAL    NOT NULL,
                composite_threat_score REAL   NOT NULL,
                tfea_mean_entropy     REAL    NOT NULL,
                aise_composite_intent REAL    NOT NULL,
                report_json           TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_timestamp
                ON scans(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_sha
                ON scans(file_sha256_prefix);
            CREATE INDEX IF NOT EXISTS idx_scans_verdict
                ON scans(quarantine_verdict);"
        ).map_err(|e| format!("Failed to create schema: {}", e))?;

        Ok(ScanDatabase { conn: Mutex::new(conn) })
    }

    /// Insert a scan result. `report_json` is the pre-serialized TEMReport.
    pub fn save_scan(
        &self,
        timestamp: f64,
        sha_prefix: u64,
        file_size: i64,
        verdict: u8,
        confidence: f64,
        composite_score: f64,
        mean_entropy: f64,
        intent_score: f64,
        report_json: &str,
    ) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        conn.execute(
            "INSERT INTO scans (
                timestamp, file_sha256_prefix, file_size,
                quarantine_verdict, quarantine_confidence,
                composite_threat_score, tfea_mean_entropy,
                aise_composite_intent, report_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                timestamp, sha_prefix as i64, file_size,
                verdict as i64, confidence,
                composite_score, mean_entropy,
                intent_score, report_json
            ],
        ).map_err(|e| format!("Insert error: {}", e))?;

        Ok(conn.last_insert_rowid())
    }

    /// List recent scans (most recent first), up to `limit`.
    pub fn list_scans(&self, limit: usize) -> Result<Vec<ScanHistoryEntry>, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, file_sha256_prefix, file_size,
                    quarantine_verdict, quarantine_confidence,
                    composite_threat_score, tfea_mean_entropy,
                    aise_composite_intent
             FROM scans
             ORDER BY timestamp DESC
             LIMIT ?1"
        ).map_err(|e| format!("Query error: {}", e))?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ScanHistoryEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                file_sha256_prefix: row.get::<_, i64>(2)? as u64,
                file_size: row.get(3)?,
                quarantine_verdict: row.get::<_, i64>(4)? as u8,
                quarantine_confidence: row.get(5)?,
                composite_threat_score: row.get(6)?,
                tfea_mean_entropy: row.get(7)?,
                aise_composite_intent: row.get(8)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("Row error: {}", e))?);
        }
        Ok(entries)
    }

    /// Get a full scan record by ID, including the JSON blob.
    pub fn get_scan(&self, id: i64) -> Result<Option<ScanRecord>, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, file_sha256_prefix, report_json
             FROM scans WHERE id = ?1"
        ).map_err(|e| format!("Query error: {}", e))?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(ScanRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                file_sha256_prefix: row.get::<_, i64>(2)? as u64,
                report_json: row.get(3)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        match rows.next() {
            Some(row) => Ok(Some(row.map_err(|e| format!("Row error: {}", e))?)),
            None => Ok(None),
        }
    }

    /// Delete a scan by ID.
    pub fn delete_scan(&self, id: i64) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let affected = conn.execute(
            "DELETE FROM scans WHERE id = ?1",
            params![id],
        ).map_err(|e| format!("Delete error: {}", e))?;
        Ok(affected > 0)
    }

    /// Get total count of stored scans.
    pub fn scan_count(&self) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .map_err(|e| format!("Count error: {}", e))
    }
}
