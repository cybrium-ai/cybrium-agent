use crate::config::Config;
use crate::sensors::Finding;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use tracing::{debug, error, info};

/// Returns the path to the SQLite buffer database.
fn db_path() -> PathBuf {
    Config::base_dir().join("buffer.db")
}

/// Open a connection to the buffer database, creating it if necessary.
pub fn open() -> anyhow::Result<Connection> {
    let path = db_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let conn = Connection::open(&path)?;

    // Enable WAL mode for better concurrent read/write
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS findings (
            id          TEXT PRIMARY KEY,
            sensor_type TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            synced_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_synced
            ON findings (synced_at);

        CREATE INDEX IF NOT EXISTS idx_findings_created
            ON findings (created_at);",
    )?;

    Ok(conn)
}

/// Insert a batch of findings into the local buffer.
pub fn insert_findings(conn: &Connection, findings: &[Finding]) -> anyhow::Result<usize> {
    let now = Utc::now().to_rfc3339();
    let mut count = 0;

    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO findings (id, sensor_type, finding_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
    )?;

    for finding in findings {
        let json = serde_json::to_string(finding)?;
        match stmt.execute(params![finding.id, finding.sensor_type, json, now]) {
            Ok(n) => count += n,
            Err(e) => error!(finding_id = %finding.id, error = %e, "failed to buffer finding"),
        }
    }

    debug!(inserted = count, "findings buffered");
    Ok(count)
}

/// Retrieve all un-synced findings from the buffer.
pub fn get_unsynced(conn: &Connection) -> anyhow::Result<Vec<(i64, Finding)>> {
    let mut stmt = conn.prepare(
        "SELECT rowid, finding_json FROM findings WHERE synced_at IS NULL ORDER BY created_at ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        let rowid: i64 = row.get(0)?;
        let json: String = row.get(1)?;
        Ok((rowid, json))
    })?;

    let mut results = Vec::new();
    for row in rows {
        let (rowid, json) = row?;
        match serde_json::from_str::<Finding>(&json) {
            Ok(finding) => results.push((rowid, finding)),
            Err(e) => error!(rowid = rowid, error = %e, "corrupt finding in buffer"),
        }
    }

    Ok(results)
}

/// Mark a batch of findings as synced (by rowid).
pub fn mark_synced(conn: &Connection, rowids: &[i64]) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let mut stmt = conn.prepare("UPDATE findings SET synced_at = ?1 WHERE rowid = ?2")?;

    for &rowid in rowids {
        stmt.execute(params![now, rowid])?;
    }

    debug!(count = rowids.len(), "findings marked as synced");
    Ok(())
}

/// Purge findings that were synced more than 24 hours ago.
pub fn purge_old_synced(conn: &Connection) -> anyhow::Result<usize> {
    let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let deleted = conn.execute(
        "DELETE FROM findings WHERE synced_at IS NOT NULL AND synced_at < ?1",
        params![cutoff],
    )?;

    if deleted > 0 {
        info!(purged = deleted, "purged old synced findings");
    }

    Ok(deleted)
}

/// Get counts for status display.
pub fn stats(conn: &Connection) -> anyhow::Result<BufferStats> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
    let unsynced: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE synced_at IS NULL",
        [],
        |r| r.get(0),
    )?;
    let synced: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE synced_at IS NOT NULL",
        [],
        |r| r.get(0),
    )?;

    Ok(BufferStats {
        total: total as usize,
        unsynced: unsynced as usize,
        synced: synced as usize,
    })
}

#[derive(Debug)]
pub struct BufferStats {
    pub total: usize,
    pub unsynced: usize,
    pub synced: usize,
}
