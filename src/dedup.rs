use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use std::path::PathBuf;

/// Device record in the local inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub mac: String,
    pub ip: String,
    pub vendor: String,
    pub hostname: Option<String>,
    pub device_type: String,
    pub purdue_level: Option<u8>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub first_seen: String,
    pub last_seen: String,
    pub fingerprint: String,
    pub changed: bool,
    pub synced: bool,
}

impl DeviceRecord {
    /// Create a new device record from discovered data, computing the
    /// fingerprint from MAC + vendor + device_type.
    pub fn new(
        mac: String,
        ip: String,
        vendor: String,
        hostname: Option<String>,
        device_type: String,
        purdue_level: Option<u8>,
        protocols: Vec<String>,
        ports: Vec<u16>,
    ) -> Self {
        let fingerprint = compute_fingerprint(&mac, &vendor, &device_type);
        let now = Utc::now().to_rfc3339();
        Self {
            mac,
            ip,
            vendor,
            hostname,
            device_type,
            purdue_level,
            protocols,
            ports,
            first_seen: now.clone(),
            last_seen: now,
            fingerprint,
            changed: true,
            synced: false,
        }
    }
}

/// Compute a stable fingerprint from identity fields.
fn compute_fingerprint(mac: &str, vendor: &str, device_type: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(mac.to_uppercase().as_bytes());
    hasher.update(b"|");
    hasher.update(vendor.as_bytes());
    hasher.update(b"|");
    hasher.update(device_type.as_bytes());
    hex::encode(hasher.finalize())
}

/// Dedup engine backed by SQLite. Tracks all discovered devices locally
/// and determines which ones are new or changed since the last sync.
pub struct DeviceInventory {
    db: Connection,
}

/// Returns the path to the device inventory database.
fn db_path() -> PathBuf {
    Config::base_dir().join("devices.db")
}

impl DeviceInventory {
    /// Open or create the device inventory database.
    pub fn new(db_path_override: Option<&str>) -> anyhow::Result<Self> {
        let path = match db_path_override {
            Some(p) => PathBuf::from(p),
            None => db_path(),
        };
        std::fs::create_dir_all(path.parent().unwrap())?;
        let db = Connection::open(&path)?;

        db.execute_batch("PRAGMA journal_mode=WAL;")?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                mac          TEXT PRIMARY KEY,
                ip           TEXT NOT NULL,
                vendor       TEXT NOT NULL DEFAULT '',
                hostname     TEXT,
                device_type  TEXT NOT NULL DEFAULT 'unknown',
                purdue_level INTEGER,
                protocols    TEXT NOT NULL DEFAULT '[]',
                ports        TEXT NOT NULL DEFAULT '[]',
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                fingerprint  TEXT NOT NULL,
                changed      INTEGER NOT NULL DEFAULT 1,
                synced       INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_devices_changed
                ON devices (changed);

            CREATE INDEX IF NOT EXISTS idx_devices_synced
                ON devices (synced);

            CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                ON devices (last_seen);",
        )?;

        info!("device inventory database ready");
        Ok(Self { db })
    }

    /// Upsert a device. Returns `true` if the device is new or has changed
    /// fields since the last time it was recorded.
    pub fn upsert_device(&self, device: &DeviceRecord) -> anyhow::Result<bool> {
        let now = Utc::now().to_rfc3339();
        let protocols_json = serde_json::to_string(&device.protocols)?;
        let ports_json = serde_json::to_string(&device.ports)?;
        let mac_upper = device.mac.to_uppercase();

        // Check if a record already exists for this MAC
        let existing: Option<(String, Option<String>, String, String, String)> = self
            .db
            .query_row(
                "SELECT ip, hostname, protocols, ports, fingerprint FROM devices WHERE mac = ?1",
                params![mac_upper],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .ok();

        match existing {
            Some((old_ip, old_hostname, old_protocols, old_ports, old_fingerprint)) => {
                // Device exists -- check if anything changed
                let ip_changed = old_ip != device.ip;
                let hostname_changed = old_hostname != device.hostname;
                let protocols_changed = old_protocols != protocols_json;
                let ports_changed = old_ports != ports_json;
                let fingerprint_changed = old_fingerprint != device.fingerprint;

                let changed =
                    ip_changed || hostname_changed || protocols_changed || ports_changed || fingerprint_changed;

                if changed {
                    debug!(
                        mac = %mac_upper,
                        ip_changed, hostname_changed, protocols_changed, ports_changed,
                        "device changed, marking for re-sync"
                    );
                    self.db.execute(
                        "UPDATE devices SET
                            ip = ?1, vendor = ?2, hostname = ?3,
                            device_type = ?4, purdue_level = ?5,
                            protocols = ?6, ports = ?7,
                            last_seen = ?8, fingerprint = ?9,
                            changed = 1, synced = 0
                         WHERE mac = ?10",
                        params![
                            device.ip,
                            device.vendor,
                            device.hostname,
                            device.device_type,
                            device.purdue_level,
                            protocols_json,
                            ports_json,
                            now,
                            device.fingerprint,
                            mac_upper,
                        ],
                    )?;
                } else {
                    // Just bump last_seen
                    self.db.execute(
                        "UPDATE devices SET last_seen = ?1 WHERE mac = ?2",
                        params![now, mac_upper],
                    )?;
                }

                Ok(changed)
            }
            None => {
                // New device
                debug!(mac = %mac_upper, ip = %device.ip, vendor = %device.vendor, "new device discovered");
                self.db.execute(
                    "INSERT INTO devices (mac, ip, vendor, hostname, device_type, purdue_level,
                        protocols, ports, first_seen, last_seen, fingerprint, changed, synced)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, 0)",
                    params![
                        mac_upper,
                        device.ip,
                        device.vendor,
                        device.hostname,
                        device.device_type,
                        device.purdue_level,
                        protocols_json,
                        ports_json,
                        device.first_seen,
                        now,
                        device.fingerprint,
                    ],
                )?;
                Ok(true)
            }
        }
    }

    /// Get all devices that are new or changed and haven't been synced yet.
    pub fn get_unsynced(&self) -> anyhow::Result<Vec<DeviceRecord>> {
        let mut stmt = self.db.prepare(
            "SELECT mac, ip, vendor, hostname, device_type, purdue_level,
                    protocols, ports, first_seen, last_seen, fingerprint, changed, synced
             FROM devices
             WHERE changed = 1 AND synced = 0
             ORDER BY last_seen ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(RawRow {
                mac: row.get(0)?,
                ip: row.get(1)?,
                vendor: row.get(2)?,
                hostname: row.get(3)?,
                device_type: row.get(4)?,
                purdue_level: row.get(5)?,
                protocols: row.get(6)?,
                ports: row.get(7)?,
                first_seen: row.get(8)?,
                last_seen: row.get(9)?,
                fingerprint: row.get(10)?,
                changed: row.get(11)?,
                synced: row.get(12)?,
            })
        })?;

        let mut devices = Vec::new();
        for row in rows {
            match row {
                Ok(r) => match parse_raw_row(r) {
                    Ok(d) => devices.push(d),
                    Err(e) => error!(error = %e, "corrupt device record"),
                },
                Err(e) => error!(error = %e, "failed to read device row"),
            }
        }

        Ok(devices)
    }

    /// Mark a set of devices as synced (by their MAC addresses).
    pub fn mark_synced(&self, macs: &[String]) -> anyhow::Result<()> {
        let mut stmt = self
            .db
            .prepare("UPDATE devices SET synced = 1, changed = 0 WHERE mac = ?1")?;

        for mac in macs {
            stmt.execute(params![mac.to_uppercase()])?;
        }

        debug!(count = macs.len(), "devices marked as synced");
        Ok(())
    }

    /// Get all devices in the local inventory for status display.
    pub fn get_all(&self) -> anyhow::Result<Vec<DeviceRecord>> {
        let mut stmt = self.db.prepare(
            "SELECT mac, ip, vendor, hostname, device_type, purdue_level,
                    protocols, ports, first_seen, last_seen, fingerprint, changed, synced
             FROM devices
             ORDER BY last_seen DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(RawRow {
                mac: row.get(0)?,
                ip: row.get(1)?,
                vendor: row.get(2)?,
                hostname: row.get(3)?,
                device_type: row.get(4)?,
                purdue_level: row.get(5)?,
                protocols: row.get(6)?,
                ports: row.get(7)?,
                first_seen: row.get(8)?,
                last_seen: row.get(9)?,
                fingerprint: row.get(10)?,
                changed: row.get(11)?,
                synced: row.get(12)?,
            })
        })?;

        let mut devices = Vec::new();
        for row in rows {
            match row {
                Ok(r) => match parse_raw_row(r) {
                    Ok(d) => devices.push(d),
                    Err(e) => error!(error = %e, "corrupt device record in get_all"),
                },
                Err(e) => error!(error = %e, "failed to read device row"),
            }
        }

        Ok(devices)
    }

    /// Remove devices that haven't been seen in the specified number of hours.
    pub fn prune_stale(&self, older_than_hours: u64) -> anyhow::Result<usize> {
        let cutoff = (Utc::now() - chrono::Duration::hours(older_than_hours as i64)).to_rfc3339();
        let deleted = self.db.execute(
            "DELETE FROM devices WHERE last_seen < ?1",
            params![cutoff],
        )?;

        if deleted > 0 {
            info!(pruned = deleted, hours = older_than_hours, "pruned stale devices");
        }

        Ok(deleted)
    }

    /// Get summary statistics for display.
    pub fn stats(&self) -> anyhow::Result<DeviceStats> {
        let total: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let unsynced: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM devices WHERE changed = 1 AND synced = 0",
            [],
            |r| r.get(0),
        )?;
        let synced: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM devices WHERE synced = 1",
            [],
            |r| r.get(0),
        )?;

        Ok(DeviceStats {
            total: total as usize,
            unsynced: unsynced as usize,
            synced: synced as usize,
        })
    }
}

/// Extract device records from raw sensor findings.
///
/// Looks for findings that contain device-discovery data (typically from
/// cyprobe or cysense) and converts them into `DeviceRecord` entries.
pub fn extract_devices_from_findings(findings: &[crate::sensors::Finding]) -> Vec<DeviceRecord> {
    let mut devices = Vec::new();

    for finding in findings {
        // Only process findings that look like device discoveries
        let details = &finding.details;

        let mac = match details.get("mac").and_then(|v| v.as_str()) {
            Some(m) if !m.is_empty() => m.to_string(),
            _ => continue, // No MAC = not a device discovery
        };

        let ip = details
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let vendor = details
            .get("vendor")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let hostname = details
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let device_type = details
            .get("device_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let purdue_level = details
            .get("purdue_level")
            .and_then(|v| v.as_u64())
            .map(|n| n as u8);

        let protocols: Vec<String> = details
            .get("protocols")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let ports: Vec<u16> = details
            .get("ports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_default();

        devices.push(DeviceRecord::new(
            mac,
            ip,
            vendor,
            hostname,
            device_type,
            purdue_level,
            protocols,
            ports,
        ));
    }

    debug!(count = devices.len(), "extracted device records from findings");
    devices
}

// ── Internal helpers ────────────────────────────────────────────────────────

struct RawRow {
    mac: String,
    ip: String,
    vendor: String,
    hostname: Option<String>,
    device_type: String,
    purdue_level: Option<u8>,
    protocols: String,
    ports: String,
    first_seen: String,
    last_seen: String,
    fingerprint: String,
    changed: bool,
    synced: bool,
}

fn parse_raw_row(r: RawRow) -> anyhow::Result<DeviceRecord> {
    let protocols: Vec<String> = serde_json::from_str(&r.protocols)?;
    let ports: Vec<u16> = serde_json::from_str(&r.ports)?;

    Ok(DeviceRecord {
        mac: r.mac,
        ip: r.ip,
        vendor: r.vendor,
        hostname: r.hostname,
        device_type: r.device_type,
        purdue_level: r.purdue_level,
        protocols,
        ports,
        first_seen: r.first_seen,
        last_seen: r.last_seen,
        fingerprint: r.fingerprint,
        changed: r.changed,
        synced: r.synced,
    })
}

#[derive(Debug)]
pub struct DeviceStats {
    pub total: usize,
    pub unsynced: usize,
    pub synced: usize,
}
