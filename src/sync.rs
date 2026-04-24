use crate::buffer;
use crate::config::Config;
use crate::dedup::{DeviceInventory, DeviceRecord};
use crate::sensors::Finding;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize)]
struct SyncRequest {
    license_key: String,
    hardware_id: String,
    sensors: Vec<SensorPayload>,
}

#[derive(Debug, Serialize)]
struct SensorPayload {
    #[serde(rename = "type")]
    sensor_type: String,
    findings: Vec<Finding>,
}

#[derive(Debug, Deserialize)]
struct SyncResponse {
    /// The server may rotate the agent token on each sync.
    agent_token: Option<String>,
    accepted: Option<usize>,
}

/// Sync buffered findings to the platform.
/// Returns Ok(true) if sync succeeded, Ok(false) if there was nothing to sync.
pub async fn sync_findings(config: &mut Config, conn: &Connection) -> anyhow::Result<bool> {
    let unsynced = buffer::get_unsynced(conn)?;
    if unsynced.is_empty() {
        debug!("no unsynced findings to send");
        return Ok(false);
    }

    let token = match &config.agent_token {
        Some(t) => t.clone(),
        None => {
            error!("cannot sync: agent not activated (no token)");
            anyhow::bail!("agent not activated");
        }
    };

    // Group findings by sensor type
    let mut grouped: std::collections::HashMap<String, Vec<Finding>> =
        std::collections::HashMap::new();
    let mut rowids: Vec<i64> = Vec::new();

    for (rowid, finding) in &unsynced {
        grouped
            .entry(finding.sensor_type.clone())
            .or_default()
            .push(finding.clone());
        rowids.push(*rowid);
    }

    let sensors: Vec<SensorPayload> = grouped
        .into_iter()
        .map(|(sensor_type, findings)| SensorPayload {
            sensor_type,
            findings,
        })
        .collect();

    let body = SyncRequest {
        license_key: config.license_key.clone(),
        hardware_id: config.hardware_id.clone(),
        sensors,
    };

    let url = format!("{}/api/agent/sync/", config.platform_url);
    info!(count = rowids.len(), url = %url, "syncing findings to platform");

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Agent-Token", &token)
        .json(&body)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "network error during sync, findings remain buffered");
            return Ok(false);
        }
    };

    let status = resp.status();

    if status == reqwest::StatusCode::UNAUTHORIZED {
        warn!("received 401 — agent token may be revoked, attempting re-activation");
        // Re-activate
        crate::activation::activate(config).await?;
        return Ok(false);
    }

    if !status.is_success() {
        let error_body = resp.text().await.unwrap_or_default();
        error!(status = %status, body = %error_body, "sync failed");
        return Ok(false);
    }

    let result: SyncResponse = resp.json().await?;

    // Mark findings as synced
    buffer::mark_synced(conn, &rowids)?;

    // Rotate token if the server provided a new one
    if let Some(new_token) = result.agent_token {
        debug!("rotating agent token");
        config.agent_token = Some(new_token);
        config.save()?;
    }

    info!(
        accepted = result.accepted.unwrap_or(rowids.len()),
        "sync completed"
    );

    // Purge old synced findings
    buffer::purge_old_synced(conn)?;

    Ok(true)
}

// ── Device inventory sync ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct DeviceSyncRequest {
    license_key: String,
    hardware_id: String,
    devices: Vec<DeviceSyncPayload>,
}

#[derive(Debug, Serialize)]
struct DeviceSyncPayload {
    mac: String,
    ip: String,
    vendor: String,
    hostname: Option<String>,
    device_type: String,
    purdue_level: Option<u8>,
    protocols: Vec<String>,
    ports: Vec<u16>,
    first_seen: String,
    last_seen: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct DeviceSyncResponse {
    agent_token: Option<String>,
    created: Option<usize>,
    updated: Option<usize>,
    unchanged: Option<usize>,
}

/// Sync the device inventory to the platform feeder endpoint.
/// Only sends devices that are new or have changed since the last sync.
/// Returns Ok(true) if devices were synced, Ok(false) if nothing to sync.
pub async fn sync_devices(
    config: &mut Config,
    inventory: &DeviceInventory,
) -> anyhow::Result<bool> {
    let unsynced = inventory.get_unsynced()?;
    if unsynced.is_empty() {
        debug!("no unsynced devices to send");
        return Ok(false);
    }

    let token = match &config.agent_token {
        Some(t) => t.clone(),
        None => {
            error!("cannot sync devices: agent not activated (no token)");
            anyhow::bail!("agent not activated");
        }
    };

    let device_count = unsynced.len();
    let macs: Vec<String> = unsynced.iter().map(|d| d.mac.clone()).collect();

    let devices: Vec<DeviceSyncPayload> = unsynced
        .into_iter()
        .map(|d| DeviceSyncPayload {
            mac: d.mac,
            ip: d.ip,
            vendor: d.vendor,
            hostname: d.hostname,
            device_type: d.device_type,
            purdue_level: d.purdue_level,
            protocols: d.protocols,
            ports: d.ports,
            first_seen: d.first_seen,
            last_seen: d.last_seen,
            fingerprint: d.fingerprint,
        })
        .collect();

    let body = DeviceSyncRequest {
        license_key: config.license_key.clone(),
        hardware_id: config.hardware_id.clone(),
        devices,
    };

    let url = format!("{}/api/inventory/feed/", config.platform_url);
    info!(count = device_count, url = %url, "syncing device inventory to platform");

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Agent-Token", &token)
        .json(&body)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "network error during device sync, will retry next cycle");
            return Ok(false);
        }
    };

    let status = resp.status();

    if status == reqwest::StatusCode::UNAUTHORIZED {
        warn!("received 401 during device sync — re-activating");
        crate::activation::activate(config).await?;
        return Ok(false);
    }

    if !status.is_success() {
        let error_body = resp.text().await.unwrap_or_default();
        error!(status = %status, body = %error_body, "device sync failed");
        return Ok(false);
    }

    let result: DeviceSyncResponse = resp.json().await?;

    // Mark all synced devices
    inventory.mark_synced(&macs)?;

    // Rotate token if rotated
    if let Some(new_token) = result.agent_token {
        debug!("rotating agent token (from device sync)");
        config.agent_token = Some(new_token);
        config.save()?;
    }

    info!(
        created = result.created.unwrap_or(0),
        updated = result.updated.unwrap_or(0),
        unchanged = result.unchanged.unwrap_or(0),
        "device sync completed — {} new, {} updated, {} unchanged",
        result.created.unwrap_or(0),
        result.updated.unwrap_or(0),
        result.unchanged.unwrap_or(0),
    );

    // Prune devices not seen in 72 hours
    inventory.prune_stale(72)?;

    Ok(true)
}
