use crate::buffer;
use crate::config::Config;
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
