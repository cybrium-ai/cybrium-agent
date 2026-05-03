use crate::config::Config;
use crate::hardware::generate_fingerprint;
use crate::hardware_rot::{detect as detect_rot, RootOfTrust};
use crate::sensors::SensorInfo;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize)]
struct HeartbeatRequest {
    license_key: String,
    hardware_id: String,
    sensors_active: Vec<String>,
    uptime_seconds: u64,
    buffer_size: usize,
    /// Stable tamper-signal hash. Backend records first-seen and alerts
    /// on change. Same model cydevice uses on the device-posture path.
    fingerprint: String,
    /// Hardware root-of-trust facts. Backend stores these alongside the
    /// fingerprint and surfaces them on the device dashboard.
    root_of_trust: RootOfTrust,
    /// Agent's running version — lets the platform know which fleet
    /// members are out of date for staged-rollout decisions.
    agent_version: String,
}

#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    /// If true, the server is revoking this agent.
    #[serde(default)]
    revoked: bool,
    /// Optional message from the server.
    message: Option<String>,
}

/// Send a heartbeat to the platform.
/// Returns Ok(true) if the agent should continue running,
/// Ok(false) if the server has revoked it.
pub async fn send_heartbeat(
    config: &Config,
    sensors: &[SensorInfo],
    uptime_seconds: u64,
    buffer_size: usize,
) -> anyhow::Result<bool> {
    let token = match &config.agent_token {
        Some(t) => t.clone(),
        None => {
            error!("cannot send heartbeat: agent not activated");
            return Ok(true); // Don't stop, just skip
        }
    };

    let active_sensors: Vec<String> = sensors
        .iter()
        .filter(|s| s.available)
        .map(|s| s.name.clone())
        .collect();

    let rot = detect_rot();
    let fingerprint = generate_fingerprint(&config.hardware_id, &rot);

    let body = HeartbeatRequest {
        license_key: config.license_key.clone(),
        hardware_id: config.hardware_id.clone(),
        sensors_active: active_sensors,
        uptime_seconds,
        buffer_size,
        fingerprint,
        root_of_trust: rot,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let url = format!("{}/api/agent/heartbeat/", config.platform_url);
    debug!(url = %url, uptime = uptime_seconds, "sending heartbeat");

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
            warn!(error = %e, "heartbeat failed (network error), will retry");
            return Ok(true);
        }
    };

    let status = resp.status();
    if !status.is_success() {
        warn!(status = %status, "heartbeat returned non-success status");
        return Ok(true);
    }

    let result: HeartbeatResponse = resp.json().await?;

    if result.revoked {
        let msg = result.message.unwrap_or_else(|| "no reason given".into());
        info!(reason = %msg, "agent has been revoked by the platform");
        return Ok(false);
    }

    debug!("heartbeat acknowledged");
    Ok(true)
}
