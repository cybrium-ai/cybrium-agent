use crate::config::Config;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Debug, Serialize)]
struct ActivateRequest {
    license_key: String,
    hardware_id: String,
}

#[derive(Debug, Deserialize)]
struct ActivateResponse {
    agent_token: String,
    tenant_schema: String,
    sync_endpoint: String,
}

/// Activate the agent with the platform.
/// Sends the license key and hardware ID, receives an agent token.
pub async fn activate(config: &mut Config) -> anyhow::Result<()> {
    let url = format!("{}/api/agent/activate/", config.platform_url);

    let body = ActivateRequest {
        license_key: config.license_key.clone(),
        hardware_id: config.hardware_id.clone(),
    };

    info!("activating agent with platform at {}", url);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let error_body = resp.text().await.unwrap_or_default();
        error!(status = %status, body = %error_body, "activation failed");
        anyhow::bail!("activation failed: HTTP {} — {}", status, error_body);
    }

    let result: ActivateResponse = resp.json().await?;

    config.agent_token = Some(result.agent_token);
    config.activated_at = Some(Utc::now());
    config.save()?;

    info!(
        tenant = %result.tenant_schema,
        sync_endpoint = %result.sync_endpoint,
        "agent activated successfully"
    );

    println!("Agent activated successfully.");
    println!("  Tenant:        {}", result.tenant_schema);
    println!("  Sync endpoint: {}", result.sync_endpoint);
    println!("  Activated at:  {}", config.activated_at.unwrap());

    // Decode JWT header to show expiry (best-effort, don't fail on decode errors)
    if let Some(expiry) = decode_jwt_expiry(&config.license_key) {
        println!("  License expiry: {}", expiry);
    }

    Ok(())
}

/// Best-effort decode of the JWT payload to extract the `exp` claim.
/// We do NOT verify the signature — the server handles that.
fn decode_jwt_expiry(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // JWT payload is the second part, base64url-encoded
    let payload = parts[1];
    // Add padding if needed
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let decoded = padded
        .replace('-', "+")
        .replace('_', "/");

    use std::io::Read;
    let mut decoder = base64_decode(&decoded)?;
    let mut json_str = String::new();
    decoder.read_to_string(&mut json_str).ok()?;

    let value: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    let exp = value.get("exp")?.as_i64()?;

    let dt = chrono::DateTime::from_timestamp(exp, 0)?;
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Simple base64 decoder (standard alphabet).
fn base64_decode(input: &str) -> Option<std::io::Cursor<Vec<u8>>> {
    static TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut buf = Vec::new();
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();

    let mut i = 0;
    while i < bytes.len() {
        let lookup = |b: u8| -> Option<u8> {
            TABLE.iter().position(|&c| c == b).map(|p| p as u8)
        };

        let b0 = lookup(bytes[i])?;
        let b1 = if i + 1 < bytes.len() { lookup(bytes[i + 1])? } else { 0 };
        let b2 = if i + 2 < bytes.len() { lookup(bytes[i + 2])? } else { 0 };
        let b3 = if i + 3 < bytes.len() { lookup(bytes[i + 3])? } else { 0 };

        buf.push((b0 << 2) | (b1 >> 4));
        if i + 2 < bytes.len() {
            buf.push((b1 << 4) | (b2 >> 2));
        }
        if i + 3 < bytes.len() {
            buf.push((b2 << 6) | b3);
        }

        i += 4;
    }

    Some(std::io::Cursor::new(buf))
}
