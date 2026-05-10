//! v0.3.0 — hardened telemetry token + endpoint.
//!
//! Three security properties (matches the backend's three guarantees):
//!
//!   1. NO CROSS-TENANT: token has the tenant slug as a visible prefix.
//!      Endpoint URL has the slug as a subdomain. Server compares both
//!      sides at every ingest call.
//!
//!   2. PER-TENANT GENERATION: tokens are issued by the platform admin
//!      under tenant context. The agent never invents one.
//!
//!   3. TYPOSQUAT PROTECTION:
//!      - Base domain is hardcoded (see config::TELEMETRY_BASE_DOMAIN) so
//!        operator cannot redirect to look-alike domains via config.
//!      - On `telemetry activate <token>`, we parse the slug out of the
//!        token, compute the canonical endpoint, hit `/handshake`, and
//!        REFUSE to save state unless the server confirms the token
//!        belongs to the named tenant.

use crate::config::{Config, TELEMETRY_BASE_DOMAIN};
use anyhow::{anyhow, Context, Result};

const TOKEN_PREFIX: &str = "cyat";

/// Parse + validate token format. Returns the tenant slug.
pub fn parse_token(token: &str) -> Result<&str> {
    let mut parts = token.splitn(3, '_');
    let prefix = parts.next().ok_or_else(|| anyhow!("empty token"))?;
    if prefix != TOKEN_PREFIX {
        return Err(anyhow!(
            "token must start with `{}_<tenant-slug>_<secret>` — got prefix `{}`",
            TOKEN_PREFIX, prefix
        ));
    }
    let slug = parts
        .next()
        .ok_or_else(|| anyhow!("token missing tenant-slug segment"))?;
    let _secret = parts
        .next()
        .ok_or_else(|| anyhow!("token missing secret segment"))?;

    if slug.is_empty() {
        return Err(anyhow!("token tenant-slug is empty"));
    }
    if !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(anyhow!(
            "token tenant-slug `{}` has invalid characters (only a-z 0-9 - allowed)",
            slug
        ));
    }
    Ok(slug)
}

/// Compute the canonical ingest endpoint. Base domain is hardcoded.
pub fn ingest_url(slug: &str) -> String {
    format!("https://{}.{}/v1/ingest", slug, TELEMETRY_BASE_DOMAIN)
}

pub fn handshake_url(slug: &str) -> String {
    format!("https://{}.{}/v1/handshake", slug, TELEMETRY_BASE_DOMAIN)
}

/// Activate a telemetry token. Verifies via handshake BEFORE persisting.
pub async fn activate(token: String) -> Result<()> {
    let slug_owned = parse_token(&token)?.to_string();
    let endpoint = handshake_url(&slug_owned);
    println!("Verifying token with platform: {}", endpoint);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("build http client")?;

    let resp = client
        .get(&endpoint)
        .bearer_auth(&token)
        .send()
        .await
        .with_context(|| format!("handshake request to {} failed", endpoint))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!(
            "platform rejected token (HTTP {}): {}\n\nCommon causes:\n  - You typed the wrong tenant — the token says it's for `{}`. Verify on the platform admin → Agents → Telemetry Tokens.\n  - The token was revoked or expired.\n  - You're behind a corporate proxy that rewrote the TLS cert.",
            status, body, slug_owned
        ));
    }

    let payload: serde_json::Value =
        serde_json::from_str(&body).context("handshake returned non-JSON")?;
    let server_slug = payload
        .get("tenant")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("handshake response missing `tenant` field"))?;
    if server_slug != slug_owned {
        return Err(anyhow!(
            "handshake mismatch: token claims tenant `{}` but server returned `{}` — refusing to activate",
            slug_owned, server_slug
        ));
    }

    let mut cfg = Config::load().unwrap_or_default();
    cfg.telemetry_token = Some(token);
    cfg.telemetry_tenant_slug = Some(slug_owned.clone());
    cfg.save()?;

    println!("Telemetry activated for tenant `{}`", slug_owned);
    println!("Endpoint: {}", ingest_url(&slug_owned));
    println!(
        "Fingerprint: {}",
        payload.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("?")
    );
    Ok(())
}

/// Clear the telemetry token from config (keeps other fields).
pub fn deactivate() -> Result<()> {
    let mut cfg = Config::load().context("no config to deactivate")?;
    if cfg.telemetry_token.is_none() {
        return Err(anyhow!("no telemetry token is active"));
    }
    cfg.telemetry_token = None;
    cfg.telemetry_tenant_slug = None;
    cfg.save()?;
    println!("Telemetry token cleared.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        assert_eq!(parse_token("cyat_demo_xyz123").unwrap(), "demo");
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        assert!(parse_token("badge_demo_xyz").is_err());
        assert!(parse_token("cyat-demo-xyz").is_err());
    }

    #[test]
    fn parse_rejects_empty_slug() {
        assert!(parse_token("cyat__xyz").is_err());
    }

    #[test]
    fn parse_rejects_slug_with_bad_chars() {
        assert!(parse_token("cyat_evil tenant_xyz").is_err());
        assert!(parse_token("cyat_evil/../_xyz").is_err());
        assert!(parse_token("cyat_x.y.z_xyz").is_err());
    }

    #[test]
    fn endpoints_use_hardcoded_base() {
        assert_eq!(
            ingest_url("demo"),
            "https://demo.telemetry.cybrium.ai/v1/ingest"
        );
        assert_eq!(
            handshake_url("aep"),
            "https://aep.telemetry.cybrium.ai/v1/handshake"
        );
    }
}
