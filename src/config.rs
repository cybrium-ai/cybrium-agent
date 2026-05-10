use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// HARDCODED — the only domain the agent will ever send telemetry to.
///
/// This is deliberately NOT configurable. If we let operators override it via
/// config.json or `--platform-url`, an attacker who tricks the operator into
/// typing a typosquat (e.g. `cybriurn.ai` with rn-for-m) can siphon telemetry.
/// Pinning the base domain in the binary forces any malicious redirect to
/// require modifying the binary itself, which is a much higher bar.
///
/// Build variants for staging/dev live in separate binaries with a different
/// constant — never via runtime config.
pub const TELEMETRY_BASE_DOMAIN: &str = "telemetry.cybrium.ai";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub license_key: String,
    pub agent_token: Option<String>,
    pub hardware_id: String,
    pub platform_url: String,
    pub sync_interval_secs: u64,
    pub scan_interval_secs: u64,
    pub sensors_enabled: Vec<String>,
    pub activated_at: Option<DateTime<Utc>>,

    /// v0.2.0 — hardened telemetry token. Separate from `agent_token`
    /// (which is the legacy general-purpose token); this one is bound to
    /// a specific tenant via its embedded slug and is only ever sent to
    /// `<slug>.{TELEMETRY_BASE_DOMAIN}/v1/ingest`.
    #[serde(default)]
    pub telemetry_token: Option<String>,
    /// Cached tenant slug extracted from the telemetry token at activation
    /// time. Used to compute the endpoint without re-parsing on every send.
    #[serde(default)]
    pub telemetry_tenant_slug: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            license_key: String::new(),
            agent_token: None,
            hardware_id: String::new(),
            platform_url: "https://api.cybrium.ai".to_string(),
            sync_interval_secs: 60,
            scan_interval_secs: 300,
            sensors_enabled: vec![
                "cysense".into(),
                "cyguard".into(),
                "cyprobe".into(),
                "cyweb".into(),
                "cyscan".into(),
                "cymail".into(),
            ],
            activated_at: None,
            telemetry_token: None,
            telemetry_tenant_slug: None,
        }
    }
}

impl Config {
    /// Returns the base directory: ~/.cybrium-agent/
    pub fn base_dir() -> PathBuf {
        dirs::home_dir()
            .expect("cannot determine home directory")
            .join(".cybrium-agent")
    }

    /// Returns the config file path: ~/.cybrium-agent/config.json
    pub fn file_path() -> PathBuf {
        Self::base_dir().join("config.json")
    }

    /// Load config from disk. Returns None if the file does not exist.
    pub fn load() -> Option<Self> {
        let path = Self::file_path();
        if !path.exists() {
            return None;
        }
        let data = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Save config to disk. Creates the directory and sets file mode 600.
    pub fn save(&self) -> anyhow::Result<()> {
        let dir = Self::base_dir();
        fs::create_dir_all(&dir)?;
        let path = Self::file_path();
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&path, &data)?;

        // Set file permissions to 600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Returns true if the agent has been activated (has a token).
    pub fn is_activated(&self) -> bool {
        self.agent_token.is_some() && self.activated_at.is_some()
    }
}
