use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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
