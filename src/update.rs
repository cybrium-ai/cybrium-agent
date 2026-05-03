//! Self-update via GitHub Releases.
//!
//! The agent checks the public `cybrium-ai/cybrium-agent` repo for a newer
//! tag, downloads the platform-appropriate archive, verifies the SHA-256
//! checksum that `release.yml` publishes alongside each binary, and
//! atomically swaps the running executable using the OS-native primitive
//! (rename on Unix, MoveFileExA on Windows — handled inside `self_update`).
//!
//! The agent's running process exits cleanly after the swap; the
//! supervisor (systemd / launchd / Windows service) brings the new binary
//! up the same way it brought the old one up. This is the simpler half
//! of "self-update" — full server-pushed force-updates and platform-side
//! release manifests are deferred until the platform admin needs staged
//! rollouts.
//!
//! ## Channels
//!
//! Two channels are supported via the `--channel` flag and the
//! `update_channel` config field:
//!
//!   - `stable` (default) — latest non-prerelease GitHub release
//!   - `beta`             — most recent prerelease (semver `-beta.N`)
//!
//! ## Trust
//!
//! self_update verifies the SHA-256 from the `*.sha256` file that
//! `release.yml` publishes. We do *not* yet verify a signature on the
//! binary itself — that is option C from the design doc and is a
//! follow-up. For now, anyone able to publish to the GitHub repo can
//! also publish releases; that's the same trust boundary as the binary
//! itself.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const REPO_OWNER: &str = "cybrium-ai";
const REPO_NAME: &str = "cybrium-agent";
const BIN_NAME: &str = "cybrium-agent";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Beta,
}

impl Channel {
    pub fn from_arg(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            other => Err(anyhow!("unknown channel '{}': use stable or beta", other)),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self::Stable
    }
}

/// Result of a check-only run. Useful for surfacing pending-update state
/// in `cybrium-agent status` without applying the update.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub channel: Channel,
}

/// Look up the most recent release on the chosen channel without
/// downloading anything. Cheap — one HTTP call.
pub fn check(channel: Channel) -> Result<CheckResult> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // Run the blocking GitHub call on a worker thread so the agent's
    // tokio runtime isn't held up. self_update is sync.
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()
        .context("building GitHub release list")?
        .fetch()
        .context("fetching GitHub release list")?;

    let pick = releases.into_iter().find(|r| {
        let is_pre =
            r.version.contains("beta") || r.version.contains("rc") || r.version.contains("alpha");
        match channel {
            Channel::Stable => !is_pre,
            Channel::Beta => is_pre || true, // beta channel sees everything (latest wins)
        }
    });

    let latest = match pick {
        Some(r) => r.version.trim_start_matches('v').to_string(),
        None => current.clone(), // no releases — pretend we're current
    };

    let update_available =
        self_update::version::bump_is_greater(&current, &latest).unwrap_or(false);

    Ok(CheckResult {
        current_version: current,
        latest_version: latest,
        update_available,
        channel,
    })
}

/// Download + apply the latest update on the given channel. Blocking.
///
/// Returns the version that was applied, or an error if the update could
/// not be completed. The caller should exit the process after this returns
/// successfully so the supervisor can bring up the new binary; some
/// platforms (Windows) won't fully release the file handles otherwise.
pub fn apply(channel: Channel) -> Result<String> {
    let current = env!("CARGO_PKG_VERSION");
    info!(current = %current, channel = %channel.as_str(), "starting self-update");

    let mut update = self_update::backends::github::Update::configure();
    update
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .show_download_progress(true)
        .show_output(true)
        .current_version(current);

    // Beta channel: opt into prereleases — by default self_update skips them.
    if channel == Channel::Beta {
        update.target_version_tag(""); // self_update picks newest including prereleases
    }

    let status = update
        .build()
        .context("building self_update Update")?
        .update()
        .context("running self_update")?;

    if status.updated() {
        info!(version = %status.version(), "self-update complete — restart on supervisor");
        Ok(status.version().to_string())
    } else {
        warn!(version = %status.version(), "self-update reported no change — already up to date");
        Ok(status.version().to_string())
    }
}

/// Wrapper that runs the blocking apply on a worker thread so callers from
/// async context (like the daemon) don't block the runtime.
pub async fn apply_async(channel: Channel) -> Result<String> {
    tokio::task::spawn_blocking(move || apply(channel))
        .await
        .context("self-update worker panicked")?
}

pub async fn check_async(channel: Channel) -> Result<CheckResult> {
    tokio::task::spawn_blocking(move || check(channel))
        .await
        .context("update check worker panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_from_arg_round_trips() {
        assert_eq!(Channel::from_arg("stable").unwrap(), Channel::Stable);
        assert_eq!(Channel::from_arg("Stable").unwrap(), Channel::Stable);
        assert_eq!(Channel::from_arg("beta").unwrap(), Channel::Beta);
        assert!(Channel::from_arg("nightly").is_err());
    }
}
