mod activation;
mod buffer;
mod config;
mod daemon;
mod dedup;
mod hardware;
mod hardware_rot;
mod heartbeat;
mod sensors;
mod service;
mod sync;
mod telemetry;
mod update;

use clap::{Parser, Subcommand};
use config::Config;
use tracing::error;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "cybrium-agent",
    about = "Cybrium on-premise security agent",
    version = VERSION,
    author = "Cybrium AI <eng@cybrium.ai>"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Activate the agent with a license key
    Activate {
        /// JWT license key from the Cybrium platform
        #[arg(long)]
        license: String,

        /// Platform API URL (default: https://api.cybrium.ai)
        #[arg(long, default_value = "https://api.cybrium.ai")]
        platform_url: String,
    },

    /// Start the agent daemon (run sensors + sync loop)
    Start,

    /// Show agent status (license, sensors, last sync)
    Status,

    /// Stop the running agent daemon
    Stop,

    /// Install as a system service (systemd on Linux, launchd on macOS)
    InstallService,

    /// Remove the system service
    UninstallService,

    /// Check for / apply a new release. By default downloads & applies
    /// the latest stable release. Pass `--check` to only report whether
    /// an update is available.
    Update {
        /// Only check; don't download or apply.
        #[arg(long)]
        check: bool,
        /// Release channel: stable (default) or beta.
        #[arg(long, default_value = "stable")]
        channel: String,
    },

    /// Print version information
    Version,

    /// Clear the agent's activation state (license + tokens). The next
    /// `activate` will start fresh.
    Deactivate,

    /// Read or write a single config field.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage the hardened telemetry channel. See `cybrium-agent telemetry
    /// --help`.
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print a config key's current value.
    Get {
        /// Key name, e.g. sync_interval_secs, scan_interval_secs,
        /// platform_url, sensors_enabled.
        key: String,
    },
    /// Set a config key. Type is inferred from the field — integers for
    /// intervals, comma-separated list for sensors_enabled, string for url.
    Set {
        key: String,
        value: String,
    },
    /// Print the whole config (with secrets redacted).
    Show,
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Activate a hardened telemetry token (cyat_<slug>_<secret>). Verifies
    /// the token via a handshake before persisting state.
    Activate {
        /// Token issued by the platform UI (Settings → Agents → Telemetry).
        token: String,
    },
    /// Clear the telemetry token without affecting the license/agent_token.
    Deactivate,
}

#[tokio::main]
async fn main() {
    // Initialize tracing with RUST_LOG env filter (default: info)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cybrium_agent=info".parse().unwrap()),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Activate {
            license,
            platform_url,
        } => cmd_activate(license, platform_url).await,
        Commands::Start => cmd_start().await,
        Commands::Status => cmd_status(),
        Commands::Stop => cmd_stop(),
        Commands::InstallService => service::install_service(),
        Commands::UninstallService => service::uninstall_service(),
        Commands::Update { check, channel } => cmd_update(check, channel).await,
        Commands::Version => {
            cmd_version();
            Ok(())
        }
        Commands::Deactivate => cmd_deactivate(),
        Commands::Config { action } => cmd_config(action),
        Commands::Telemetry { action } => match action {
            TelemetryAction::Activate { token } => telemetry::activate(token).await,
            TelemetryAction::Deactivate => telemetry::deactivate(),
        },
    };

    if let Err(e) = result {
        error!(error = %e, "command failed");
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_activate(license: String, platform_url: String) -> anyhow::Result<()> {
    let hw_id = hardware::generate_hardware_id();

    let mut cfg = Config::load().unwrap_or_default();
    cfg.license_key = license;
    cfg.hardware_id = hw_id.clone();
    cfg.platform_url = platform_url;
    cfg.save()?;

    println!("Hardware ID: {}", hw_id);
    println!("Activating with platform...");

    activation::activate(&mut cfg).await?;

    Ok(())
}

async fn cmd_start() -> anyhow::Result<()> {
    let mut cfg = Config::load().ok_or_else(|| {
        anyhow::anyhow!("agent not configured. Run `cybrium-agent activate --license <KEY>` first.")
    })?;

    if !cfg.is_activated() {
        anyhow::bail!("agent not activated. Run `cybrium-agent activate --license <KEY>` first.");
    }

    // Write PID file for stop command
    let pid_path = Config::base_dir().join("agent.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let result = daemon::run_daemon(&mut cfg).await;

    // Clean up PID file on exit
    let _ = std::fs::remove_file(&pid_path);

    result
}

fn cmd_status() -> anyhow::Result<()> {
    let cfg = match Config::load() {
        Some(c) => c,
        None => {
            println!("Agent status: NOT CONFIGURED");
            println!("Run `cybrium-agent activate --license <KEY>` to get started.");
            return Ok(());
        }
    };

    // Detect hardware root of trust each time so we surface the *current*
    // state, not whatever was cached on activation.
    let rot = hardware_rot::detect();
    let fingerprint = hardware::generate_fingerprint(&cfg.hardware_id, &rot);

    println!("Cybrium Agent Status");
    println!("--------------------");
    println!(
        "  Activated:    {}",
        if cfg.is_activated() { "yes" } else { "no" }
    );
    println!("  Hardware ID:  {}", cfg.hardware_id);
    println!(
        "  Fingerprint:  {}…  ({})",
        &fingerprint[..16],
        fingerprint.len()
    );
    println!(
        "  Root of trust: {}{}{}",
        rot.kind.as_str(),
        if rot.vendor.is_empty() {
            String::new()
        } else {
            format!(" · {}", rot.vendor)
        },
        if rot.present {
            " · present"
        } else {
            " · absent"
        },
    );
    println!("  Platform URL: {}", cfg.platform_url);
    println!("  Sync interval: {}s", cfg.sync_interval_secs);
    println!("  Scan interval: {}s", cfg.scan_interval_secs);

    if let Some(at) = &cfg.activated_at {
        println!("  Activated at: {}", at);
    }

    // Check PID file for running status
    let pid_path = Config::base_dir().join("agent.pid");
    if pid_path.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            println!("  Daemon PID:   {}", pid_str.trim());
            // Check if process is actually running
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let running = is_process_running(pid);
                println!(
                    "  Running:      {}",
                    if running {
                        "yes"
                    } else {
                        "no (stale PID file)"
                    }
                );
            }
        }
    } else {
        println!("  Running:      no");
    }

    // Show sensor availability
    println!();
    println!("Sensors:");
    let sensors = sensors::discover_sensors(&cfg.sensors_enabled);
    for s in &sensors {
        let status = if s.available {
            format!("available ({})", s.version)
        } else {
            "not found".to_string()
        };
        println!("  {:<10} {}", s.name, status);
    }

    // Show buffer stats
    if let Ok(conn) = buffer::open() {
        if let Ok(stats) = buffer::stats(&conn) {
            println!();
            println!("Buffer:");
            println!("  Total:    {}", stats.total);
            println!("  Unsynced: {}", stats.unsynced);
            println!("  Synced:   {}", stats.synced);
        }
    }

    // Show device inventory stats
    if let Ok(inv) = dedup::DeviceInventory::new(None) {
        if let Ok(stats) = inv.stats() {
            println!();
            println!("Device Inventory:");
            println!("  Total:    {}", stats.total);
            println!("  Unsynced: {}", stats.unsynced);
            println!("  Synced:   {}", stats.synced);
        }
    }

    Ok(())
}

fn cmd_stop() -> anyhow::Result<()> {
    let pid_path = Config::base_dir().join("agent.pid");
    if !pid_path.exists() {
        println!("No running agent found (no PID file).");
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_path)?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid PID in file"))?;

    if !is_process_running(pid) {
        println!("Agent process {} is not running (stale PID file).", pid);
        std::fs::remove_file(&pid_path)?;
        return Ok(());
    }

    println!("Sending SIGTERM to agent process {}...", pid);

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    #[cfg(not(unix))]
    {
        println!(
            "Stop is only supported on Unix systems. Kill process {} manually.",
            pid
        );
    }

    // Wait briefly then check
    std::thread::sleep(std::time::Duration::from_secs(2));
    if is_process_running(pid) {
        println!("Agent still running. It may take a moment to shut down.");
    } else {
        println!("Agent stopped.");
        let _ = std::fs::remove_file(&pid_path);
    }

    Ok(())
}

fn cmd_version() {
    println!("cybrium-agent {}", VERSION);
    println!("Cybrium AI — on-premise security agent");
    println!("https://cybrium.ai");
}

async fn cmd_update(check_only: bool, channel_arg: String) -> anyhow::Result<()> {
    let channel = update::Channel::from_arg(&channel_arg)?;

    if check_only {
        let res = update::check_async(channel).await?;
        if res.update_available {
            println!(
                "Update available: {} → {} (channel: {})",
                res.current_version,
                res.latest_version,
                channel.as_str()
            );
        } else {
            println!(
                "Up to date: cybrium-agent {} (channel: {})",
                res.current_version,
                channel.as_str()
            );
        }
        return Ok(());
    }

    println!("cybrium-agent self-update — channel: {}", channel.as_str());
    let new_version = update::apply_async(channel).await?;
    println!("Self-update complete. Now running version: {}", new_version);
    println!();
    println!("If the agent is running under systemd / launchd / a Windows service,");
    println!("the supervisor will restart the new binary automatically. If you");
    println!("started it manually with `cybrium-agent start`, restart it.");
    Ok(())
}

/// v0.2.0 — wipe activation state.
fn cmd_deactivate() -> anyhow::Result<()> {
    let Some(mut cfg) = Config::load() else {
        anyhow::bail!("no config file at {} — nothing to deactivate", Config::file_path().display());
    };
    cfg.license_key = String::new();
    cfg.agent_token = None;
    cfg.activated_at = None;
    cfg.telemetry_token = None;
    cfg.telemetry_tenant_slug = None;
    cfg.save()?;
    println!("Agent deactivated. License, agent token, and telemetry token cleared.");
    println!("Run `cybrium-agent activate --license <jwt>` to re-enroll.");
    Ok(())
}

/// v0.2.0 — get/set a single config field, or show the whole config.
fn cmd_config(action: ConfigAction) -> anyhow::Result<()> {
    let mut cfg = Config::load().unwrap_or_default();
    match action {
        ConfigAction::Get { key } => {
            let value = match key.as_str() {
                "sync_interval_secs" => cfg.sync_interval_secs.to_string(),
                "scan_interval_secs" => cfg.scan_interval_secs.to_string(),
                "platform_url" => cfg.platform_url.clone(),
                "sensors_enabled" => cfg.sensors_enabled.join(","),
                "telemetry_tenant_slug" => cfg.telemetry_tenant_slug.clone().unwrap_or_default(),
                other => anyhow::bail!(
                    "unknown key `{}` — supported: sync_interval_secs, scan_interval_secs, platform_url, sensors_enabled, telemetry_tenant_slug",
                    other
                ),
            };
            println!("{}", value);
        }
        ConfigAction::Set { key, value } => {
            match key.as_str() {
                "sync_interval_secs" => {
                    cfg.sync_interval_secs = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("sync_interval_secs must be a positive integer"))?;
                }
                "scan_interval_secs" => {
                    cfg.scan_interval_secs = value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("scan_interval_secs must be a positive integer"))?;
                }
                "platform_url" => {
                    // Allow override for the legacy /api channel only —
                    // the telemetry endpoint base is hardcoded for security
                    // (see config::TELEMETRY_BASE_DOMAIN).
                    if !(value.starts_with("http://") || value.starts_with("https://")) {
                        anyhow::bail!("platform_url must start with http:// or https://");
                    }
                    cfg.platform_url = value;
                }
                "sensors_enabled" => {
                    cfg.sensors_enabled = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "telemetry_token" | "license_key" | "agent_token" | "telemetry_tenant_slug" => {
                    anyhow::bail!(
                        "`{}` is set via `activate` / `telemetry activate` / `deactivate` — not via `config set`",
                        key
                    );
                }
                other => anyhow::bail!("unknown key `{}`", other),
            }
            cfg.save()?;
            println!("Saved.");
        }
        ConfigAction::Show => {
            // Print with secrets redacted.
            let mut redacted = cfg.clone();
            if !redacted.license_key.is_empty() {
                redacted.license_key = format!("<JWT, {} chars>", redacted.license_key.len());
            }
            if let Some(t) = &redacted.agent_token {
                redacted.agent_token = Some(format!("<{} chars>", t.len()));
            }
            if let Some(t) = &redacted.telemetry_token {
                // Show only the prefix portion (cyat_<slug>) which is visible
                // by design — secret portion redacted.
                let prefix_end = t.rfind('_').unwrap_or(t.len());
                redacted.telemetry_token = Some(format!("{}_<redacted>", &t[..prefix_end]));
            }
            println!("{}", serde_json::to_string_pretty(&redacted)?);
        }
    }
    Ok(())
}

/// Check if a process with the given PID is running.
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if process exists without sending a signal
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}
