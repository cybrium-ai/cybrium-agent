mod activation;
mod buffer;
mod config;
mod daemon;
mod hardware;
mod heartbeat;
mod sensors;
mod service;
mod sync;

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

    /// Print version information
    Version,
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
        Commands::Version => {
            cmd_version();
            Ok(())
        }
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
        anyhow::anyhow!(
            "agent not configured. Run `cybrium-agent activate --license <KEY>` first."
        )
    })?;

    if !cfg.is_activated() {
        anyhow::bail!(
            "agent not activated. Run `cybrium-agent activate --license <KEY>` first."
        );
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

    println!("Cybrium Agent Status");
    println!("--------------------");
    println!(
        "  Activated:    {}",
        if cfg.is_activated() { "yes" } else { "no" }
    );
    println!("  Hardware ID:  {}", cfg.hardware_id);
    println!("  Platform URL: {}", cfg.platform_url);
    println!(
        "  Sync interval: {}s",
        cfg.sync_interval_secs
    );
    println!(
        "  Scan interval: {}s",
        cfg.scan_interval_secs
    );

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
                    if running { "yes" } else { "no (stale PID file)" }
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
        println!("Stop is only supported on Unix systems. Kill process {} manually.", pid);
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
