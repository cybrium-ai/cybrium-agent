use std::fs;
use std::path::Path;
use tracing::info;

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = r#"[Unit]
Description=Cybrium Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cybrium-agent start
Restart=always
RestartSec=10
User=root
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
"#;

#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.cybrium.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/cybrium-agent</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/cybrium-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/cybrium-agent.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
"#;

/// Install the agent as a system service.
pub fn install_service() -> anyhow::Result<()> {
    // First, check the agent binary is at /usr/local/bin
    let binary = std::env::current_exe()?;
    let target = Path::new("/usr/local/bin/cybrium-agent");
    if binary != target {
        println!(
            "Note: the agent binary should be at {}.",
            target.display()
        );
        println!("  Copy it with: sudo cp {} {}", binary.display(), target.display());
    }

    #[cfg(target_os = "linux")]
    {
        install_systemd()?;
    }

    #[cfg(target_os = "macos")]
    {
        install_launchd()?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("service installation not supported on this OS");
    }

    Ok(())
}

/// Remove the agent system service.
pub fn uninstall_service() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        uninstall_systemd()?;
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_launchd()?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("service removal not supported on this OS");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd() -> anyhow::Result<()> {
    let path = Path::new("/etc/systemd/system/cybrium-agent.service");
    fs::write(path, SYSTEMD_UNIT)?;
    info!(path = %path.display(), "wrote systemd unit file");

    println!("Systemd service installed.");
    println!("  Enable and start:");
    println!("    sudo systemctl daemon-reload");
    println!("    sudo systemctl enable cybrium-agent");
    println!("    sudo systemctl start cybrium-agent");
    println!();
    println!("  Check status:");
    println!("    sudo systemctl status cybrium-agent");
    println!("    journalctl -u cybrium-agent -f");

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let path = Path::new("/etc/systemd/system/cybrium-agent.service");
    if path.exists() {
        println!("Stopping and disabling service...");
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "cybrium-agent"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "cybrium-agent"])
            .status();
        fs::remove_file(path)?;
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
        println!("Systemd service removed.");
    } else {
        println!("Service file not found, nothing to remove.");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd() -> anyhow::Result<()> {
    let path = Path::new("/Library/LaunchDaemons/ai.cybrium.agent.plist");
    fs::write(path, LAUNCHD_PLIST)?;
    info!(path = %path.display(), "wrote launchd plist");

    println!("LaunchDaemon installed.");
    println!("  Load the service:");
    println!("    sudo launchctl load {}", path.display());
    println!();
    println!("  Check status:");
    println!("    sudo launchctl list | grep cybrium");
    println!("    tail -f /var/log/cybrium-agent.log");

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> anyhow::Result<()> {
    let path = Path::new("/Library/LaunchDaemons/ai.cybrium.agent.plist");
    if path.exists() {
        println!("Unloading and removing service...");
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &path.to_string_lossy()])
            .status();
        fs::remove_file(path)?;
        println!("LaunchDaemon removed.");
    } else {
        println!("Plist file not found, nothing to remove.");
    }
    Ok(())
}
