use crate::buffer;
use crate::config::Config;
use crate::dedup::{self, DeviceInventory};
use crate::sensors;
use crate::sync;
use crate::heartbeat;
use std::time::Instant;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Run the main agent daemon loop.
///
/// The daemon performs three recurring tasks:
/// 1. Run sensors at `scan_interval_secs` intervals and buffer findings locally.
/// 2. Sync buffered findings to the platform at `sync_interval_secs` intervals.
/// 3. Send heartbeats every 60 seconds.
///
/// Gracefully shuts down on SIGTERM or SIGINT.
pub async fn run_daemon(config: &mut Config) -> anyhow::Result<()> {
    info!("starting cybrium-agent daemon");

    // Open the local buffer database
    let conn = buffer::open()?;

    // Open the device inventory database
    let device_inventory = DeviceInventory::new(None)?;

    // Discover available sensors
    let available_sensors = sensors::discover_sensors(&config.sensors_enabled);
    let active_count = available_sensors.iter().filter(|s| s.available).count();

    if active_count == 0 {
        warn!("no sensors found in PATH — agent will run but collect no data");
        warn!("install at least one Cybrium sensor: cysense, cyguard, cyprobe, cyweb, cyscan, cymail");
    } else {
        info!(
            sensors = active_count,
            "discovered {} active sensor(s)",
            active_count
        );
        for s in &available_sensors {
            if s.available {
                info!(sensor = %s.name, version = %s.version, "  sensor ready");
            }
        }
    }

    let start = Instant::now();

    let mut scan_tick = interval(Duration::from_secs(config.scan_interval_secs));
    let mut sync_tick = interval(Duration::from_secs(config.sync_interval_secs));
    let mut heartbeat_tick = interval(Duration::from_secs(60));

    // Consume the first immediate tick for sync and heartbeat
    // (we want scan to fire immediately, but sync/heartbeat should wait)
    sync_tick.tick().await;
    heartbeat_tick.tick().await;

    info!(
        scan_interval = config.scan_interval_secs,
        sync_interval = config.sync_interval_secs,
        "daemon loop started — press Ctrl+C to stop"
    );

    loop {
        tokio::select! {
            _ = scan_tick.tick() => {
                info!("running sensor sweep");
                let findings = sensors::run_all_sensors(&available_sensors);
                if !findings.is_empty() {
                    // Buffer raw findings for sync
                    match buffer::insert_findings(&conn, &findings) {
                        Ok(n) => info!(buffered = n, "sensor findings buffered"),
                        Err(e) => error!(error = %e, "failed to buffer findings"),
                    }

                    // Extract device records and upsert into local inventory
                    let devices = dedup::extract_devices_from_findings(&findings);
                    if !devices.is_empty() {
                        let mut new_count = 0usize;
                        let mut changed_count = 0usize;
                        for device in &devices {
                            match device_inventory.upsert_device(device) {
                                Ok(true) => {
                                    new_count += 1;
                                }
                                Ok(false) => {
                                    // Unchanged, no action needed
                                }
                                Err(e) => error!(mac = %device.mac, error = %e, "failed to upsert device"),
                            }
                        }
                        if new_count > 0 {
                            info!(new_or_changed = new_count, total_discovered = devices.len(), "device inventory updated");
                        }
                    }
                } else {
                    info!("no findings from sensor sweep");
                }
            }

            _ = sync_tick.tick() => {
                // Sync raw findings
                match sync::sync_findings(config, &conn).await {
                    Ok(true) => info!("findings sync completed"),
                    Ok(false) => {} // Nothing to sync or transient error
                    Err(e) => error!(error = %e, "findings sync error"),
                }

                // Sync device inventory (only changed/new devices)
                match sync::sync_devices(config, &device_inventory).await {
                    Ok(true) => info!("device inventory sync completed"),
                    Ok(false) => {} // Nothing to sync
                    Err(e) => error!(error = %e, "device inventory sync error"),
                }
            }

            _ = heartbeat_tick.tick() => {
                let uptime = start.elapsed().as_secs();
                let buf_stats = buffer::stats(&conn).unwrap_or(buffer::BufferStats {
                    total: 0, unsynced: 0, synced: 0,
                });
                match heartbeat::send_heartbeat(
                    config,
                    &available_sensors,
                    uptime,
                    buf_stats.unsynced,
                ).await {
                    Ok(true) => {} // All good
                    Ok(false) => {
                        warn!("agent revoked by platform, shutting down");
                        break;
                    }
                    Err(e) => error!(error = %e, "heartbeat error"),
                }
            }

            _ = shutdown_signal() => {
                info!("shutdown signal received, stopping daemon");
                break;
            }
        }
    }

    info!("daemon stopped");
    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl+C).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
