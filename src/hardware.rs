use sha2::{Digest, Sha256};
use sysinfo::System;
use tracing::debug;

/// Generate a deterministic hardware fingerprint.
/// SHA256(mac_address + cpu_brand + host_name)
///
/// We use sysinfo for cross-platform support. The fingerprint combines
/// the first non-loopback MAC address, CPU brand string, and hostname
/// to produce a stable identifier for this machine.
pub fn generate_hardware_id() -> String {
    let mac = get_mac_address();
    let cpu = get_cpu_info();
    let host = get_hostname();

    debug!(mac = %mac, cpu = %cpu, host = %host, "collecting hardware fingerprint components");

    let mut hasher = Sha256::new();
    hasher.update(mac.as_bytes());
    hasher.update(b"|");
    hasher.update(cpu.as_bytes());
    hasher.update(b"|");
    hasher.update(host.as_bytes());

    hex::encode(hasher.finalize())
}

/// Get the first non-loopback MAC address.
/// Falls back to reading /sys/class/net on Linux or ifconfig on macOS.
fn get_mac_address() -> String {
    // Try reading from /sys/class/net (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" {
                    continue;
                }
                let addr_path = entry.path().join("address");
                if let Ok(mac) = std::fs::read_to_string(addr_path) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }
    }

    // macOS: parse ifconfig output
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ifconfig").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("ether ") {
                    let mac = trimmed.trim_start_matches("ether ").trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return mac;
                    }
                }
            }
        }
    }

    // Fallback: use hostname as a substitute
    "unknown-mac".to_string()
}

/// Get the CPU brand string from sysinfo.
fn get_cpu_info() -> String {
    let sys = System::new_all();
    sys.cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "unknown-cpu".to_string())
}

/// Get the machine hostname.
fn get_hostname() -> String {
    System::host_name().unwrap_or_else(|| "unknown-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_id_is_deterministic() {
        let id1 = generate_hardware_id();
        let id2 = generate_hardware_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA256 hex = 64 chars
    }
}
