use crate::hardware_rot::RootOfTrust;
use sha2::{Digest, Sha256};
use sysinfo::System;
use tracing::debug;

/// Compute a tamper-signal fingerprint for this host.
///
/// SHA256 over `(hardware_id | rot.kind | rot.vendor | rot.present)`.
/// Distinct from `hardware_id` itself so that adopting the fingerprint
/// does not invalidate existing activations: the agent continues to send
/// the same `hardware_id` it has always sent, plus the new fingerprint
/// as an additional field.
///
/// Stable across reboots; changes only on hardware swap, OS reinstall,
/// or firmware tampering — same trigger conditions cydevice uses.
pub fn generate_fingerprint(hardware_id: &str, rot: &RootOfTrust) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hardware_id.as_bytes());
    hasher.update(b"|");
    hasher.update(rot.kind.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(rot.vendor.as_bytes());
    hasher.update(b"|");
    hasher.update(if rot.present { b"1" } else { b"0" });
    hex::encode(hasher.finalize())
}

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
    use crate::hardware_rot::{RootOfTrust, RootOfTrustKind};

    #[test]
    fn hardware_id_is_deterministic() {
        let id1 = generate_hardware_id();
        let id2 = generate_hardware_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn fingerprint_is_deterministic_and_hex() {
        let rot = RootOfTrust {
            kind: RootOfTrustKind::Tpm20,
            vendor: "INTC".to_string(),
            present: true,
        };
        let f1 = generate_fingerprint("abc", &rot);
        let f2 = generate_fingerprint("abc", &rot);
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64);
        assert!(f1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_changes_on_rot_difference() {
        let rot_a = RootOfTrust {
            kind: RootOfTrustKind::Tpm20,
            vendor: "INTC".into(),
            present: true,
        };
        let rot_b = RootOfTrust {
            kind: RootOfTrustKind::Tpm20,
            vendor: "STM ".into(),
            present: true,
        };
        let rot_c = RootOfTrust {
            kind: RootOfTrustKind::None,
            vendor: "".into(),
            present: false,
        };
        let f_a = generate_fingerprint("xyz", &rot_a);
        let f_b = generate_fingerprint("xyz", &rot_b);
        let f_c = generate_fingerprint("xyz", &rot_c);
        assert_ne!(f_a, f_b);
        assert_ne!(f_a, f_c);
    }
}
