//! Hardware Root-of-Trust detection.
//!
//! Reports the presence + manufacturer of a TPM (Linux/Windows) or Apple
//! Secure Enclave (macOS). This is *detection only* — we don't drive the
//! TPM, generate AIKs, or sign payloads. The output feeds the agent's
//! `fingerprint` field so the platform can:
//!
//!   1. Surface the ROT status in its device dashboard.
//!   2. Detect tampering — a stable host should not see its TPM vendor
//!      flip between check-ins. A change is a high-severity signal.
//!
//! Cryptographic attestation (signing every payload with a TPM-bound key)
//! is intentionally out of scope here — that's a separate engineering
//! investment requiring `tss-esapi` (Linux), TBS API (Windows), and IOKit
//! (macOS) integration.

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Family of hardware root of trust detected on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootOfTrustKind {
    /// TPM 2.0 detected.
    Tpm20,
    /// Older TPM 1.2 — still common on Windows fleets pre-Win11.
    Tpm12,
    /// Apple Secure Enclave (T2 chip or Apple Silicon).
    SecureEnclave,
    /// No supported root-of-trust device found.
    None,
    /// Detection ran into an error — distinct from "absent".
    Unknown,
}

impl RootOfTrustKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm20 => "tpm20",
            Self::Tpm12 => "tpm12",
            Self::SecureEnclave => "secure_enclave",
            Self::None => "none",
            Self::Unknown => "unknown",
        }
    }
}

/// Snapshot of the host's hardware root of trust.
///
/// `present == true` when the OS reports an active, queryable device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootOfTrust {
    pub kind: RootOfTrustKind,
    pub vendor: String,
    pub present: bool,
}

impl RootOfTrust {
    fn absent() -> Self {
        Self {
            kind: RootOfTrustKind::None,
            vendor: String::new(),
            present: false,
        }
    }
    fn unknown() -> Self {
        Self {
            kind: RootOfTrustKind::Unknown,
            vendor: String::new(),
            present: false,
        }
    }
}

/// Detect the host's hardware root of trust. Never panics; on detection
/// failure returns `Unknown` so the caller can include it in the
/// fingerprint without crashing.
pub fn detect() -> RootOfTrust {
    #[cfg(target_os = "linux")]
    {
        detect_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos()
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        RootOfTrust::absent()
    }
}

// ── Linux ────────────────────────────────────────────────────────────────
//
// On Linux the kernel exposes TPM information under /sys/class/tpm/tpm0/.
// We read the version + manufacturer files directly — no syscalls, no
// extra dependencies. Falls back to /dev/tpm0 presence if /sys is
// unavailable (rare, but happens on minimal containers).

#[cfg(target_os = "linux")]
fn detect_linux() -> RootOfTrust {
    use std::fs;
    use std::path::Path;

    let tpm_dir = Path::new("/sys/class/tpm/tpm0");
    if !tpm_dir.exists() {
        // Some kernels expose the device but not the sysfs class entry.
        if Path::new("/dev/tpm0").exists() {
            return RootOfTrust {
                kind: RootOfTrustKind::Tpm20, // can't tell version without sysfs; assume modern
                vendor: String::new(),
                present: true,
            };
        }
        return RootOfTrust::absent();
    }

    // tpm_version_major: "1" = TPM 1.2, "2" = TPM 2.0 (most current).
    let kind = match fs::read_to_string(tpm_dir.join("tpm_version_major"))
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("2") => RootOfTrustKind::Tpm20,
        Some("1") => RootOfTrustKind::Tpm12,
        _ => RootOfTrustKind::Tpm20, // sane default for any TPM that's present
    };

    // manufacturer: hex string like "STM " (STMicroelectronics) or "INTC" (Intel).
    let vendor = fs::read_to_string(tpm_dir.join("tpm_manufacturer"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    debug!(?kind, vendor = %vendor, "detected linux tpm");
    RootOfTrust {
        kind,
        vendor,
        present: true,
    }
}

// ── macOS ────────────────────────────────────────────────────────────────
//
// macOS exposes the Secure Enclave through IOKit. We shell out to `ioreg`
// and look for the AppleSEPManager class. Apple Silicon Macs always have
// it; Intel Macs have it only with a T1/T2 chip.

#[cfg(target_os = "macos")]
fn detect_macos() -> RootOfTrust {
    use std::process::Command;

    let out = match Command::new("ioreg")
        .args(["-r", "-c", "AppleSEPManager", "-d", "1"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return RootOfTrust::unknown(),
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let present = text.contains("AppleSEPManager");
    if !present {
        return RootOfTrust::absent();
    }

    // Best-effort vendor extraction. Apple is always the vendor; we record
    // the detected chip family if visible (T2, M1, M2…) for cross-check.
    let vendor = if text.contains("\"product-name\"") {
        text.lines()
            .find(|l| l.contains("\"product-name\""))
            .and_then(|l| l.split('=').nth(1))
            .map(|s| {
                s.trim()
                    .trim_matches('<')
                    .trim_matches('>')
                    .trim_matches('"')
                    .to_string()
            })
            .unwrap_or_else(|| "Apple".to_string())
    } else {
        "Apple".to_string()
    };

    debug!(vendor = %vendor, "detected apple secure enclave");
    RootOfTrust {
        kind: RootOfTrustKind::SecureEnclave,
        vendor,
        present: true,
    }
}

// ── Windows ──────────────────────────────────────────────────────────────
//
// On Windows we shell out to PowerShell `Get-Tpm` and parse the JSON
// representation. Avoids pulling in WMI bindings. If PowerShell is
// missing or returns garbage, we fall back to `tpmtool getdeviceinformation`.

#[cfg(target_os = "windows")]
fn detect_windows() -> RootOfTrust {
    use std::process::Command;

    let ps_out = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Tpm | Select-Object TpmPresent,TpmReady,ManufacturerIdTxt,ManufacturerVersion | ConvertTo-Json -Compress",
        ])
        .output();

    if let Ok(out) = ps_out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            // Quick parse — we don't need a full JSON dependency for this.
            let present = text.contains("\"TpmPresent\":true");
            let ready = text.contains("\"TpmReady\":true");
            let vendor = extract_field(&text, "ManufacturerIdTxt").unwrap_or_default();
            if present {
                let kind = if ready {
                    RootOfTrustKind::Tpm20
                } else {
                    RootOfTrustKind::Tpm12
                };
                debug!(vendor = %vendor, ready, "detected windows tpm");
                return RootOfTrust {
                    kind,
                    vendor: vendor.trim().to_string(),
                    present: true,
                };
            }
            return RootOfTrust::absent();
        }
    }

    // Fallback: tpmtool — present on Windows 10+ Pro/Enterprise.
    let tt = Command::new("tpmtool").arg("getdeviceinformation").output();
    if let Ok(out) = tt {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("TPM Present: true") {
            let kind = if text.contains("Specification Version: 2.0") {
                RootOfTrustKind::Tpm20
            } else {
                RootOfTrustKind::Tpm12
            };
            return RootOfTrust {
                kind,
                vendor: String::new(),
                present: true,
            };
        }
    }

    RootOfTrust::absent()
}

#[cfg(target_os = "windows")]
fn extract_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        // The exact result depends on the host. We just want to confirm
        // the function returns without panicking on whatever the CI runner
        // has.
        let r = detect();
        assert!(matches!(
            r.kind,
            RootOfTrustKind::Tpm20
                | RootOfTrustKind::Tpm12
                | RootOfTrustKind::SecureEnclave
                | RootOfTrustKind::None
                | RootOfTrustKind::Unknown,
        ));
    }
}
