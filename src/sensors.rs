use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Known Cybrium sensor binaries.
const KNOWN_SENSORS: &[&str] = &[
    "cysense", // Network traffic analysis
    "cyguard", // Endpoint protection scan
    "cyprobe", // Network device discovery
    "cyweb",   // Web application scan
    "cyscan",  // SAST / code scan
    "cymail",  // Email security scan
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorInfo {
    pub name: String,
    pub version: String,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub sensor_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub details: serde_json::Value,
    pub timestamp: String,
}

/// Discover which sensor binaries are installed and available in PATH.
pub fn discover_sensors(enabled: &[String]) -> Vec<SensorInfo> {
    let mut sensors = Vec::new();

    for &name in KNOWN_SENSORS {
        if !enabled.iter().any(|e| e == name) {
            debug!(sensor = name, "sensor not enabled in config, skipping");
            continue;
        }

        let info = match check_sensor(name) {
            Some(version) => {
                info!(sensor = name, version = %version, "sensor available");
                SensorInfo {
                    name: name.to_string(),
                    version,
                    available: true,
                }
            }
            None => {
                debug!(sensor = name, "sensor not found in PATH");
                SensorInfo {
                    name: name.to_string(),
                    version: String::new(),
                    available: false,
                }
            }
        };

        sensors.push(info);
    }

    sensors
}

/// Check if a sensor binary exists and get its version.
fn check_sensor(name: &str) -> Option<String> {
    let output = Command::new(name).arg("--version").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Some(if version.is_empty() {
        "unknown".to_string()
    } else {
        version
    })
}

/// Run a single sensor and collect its findings.
pub fn run_sensor(sensor_type: &str) -> Vec<Finding> {
    info!(sensor = sensor_type, "running sensor");

    let result = match sensor_type {
        "cysense" => run_cysense(),
        "cyguard" => run_cyguard(),
        "cyprobe" => run_cyprobe(),
        "cyweb" => run_cyweb(),
        "cyscan" => run_cyscan(),
        "cymail" => run_cymail(),
        _ => {
            warn!(sensor = sensor_type, "unknown sensor type");
            return Vec::new();
        }
    };

    match result {
        Ok(findings) => {
            info!(
                sensor = sensor_type,
                count = findings.len(),
                "sensor completed"
            );
            findings
        }
        Err(e) => {
            error!(sensor = sensor_type, error = %e, "sensor failed");
            Vec::new()
        }
    }
}

/// Run all available sensors and collect aggregated findings.
pub fn run_all_sensors(sensors: &[SensorInfo]) -> Vec<Finding> {
    let mut all_findings = Vec::new();

    for sensor in sensors {
        if !sensor.available {
            continue;
        }
        let findings = run_sensor(&sensor.name);
        all_findings.extend(findings);
    }

    all_findings
}

fn run_cysense() -> anyhow::Result<Vec<Finding>> {
    // cysense listens on a network interface for traffic anomalies
    let interface = detect_default_interface();
    let output = Command::new("cysense")
        .args([
            "listen",
            "--interface",
            &interface,
            "--duration",
            "30",
            "--format",
            "json",
        ])
        .output()?;

    parse_json_findings("cysense", &output.stdout)
}

fn run_cyguard() -> anyhow::Result<Vec<Finding>> {
    let output = Command::new("cyguard")
        .args(["scan", "--format", "json"])
        .output()?;

    parse_json_findings("cyguard", &output.stdout)
}

fn run_cyprobe() -> anyhow::Result<Vec<Finding>> {
    let interface = detect_default_interface();
    let subnet = detect_local_subnet();
    let output = Command::new("cyprobe")
        .args([
            "discover",
            "--interface",
            &interface,
            "--targets",
            &subnet,
            "--format",
            "json",
        ])
        .output()?;

    parse_json_findings("cyprobe", &output.stdout)
}

fn run_cyweb() -> anyhow::Result<Vec<Finding>> {
    let output = Command::new("cyweb")
        .args(["scan", "--format", "json"])
        .output()?;

    parse_json_findings("cyweb", &output.stdout)
}

fn run_cyscan() -> anyhow::Result<Vec<Finding>> {
    let output = Command::new("cyscan")
        .args(["scan", "--format", "json"])
        .output()?;

    parse_json_findings("cyscan", &output.stdout)
}

fn run_cymail() -> anyhow::Result<Vec<Finding>> {
    let output = Command::new("cymail")
        .args(["scan", "--format", "json"])
        .output()?;

    parse_json_findings("cymail", &output.stdout)
}

/// Parse JSON output from a sensor binary into findings.
/// Expects either a JSON array of findings or a JSON object with a `findings` field.
fn parse_json_findings(sensor_type: &str, stdout: &[u8]) -> anyhow::Result<Vec<Finding>> {
    let text = String::from_utf8_lossy(stdout);
    let text = text.trim();

    if text.is_empty() {
        return Ok(Vec::new());
    }

    // Try parsing as a direct array of findings
    if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(text) {
        return Ok(findings);
    }

    // Try parsing as an object with a "findings" key
    if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(arr) = wrapper.get("findings").and_then(|v| v.as_array()) {
            let findings: Vec<Finding> = arr
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            return Ok(findings);
        }
    }

    warn!(
        sensor = sensor_type,
        "could not parse sensor output as JSON findings"
    );
    Ok(Vec::new())
}

/// Detect the default network interface name.
fn detect_default_interface() -> String {
    #[cfg(target_os = "linux")]
    {
        // Read from /proc/net/route — first line after header with dest 00000000 is the default
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 2 && fields[1] == "00000000" {
                    return fields[0].to_string();
                }
            }
        }
        "eth0".to_string()
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("route").args(["get", "default"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("interface:") {
                    return trimmed.trim_start_matches("interface:").trim().to_string();
                }
            }
        }
        "en0".to_string()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "eth0".to_string()
    }
}

/// Detect the local subnet in CIDR notation.
fn detect_local_subnet() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            // Parse "default via X.X.X.X dev ethN" to infer subnet
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                    // Convert gateway to /24 subnet
                    let gw = parts[2];
                    if let Some(prefix) = gw.rsplit_once('.') {
                        return format!("{}.0/24", prefix.0);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("route").args(["get", "default"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("gateway:") {
                    let gw = trimmed.trim_start_matches("gateway:").trim();
                    if let Some(prefix) = gw.rsplit_once('.') {
                        return format!("{}.0/24", prefix.0);
                    }
                }
            }
        }
    }

    "192.168.1.0/24".to_string()
}
