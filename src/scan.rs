use anyhow::Result;
use serde::Serialize;
use tokio::process::Command;

/// A struct defining a wifi network
#[derive(Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct WifiNetwork {
    /// The SSID of the access point
    pub ssid: String,
    /// Signal strength in dBm
    pub signal_dbm: i32,
    /// Encryption type(s) available
    pub security: String,
}

pub async fn scan_wifi_networks(iface: &str) -> Result<Vec<WifiNetwork>> {
    let link_out = Command::new("ip")
        .args(["link", "show", iface])
        .output()
        .await?;
    let link_stdout = String::from_utf8_lossy(&link_out.stdout);
    let already_up = link_stdout.contains("state UP");

    if !already_up {
        let _ = Command::new("ip")
            .args(["link", "set", iface, "down"])
            .output()
            .await;
        let _ = Command::new("iw")
            .args(["dev", iface, "set", "type", "managed"])
            .output()
            .await;
        let _ = Command::new("ip")
            .args(["link", "set", iface, "up"])
            .output()
            .await;
    }

    let out = Command::new("iw")
        .args(["dev", iface, "scan"])
        .output()
        .await?;
    Ok(parse_iw_scan(&String::from_utf8_lossy(&out.stdout)))
}

pub(crate) fn parse_iw_scan(output: &str) -> Vec<WifiNetwork> {
    let mut networks: Vec<WifiNetwork> = Vec::new();
    let mut current_ssid: Option<String> = None;
    let mut current_signal: i32 = -100;
    let mut current_security = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if line.starts_with("BSS ") {
            if let Some(ssid) = current_ssid.take()
                && !ssid.is_empty()
            {
                push_or_update(&mut networks, ssid, current_signal, &current_security);
            }
            current_signal = -100;
            current_security = String::new();
        } else if let Some(ssid) = trimmed.strip_prefix("SSID: ") {
            current_ssid = Some(ssid.to_string());
        } else if let Some(sig) = trimmed.strip_prefix("signal: ") {
            if let Some(dbm) = sig.split_whitespace().next() {
                current_signal = dbm.parse::<f32>().unwrap_or(-100.0) as i32;
            }
        } else if trimmed.starts_with("RSN:") {
            current_security = "WPA2".to_string();
        } else if trimmed.starts_with("WPA:") && current_security.is_empty() {
            current_security = "WPA".to_string();
        }
    }

    if let Some(ssid) = current_ssid
        && !ssid.is_empty()
    {
        push_or_update(&mut networks, ssid, current_signal, &current_security);
    }

    networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    networks
}

fn push_or_update(networks: &mut Vec<WifiNetwork>, ssid: String, signal: i32, security: &str) {
    if let Some(existing) = networks.iter_mut().find(|n| n.ssid == ssid) {
        if signal > existing.signal_dbm {
            existing.signal_dbm = signal;
        }
    } else {
        networks.push(WifiNetwork {
            ssid,
            signal_dbm: signal,
            security: if security.is_empty() {
                "Open".to_string()
            } else {
                security.to_string()
            },
        });
    }
}
