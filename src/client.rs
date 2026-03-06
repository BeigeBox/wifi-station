use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use log::info;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use crate::{
    DHCP_LEASE_FILE, HOSTAPD_CONF, STA_IFACE, UDHCPC_HOOK, WPA_BIN, WPA_CONF_PATH, WifiConfig,
    iw_path,
};

pub(crate) const TX_STALL_THRESHOLD: u32 = 3;

pub(crate) struct WifiClient {
    pub(crate) iface: String,
    pub(crate) wpa_bin: String,
    pub(crate) hostapd_conf: String,
    pub(crate) wpa_child: Option<Child>,
    pub(crate) dhcp_child: Option<Child>,
    pub(crate) rt_table: u32,
    pub(crate) dns_servers: Vec<String>,
    pub(crate) saved_resolv: Option<String>,
    pub(crate) last_tx_packets: Option<u64>,
    pub(crate) last_rx_packets: Option<u64>,
    pub(crate) tx_stall_count: u32,
}

impl WifiClient {
    pub(crate) fn new(dns_servers: Vec<String>, config: &WifiConfig) -> Self {
        WifiClient {
            iface: STA_IFACE.to_string(),
            wpa_bin: config
                .wpa_supplicant_bin
                .clone()
                .unwrap_or_else(|| WPA_BIN.to_string()),
            hostapd_conf: config
                .hostapd_conf
                .clone()
                .unwrap_or_else(|| HOSTAPD_CONF.to_string()),
            wpa_child: None,
            dhcp_child: None,
            rt_table: 100,
            dns_servers,
            saved_resolv: None,
            last_tx_packets: None,
            last_rx_packets: None,
            tx_stall_count: 0,
        }
    }

    pub(crate) async fn start(&mut self) -> Result<()> {
        self.wait_for_interface().await?;
        self.set_managed_mode().await?;
        self.start_wpa_supplicant().await?;
        self.start_dhcp().await?;
        self.setup_routing().await?;
        self.allow_inbound().await;
        Ok(())
    }

    pub(crate) async fn stop(&mut self) {
        if let Some(mut child) = self.wpa_child.take() {
            let _ = child.kill().await;
        }
        if let Some(mut child) = self.dhcp_child.take() {
            let _ = child.kill().await;
        }
        self.remove_inbound().await;
        self.cleanup_routing().await;
        self.interface_down().await;

        crate::routing::restore_cellular_default().await;

        if let Some(resolv) = self.saved_resolv.take() {
            let _ = tokio::fs::write("/etc/resolv.conf", resolv).await;
        }
    }

    async fn create_sta_interface(&self) -> Result<()> {
        let iw = iw_path();
        let out = Command::new(iw)
            .args([
                "dev",
                crate::AP_IFACE,
                "interface",
                "add",
                &self.iface,
                "type",
                "managed",
            ])
            .output()
            .await;
        if let Ok(ref o) = out
            && o.status.success()
        {
            return Ok(());
        }
        info!("direct managed creation failed, trying P2P_CLIENT workaround");
        let out = Command::new(iw)
            .args([
                "dev",
                crate::AP_IFACE,
                "interface",
                "add",
                &self.iface,
                "type",
                "__p2pcl",
            ])
            .output()
            .await?;
        if !out.status.success() {
            bail!(
                "failed to create {}: {}",
                self.iface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let out = Command::new(iw)
            .args(["dev", &self.iface, "set", "type", "managed"])
            .output()
            .await?;
        if !out.status.success() {
            bail!(
                "failed to set {} to managed: {}",
                self.iface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    async fn wait_for_interface(&self) -> Result<()> {
        if !Path::new(&format!("/sys/class/net/{}", self.iface)).exists() {
            info!("{} not found, attempting to create it", self.iface);
            self.create_sta_interface().await?;
        }
        for _ in 0..30 {
            if Path::new(&format!("/sys/class/net/{}", self.iface)).exists() {
                return Ok(());
            }
            sleep(Duration::from_secs(1)).await;
        }
        bail!("{} not found after 30s", self.iface);
    }

    async fn set_managed_mode(&self) -> Result<()> {
        let out = Command::new(iw_path())
            .args(["dev", &self.iface, "set", "type", "managed"])
            .output()
            .await?;
        if !out.status.success() {
            bail!(
                "iw set type managed failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let out = Command::new("ip")
            .args(["link", "set", &self.iface, "up"])
            .output()
            .await?;
        if !out.status.success() {
            bail!(
                "ip link set up failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }

    pub(crate) async fn start_wpa_supplicant(&mut self) -> Result<()> {
        use std::process::Stdio;
        let child = Command::new(&self.wpa_bin)
            .args(["-i", &self.iface, "-Dnl80211", "-c", WPA_CONF_PATH])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.wpa_child = Some(child);
        if self.wait_for_association().await.is_ok() {
            return Ok(());
        }

        if let Some(mut child) = self.wpa_child.take() {
            let _ = child.kill().await;
        }

        if let Ok(out) = Command::new(iw_path())
            .args(["dev", &self.iface, "scan"])
            .output()
            .await
            && !out.status.success()
        {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("I/O error") || stderr.contains("(-5)") {
                bail!("scan failed with -EIO; radio may be busy (module reload needed)");
            }
        }
        bail!("wpa_supplicant did not associate within 30s");
    }

    async fn wait_for_association(&self) -> Result<()> {
        let operstate_path = format!("/sys/class/net/{}/operstate", self.iface);
        for i in 0..30 {
            if let Ok(state) = tokio::fs::read_to_string(&operstate_path).await
                && state.trim() == "up"
            {
                info!("wpa_supplicant associated after {}s", i + 1);
                return Ok(());
            }
            sleep(Duration::from_secs(1)).await;
        }
        bail!("wpa_supplicant did not associate within 30s");
    }

    pub(crate) async fn start_dhcp(&mut self) -> Result<()> {
        use std::process::Stdio;
        let _ = tokio::fs::remove_file(DHCP_LEASE_FILE).await;
        let child = Command::new("udhcpc")
            .args([
                "-i",
                &self.iface,
                "-s",
                UDHCPC_HOOK,
                "-t",
                "10",
                "-A",
                "3",
                "-f",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.dhcp_child = Some(child);

        for _ in 0..30 {
            sleep(Duration::from_secs(1)).await;
            if tokio::fs::metadata(DHCP_LEASE_FILE).await.is_ok() {
                return Ok(());
            }
        }
        bail!("DHCP did not assign an address within 30s");
    }

    pub(crate) async fn interface_down(&self) {
        let _ = Command::new("ip")
            .args(["link", "set", &self.iface, "down"])
            .output()
            .await;
    }

    pub(crate) fn interface_exists(&self) -> bool {
        Path::new(&format!("/sys/class/net/{}", self.iface)).exists()
    }

    pub(crate) async fn read_tx_packets(&self) -> Option<u64> {
        let path = format!("/sys/class/net/{}/statistics/tx_packets", self.iface);
        tokio::fs::read_to_string(&path)
            .await
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    pub(crate) async fn read_rx_packets(&self) -> Option<u64> {
        let path = format!("/sys/class/net/{}/statistics/rx_packets", self.iface);
        tokio::fs::read_to_string(&path)
            .await
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    pub(crate) async fn check_tx_advancing(&self) -> bool {
        let first = self.read_tx_packets().await;
        sleep(Duration::from_secs(5)).await;
        let second = self.read_tx_packets().await;
        match (first, second) {
            (Some(a), Some(b)) => b > a,
            _ => false,
        }
    }
}
