use super::*;
use std::io::ErrorKind;

impl<'a> RuleManager<'a> {
    pub(super) fn runtime_save(&self) -> Result<()> {
        fs::create_dir_all(&self.config.paths.state)
            .map_err(|err| format!("create state directory failed: {err}"))?;
        let text = runtime_snapshot_text(
            self.config.network_mode.as_str(),
            &self.config.bin_name,
            &self.config.ipv6_mode,
            &self.config.dns_hijack_mode,
            &self.config.tproxy_port,
            &self.config.redir_port,
            &self.config.tun_device,
        )?;
        self.write_runtime_snapshot(&text)
    }

    pub(super) fn runtime_clear(&self) -> Result<()> {
        remove_runtime_file(&self.runtime_snapshot_path())?;
        remove_runtime_file(&self.config.paths.state.join("runtime.iptables.env"))
    }

    pub(super) fn runtime_env_value(&self, key: &str) -> Option<String> {
        let text = fs::read_to_string(self.runtime_snapshot_path()).ok()?;
        serde_json::from_str::<serde_json::Value>(&text)
            .ok()?
            .get(key)?
            .as_str()
            .map(ToOwned::to_owned)
    }

    fn runtime_snapshot_path(&self) -> PathBuf {
        self.config.paths.state.join("runtime.iptables.json")
    }

    fn write_runtime_snapshot(&self, text: &str) -> Result<()> {
        let path = self.runtime_snapshot_path();
        crate::atomic_file::write_atomic(&path, text.as_bytes(), None)
            .map_err(|err| format!("write runtime snapshot {} failed: {err}", path.display()))
    }
}

fn runtime_snapshot_text(
    network_mode: &str,
    bin_name: &str,
    ipv6_mode: &str,
    dns_hijack_mode: &str,
    tproxy_port: &str,
    redir_port: &str,
    tun_device: &str,
) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "network_mode": network_mode,
        "bin_name": bin_name,
        "ipv6_mode": ipv6_mode,
        "dns_hijack_mode": dns_hijack_mode,
        "tproxy_port": tproxy_port,
        "redir_port": redir_port,
        "tun_device": tun_device,
    }))
    .map_err(|err| format!("serialize runtime snapshot failed: {err}"))
}

fn remove_runtime_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "remove runtime state {} failed: {err}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_snapshot_reads_only_json_string_fields() {
        let snapshot = serde_json::json!({
            "network_mode": "tproxy",
            "tproxy_port": "9898",
            "invalid": 42,
        });
        let text = serde_json::to_string(&snapshot).unwrap();
        let value = |key: &str| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()?
                .get(key)?
                .as_str()
                .map(ToOwned::to_owned)
        };

        assert_eq!(value("network_mode").as_deref(), Some("tproxy"));
        assert_eq!(value("invalid"), None);
    }

    #[test]
    fn runtime_snapshot_retains_effective_network_endpoints() {
        let text = runtime_snapshot_text(
            "tproxy",
            "sing-box",
            "enable",
            "redirect",
            "19093",
            "19092",
            "custom-tun",
        )
        .unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(snapshot["tproxy_port"], "19093");
        assert_eq!(snapshot["redir_port"], "19092");
        assert_eq!(snapshot["tun_device"], "custom-tun");
    }
}
