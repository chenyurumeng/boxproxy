use crate::db;
use crate::Result;
use std::env;
use std::path::{Path, PathBuf};

mod core_values;
mod types;
mod validation;
use core_values::*;
pub use types::{CnipMode, NetworkMode, ProxyMode};
use validation::*;

#[derive(Clone, Debug)]
pub struct BoxPaths {
    pub home: PathBuf,
    pub run: PathBuf,
    pub state: PathBuf,
    pub bin: PathBuf,
    pub db: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {
    pub bin_name: Option<String>,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub auto_sync_config: Option<bool>,
    pub network_mode: Option<String>,
    pub proxy_mode: Option<String>,
    pub tproxy_port: Option<String>,
    pub redir_port: Option<String>,
    pub ipv6_mode: Option<String>,
    pub proxy_tcp: Option<bool>,
    pub proxy_udp: Option<bool>,
    pub dns_hijack_tcp: Option<bool>,
    pub dns_hijack_udp: Option<bool>,
    pub dns_hijack_mode: Option<String>,
    pub mihomo_dns_forward: Option<String>,
    pub mihomo_dns_port: Option<String>,
    pub quic: Option<String>,
    pub performance_mode: Option<bool>,
    pub clean_vendor_firewall: Option<bool>,
    pub cgroup_memcg: Option<bool>,
    pub memcg_limit: Option<String>,
    pub taskset_cpu: Option<bool>,
    pub allow_cpu: Option<String>,
    pub cgroup_blkio: Option<bool>,
    pub weight: Option<String>,
    pub bypass_cn_ip: Option<bool>,
    pub bypass_cn_ip_v4: Option<bool>,
    pub bypass_cn_ip_v6: Option<bool>,
    pub cn_ip_file: Option<PathBuf>,
    pub cn_ipv6_file: Option<PathBuf>,
    pub db_path: Option<PathBuf>,
    pub tun_device: Option<String>,
    pub fake_ip_range: Option<String>,
    pub fake_ip6_range: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub paths: BoxPaths,
    pub log_language: String,
    pub box_pid: PathBuf,
    pub box_log: PathBuf,
    pub box_user_group: String,
    pub bin_name: String,
    pub bin_list: Vec<String>,
    pub bin_path: PathBuf,
    pub bpf_matcher_path: PathBuf,
    pub bin_log: PathBuf,
    pub auto_sync_config: bool,
    pub network_mode: NetworkMode,
    pub proxy_mode: ProxyMode,
    pub tproxy_port: String,
    pub redir_port: String,
    pub ipv6_mode: String,
    pub ipv6: bool,
    pub proxy_tcp: bool,
    pub proxy_udp: bool,
    pub dns_hijack_tcp: bool,
    pub dns_hijack_udp: bool,
    pub dns_hijack_mode: String,
    pub mihomo_dns_forward: String,
    pub mihomo_dns_port: String,
    pub quic: String,
    pub performance_mode: bool,
    pub clean_vendor_firewall: bool,
    pub cgroup_memcg: bool,
    pub memcg_limit: String,
    pub taskset_cpu: bool,
    pub allow_cpu: String,
    pub cgroup_blkio: bool,
    pub weight: String,
    pub bypass_cn_ip: bool,
    pub cnip_mode: CnipMode,
    pub bypass_cn_ip_v4: bool,
    pub bypass_cn_ip_v6: bool,
    pub cn_ip_file: PathBuf,
    pub cn_ipv6_file: PathBuf,
    pub selected_uids: Vec<String>,
    pub cnip_force_uids: Vec<String>,
    pub wifi_network_control_enabled: bool,
    pub wifi_use_on_disconnect: bool,
    pub wifi_use_on_connect: bool,
    pub wifi_enable_ssid_matching: bool,
    pub wifi_enable_log: bool,
    pub wifi_list_mode: String,
    pub wifi_ssids: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub tun_device: String,
    pub fake_ip_range: String,
    pub fake_ip6_range: String,
    pub core_config_sources: CoreConfigSources,
    pub gid_list: Vec<String>,
    pub hotspot_ap_interfaces: Vec<String>,
    pub blocked_interfaces: Vec<String>,
    pub mac_filter: bool,
    pub mac_mode: String,
    pub macs_list: Vec<String>,
    pub intranet_cidrs4: Vec<String>,
    pub intranet_cidrs6: Vec<String>,
    pub config_name: String,
    pub source_config_path: PathBuf,
    pub runtime_config_path: PathBuf,
}

impl BoxPaths {
    pub fn new(home_arg: Option<String>, db_arg: Option<PathBuf>) -> Result<Self> {
        let home_str = home_arg
            .or_else(|| env::var("BOX_HOME").ok())
            .or_else(|| {
                db_arg.as_ref().and_then(|path| {
                    path.parent()
                        .map(|parent| parent.to_string_lossy().to_string())
                })
            })
            .or_else(infer_home_from_current_exe)
            .unwrap_or_else(|| "/data/user/0/com.boxproxy.box/files/box".to_string());
        let home = PathBuf::from(home_str);
        let db = db_arg.unwrap_or_else(|| home.join("box.db"));
        Ok(Self {
            run: home.join("run"),
            state: home.join("run").join("state"),
            bin: home.join("bin"),
            home,
            db,
        })
    }
}

impl Config {
    pub fn load(paths: BoxPaths, overrides: ConfigOverrides) -> Result<Self> {
        let db_data = db::load_runtime_data(&paths.db)?;
        let auto_sync_config = overrides
            .auto_sync_config
            .unwrap_or(db_data.auto_sync_config);
        let bin_name = overrides
            .bin_name
            .clone()
            .unwrap_or_else(|| db_data.core_name.clone());
        let db_config_name = db_data.config_name.trim().to_string();
        let (config_name, source_config_path) = match overrides.config_path.clone() {
            Some(path) => {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string();
                (name, path)
            }
            None => {
                let path = paths.home.join(&bin_name).join(&db_config_name);
                (db_config_name, path)
            }
        };
        let network_mode = NetworkMode::parse(
            &overrides
                .network_mode
                .clone()
                .unwrap_or_else(|| db_data.mode.clone()),
        )?;
        let proxy_mode = ProxyMode::parse(
            &overrides
                .proxy_mode
                .clone()
                .unwrap_or_else(|| db_data.proxy_mode.clone()),
        )?;
        let default_mihomo_dns_port = default_mihomo_dns_port(&bin_name);
        let default_tun_device = default_tun_device(&bin_name, network_mode.as_str());
        let default_tproxy_port = "7893".to_string();
        let default_redir_port = "7892".to_string();
        let db_tproxy_port = non_empty_value(&db_data.tproxy_port);
        let db_redir_port = non_empty_value(&db_data.redir_port);
        let default_fake_ip_range = default_fake_ip_range(&bin_name);
        let default_fake_ip6_range = default_fake_ip6_range(&bin_name);
        let db_mihomo_dns_port = non_empty_value(&db_data.mihomo_dns_port);
        let db_tun_device = non_empty_value(&db_data.tun_device);
        let db_fake_ip_range = non_empty_value(&db_data.fake_ip_range);
        let db_fake_ip6_range = non_empty_value(&db_data.fake_ip6_range);
        let core_values = if core_config_values_needed(&bin_name) {
            CoreConfigValues::read(&bin_name, network_mode.as_str(), &source_config_path)
        } else {
            CoreConfigValues::skipped()
        };
        let resolved_tproxy_port = resolve_value(
            &overrides.tproxy_port,
            &db_tproxy_port,
            &core_values.tproxy_port,
            &default_tproxy_port,
            matches!(network_mode, NetworkMode::Tproxy | NetworkMode::Enhance),
        );
        let resolved_redir_port = resolve_value(
            &overrides.redir_port,
            &db_redir_port,
            &core_values.redir_port,
            &default_redir_port,
            matches!(
                network_mode,
                NetworkMode::Redirect | NetworkMode::Mixed | NetworkMode::Enhance
            ),
        );
        let resolved_mihomo_dns_port = resolve_value(
            &overrides.mihomo_dns_port,
            &db_mihomo_dns_port,
            &core_values.mihomo_dns_port,
            &default_mihomo_dns_port,
            bin_name == "mihomo",
        );
        let resolved_tun_device = resolve_value(
            &overrides.tun_device,
            &db_tun_device,
            &core_values.tun_device,
            &default_tun_device,
            network_mode.uses_tun(),
        );
        let resolved_fake_ip_range = resolve_value(
            &overrides.fake_ip_range,
            &db_fake_ip_range,
            &core_values.fake_ip_range,
            &default_fake_ip_range,
            matches!(bin_name.as_str(), "mihomo" | "sing-box"),
        );
        let resolved_fake_ip6_range = resolve_value(
            &overrides.fake_ip6_range,
            &db_fake_ip6_range,
            &core_values.fake_ip6_range,
            &default_fake_ip6_range,
            matches!(bin_name.as_str(), "mihomo" | "sing-box"),
        );
        let sources = CoreConfigSources {
            read_status: core_values.read_status.clone(),
            tproxy_port: resolved_tproxy_port.source,
            redir_port: resolved_redir_port.source,
            mihomo_dns_port: resolved_mihomo_dns_port.source,
            tun_device: resolved_tun_device.source,
            fake_ip_range: resolved_fake_ip_range.source,
            fake_ip6_range: resolved_fake_ip6_range.source,
        };

        let performance_mode = overrides
            .performance_mode
            .unwrap_or(db_data.performance_mode);
        let cnip_mode = CnipMode::from_storage(&db_data.cnip_mode);
        let mut config = Self {
            paths: paths.clone(),
            log_language: normalize_log_language(&db_data.log_language),
            box_pid: paths.run.join("box.pid"),
            box_log: paths.run.join("runs.log"),
            box_user_group: "root:net_admin".to_string(),
            bin_name: bin_name.clone(),
            bin_list: ["mihomo", "sing-box", "xray", "v2fly", "hysteria"]
                .iter()
                .map(|value| value.to_string())
                .collect(),
            bin_path: overrides
                .bin_path
                .clone()
                .unwrap_or_else(|| paths.bin.join(&bin_name)),
            bpf_matcher_path: paths.bin.join("boxbpf"),
            bin_log: paths.run.join(format!("{bin_name}.log")),
            auto_sync_config,
            network_mode,
            proxy_mode,
            tproxy_port: resolved_tproxy_port.value,
            redir_port: resolved_redir_port.value,
            ipv6_mode: normalize_ipv6_mode(
                overrides.ipv6_mode.as_deref().unwrap_or(&db_data.ipv6_mode),
            ),
            ipv6: normalize_ipv6_mode(overrides.ipv6_mode.as_deref().unwrap_or(&db_data.ipv6_mode))
                == "enable",
            proxy_tcp: overrides.proxy_tcp.unwrap_or(db_data.proxy_tcp),
            proxy_udp: overrides.proxy_udp.unwrap_or(db_data.proxy_udp),
            dns_hijack_tcp: overrides.dns_hijack_tcp.unwrap_or(db_data.dns_hijack_tcp),
            dns_hijack_udp: overrides.dns_hijack_udp.unwrap_or(db_data.dns_hijack_udp),
            dns_hijack_mode: overrides
                .dns_hijack_mode
                .clone()
                .unwrap_or_else(|| db_data.dns_hijack_mode.clone()),
            mihomo_dns_forward: overrides
                .mihomo_dns_forward
                .clone()
                .unwrap_or_else(|| db_data.mihomo_dns_forward.clone()),
            mihomo_dns_port: resolved_mihomo_dns_port.value,
            quic: overrides
                .quic
                .clone()
                .unwrap_or_else(|| db_data.quic.clone()),
            performance_mode,
            clean_vendor_firewall: overrides
                .clean_vendor_firewall
                .unwrap_or(db_data.clean_vendor_firewall),
            cgroup_memcg: overrides.cgroup_memcg.unwrap_or(db_data.cgroup_memcg),
            memcg_limit: overrides
                .memcg_limit
                .clone()
                .unwrap_or_else(|| db_data.memcg_limit.clone()),
            taskset_cpu: overrides.taskset_cpu.unwrap_or(db_data.taskset_cpu),
            allow_cpu: overrides
                .allow_cpu
                .clone()
                .unwrap_or_else(|| db_data.allow_cpu.clone()),
            cgroup_blkio: overrides.cgroup_blkio.unwrap_or(db_data.cgroup_blkio),
            weight: overrides
                .weight
                .clone()
                .unwrap_or_else(|| db_data.weight.clone()),
            bypass_cn_ip: overrides.bypass_cn_ip.unwrap_or(db_data.bypass_cn),
            cnip_mode,
            bypass_cn_ip_v4: overrides.bypass_cn_ip_v4.unwrap_or(db_data.bypass_cn_v4),
            bypass_cn_ip_v6: overrides.bypass_cn_ip_v6.unwrap_or(db_data.bypass_cn_v6),
            cn_ip_file: overrides
                .cn_ip_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(db_data.cn_ip_file.clone())),
            cn_ipv6_file: overrides
                .cn_ipv6_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(db_data.cn_ipv6_file.clone())),
            selected_uids: db_data.selected_uids,
            gid_list: db_data.gid_list,
            cnip_force_uids: db_data.cnip_force_uids,
            wifi_network_control_enabled: db_data.wifi_network_control_enabled,
            wifi_use_on_disconnect: db_data.wifi_use_on_disconnect,
            wifi_use_on_connect: db_data.wifi_use_on_connect,
            wifi_enable_ssid_matching: db_data.wifi_enable_ssid_matching,
            wifi_enable_log: db_data.wifi_enable_log,
            wifi_list_mode: db_data.wifi_list_mode,
            wifi_ssids: db_data.wifi_ssids,
            wifi_bssids: db_data.wifi_bssids,
            tun_device: resolved_tun_device.value,
            fake_ip_range: resolved_fake_ip_range.value,
            fake_ip6_range: resolved_fake_ip6_range.value,
            core_config_sources: sources,
            hotspot_ap_interfaces: db_data.hotspot_ap_interfaces,
            blocked_interfaces: db_data.blocked_interfaces,
            mac_filter: db_data.mac_filter,
            mac_mode: db_data.mac_mode,
            macs_list: db_data.macs_list,
            intranet_cidrs4: db_data.intranet_cidrs4,
            intranet_cidrs6: db_data.intranet_cidrs6,
            runtime_config_path: runtime_config_file_path(&paths),
            config_name,
            source_config_path,
        };

        config.normalize_and_validate()?;
        Ok(config)
    }

    pub fn core_dir(&self) -> PathBuf {
        self.paths.home.join(&self.bin_name)
    }

    pub fn source_config_path(&self) -> &Path {
        &self.source_config_path
    }

    pub fn runtime_config_path(&self) -> &Path {
        &self.runtime_config_path
    }

    pub fn uses_runtime_config(&self) -> bool {
        core_uses_runtime_config(&self.bin_name)
    }

    pub fn launch_config_path(&self) -> &Path {
        if self.uses_runtime_config() {
            self.runtime_config_path()
        } else {
            self.source_config_path()
        }
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        self.bin_name = normalize_choice(
            "core",
            &self.bin_name,
            &["mihomo", "sing-box", "xray", "v2fly", "hysteria"],
        )?;
        self.dns_hijack_mode = normalize_choice(
            "DNS hijack mode",
            &self.dns_hijack_mode,
            &["disable", "tproxy", "redirect", "redirect-apps"],
        )?;
        self.quic = normalize_choice("QUIC mode", &self.quic, &["enable", "disable"])?;
        self.mihomo_dns_forward = normalize_choice(
            "Mihomo DNS forwarding",
            &self.mihomo_dns_forward,
            &["enable", "disable"],
        )?;
        self.mac_mode = normalize_choice(
            "hotspot MAC mode",
            &self.mac_mode,
            &["whitelist", "blacklist"],
        )?;
        self.tproxy_port = normalize_port("TPROXY port", &self.tproxy_port)?;
        self.redir_port = normalize_port("REDIRECT port", &self.redir_port)?;
        self.mihomo_dns_port = normalize_optional_port("Mihomo DNS port", &self.mihomo_dns_port)?;
        self.tun_device = normalize_optional_interface("TUN device", &self.tun_device)?;
        self.hotspot_ap_interfaces =
            normalize_interface_list("hotspot interface", &self.hotspot_ap_interfaces)?;
        self.blocked_interfaces =
            normalize_interface_list("blocked interface", &self.blocked_interfaces)?;
        self.fake_ip_range =
            normalize_optional_cidr("Fake-IP IPv4 range", &self.fake_ip_range, false)?;
        self.fake_ip6_range =
            normalize_optional_cidr("Fake-IP IPv6 range", &self.fake_ip6_range, true)?;
        self.intranet_cidrs4 =
            normalize_cidr_list("intranet IPv4 CIDR", &self.intranet_cidrs4, false)?;
        self.intranet_cidrs6 =
            normalize_cidr_list("intranet IPv6 CIDR", &self.intranet_cidrs6, true)?;
        self.selected_uids = normalize_numeric_list(&self.selected_uids);
        self.gid_list = normalize_numeric_list(&self.gid_list);
        self.cnip_force_uids = normalize_numeric_list(&self.cnip_force_uids);

        if self.dns_hijack_mode == "redirect-apps" {
            if self.selected_uids.is_empty() {
                return Err(
                    "DNS hijack mode redirect-apps requires at least one selected application UID"
                        .to_string(),
                );
            }
            if !matches!(
                self.proxy_mode.as_str(),
                "whitelist" | "white" | "blacklist" | "black"
            ) {
                return Err(format!(
                    "DNS hijack mode redirect-apps requires whitelist or blacklist proxy mode, got {}",
                    self.proxy_mode.as_str()
                ));
            }
        }

        Ok(())
    }
}

fn runtime_config_file_path(paths: &BoxPaths) -> PathBuf {
    paths.state.join("startup-config")
}

fn core_uses_runtime_config(bin_name: &str) -> bool {
    matches!(bin_name, "mihomo" | "sing-box")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_uses_one_fixed_state_file() {
        let paths = BoxPaths {
            home: PathBuf::from("/box"),
            run: PathBuf::from("/box/run"),
            state: PathBuf::from("/box/run/state"),
            bin: PathBuf::from("/box/bin"),
            db: PathBuf::from("/box/box.db"),
        };

        assert_eq!(
            runtime_config_file_path(&paths),
            PathBuf::from("/box/run/state/startup-config")
        );
    }

    #[test]
    fn only_mihomo_and_sing_box_use_runtime_config() {
        assert!(core_uses_runtime_config("mihomo"));
        assert!(core_uses_runtime_config("sing-box"));
        assert!(!core_uses_runtime_config("hysteria"));
        assert!(!core_uses_runtime_config("xray"));
        assert!(!core_uses_runtime_config("v2fly"));
    }

    #[test]
    fn normalizes_ports_and_rejects_invalid_values() {
        assert_eq!(normalize_port("port", " 09898 ").unwrap(), "9898");
        assert!(normalize_port("port", "0").is_err());
        assert!(normalize_port("port", "53\n-A OUTPUT").is_err());
    }

    #[test]
    fn validates_interfaces_and_ip_ranges_before_rule_generation() {
        assert_eq!(
            normalize_optional_interface("interface", " wlan2 ").unwrap(),
            "wlan2"
        );
        assert!(normalize_optional_interface("interface", "wlan2 -j ACCEPT").is_err());
        assert!(normalize_optional_interface("interface", "wlan2\n-A OUTPUT").is_err());
        assert!(normalize_optional_cidr("CIDR", "198.18.0.1/16", false).is_ok());
        assert!(normalize_optional_cidr("CIDR", "198.18.0.1/64", false).is_err());
        assert!(normalize_optional_cidr("CIDR", "198.18.0.1 -j ACCEPT", false).is_err());
    }
}

fn core_config_values_needed(bin_name: &str) -> bool {
    matches!(bin_name, "mihomo" | "sing-box")
}

#[derive(Clone, Debug)]
pub struct CoreConfigSources {
    pub read_status: String,
    pub tproxy_port: &'static str,
    pub redir_port: &'static str,
    pub mihomo_dns_port: &'static str,
    pub tun_device: &'static str,
    pub fake_ip_range: &'static str,
    pub fake_ip6_range: &'static str,
}

fn infer_home_from_current_exe() -> Option<String> {
    let exe = env::current_exe().ok()?;
    let bin_dir = exe.parent()?;
    if bin_dir.file_name()?.to_str()? != "bin" {
        return None;
    }
    Some(bin_dir.parent()?.to_string_lossy().to_string())
}

fn normalize_log_language(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("en") {
        "en".to_string()
    } else {
        "zh-CN".to_string()
    }
}

pub fn normalize_ipv6_mode(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "enable" | "enabled" | "true" | "1" => "enable".to_string(),
        "disable" | "disabled" | "system_disable" | "off" => "disable".to_string(),
        _ => "bypass".to_string(),
    }
}
