use crate::config::Config;
use crate::{logger, Result};
use jsonc_parser::ParseOptions;
use logger::{arg, LogKey};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

mod common;
mod mihomo;
mod sing_box;
mod util;
use common::*;
use mihomo::sync_mihomo;
use sing_box::sync_sing_box;
use util::*;

const MANAGED_TUN_BEGIN: &str = "# boxctl managed tun begin";
const MANAGED_TUN_END: &str = "# boxctl managed tun end";

pub fn sync(config: &Config) -> Result<()> {
    ensure_network_mode_supported(config)?;
    if !config.auto_sync_config {
        logger::info_key(config, LogKey::CoreConfigSyncDisabled, &[]);
    }

    match config.bin_name.as_str() {
        "mihomo" => sync_mihomo(config),
        "sing-box" => sync_sing_box(config),
        "hysteria" | "xray" | "v2fly" => {
            if config.auto_sync_config {
                logger::warn_key(
                    config,
                    LogKey::CoreConfigSyncUnsupported,
                    &[arg("core", &config.bin_name)],
                );
            }
            Ok(())
        }
        other => Err(format!("unknown core: {other}")),
    }
}

pub(crate) fn ensure_network_mode_supported(config: &Config) -> Result<()> {
    if config.network_mode == crate::config::NetworkMode::Ebpf && config.bin_name != "sing-box" {
        return Err("eBPF network mode is only supported by sing-box".to_string());
    }
    Ok(())
}

fn parse_yaml_runtime_value(text: &str, core: &str, source: &Path) -> Result<serde_norway::Value> {
    let mut value = serde_norway::from_str::<serde_norway::Value>(text)
        .map_err(|err| format!("parse {core} config {} failed: {err}", source.display()))?;
    value
        .apply_merge()
        .map_err(|err| format!("expand {core} config {} failed: {err}", source.display()))?;
    Ok(value)
}

fn format_yaml_runtime_value(
    value: &serde_norway::Value,
    core: &str,
    source: &Path,
) -> Result<String> {
    let mut formatted = serde_norway::to_string(value)
        .map_err(|err| format!("format {core} config {} failed: {err}", source.display()))?;
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_yaml_startup_config_without_comments() {
        let source = Path::new("source.yaml");
        let value = parse_yaml_runtime_value(
            "# source comment\ndns:\n  listen: 0.0.0.0:1053 # trailing comment\n",
            "mihomo",
            source,
        )
        .unwrap();
        let formatted = format_yaml_runtime_value(&value, "mihomo", source).unwrap();

        assert!(!formatted.contains("comment"));
        assert!(formatted.ends_with('\n'));
        assert!(serde_norway::from_str::<serde_norway::Value>(&formatted).is_ok());
    }

    #[test]
    fn formats_yaml_startup_config_with_expanded_merge_aliases() {
        let source = Path::new("source.yaml");
        let value = parse_yaml_runtime_value(
            "templates:\n  selectall: &selectall\n    type: select\nproxy-groups:\n  - name: first\n    <<: *selectall\n",
            "mihomo",
            source,
        )
        .unwrap();
        let formatted = format_yaml_runtime_value(&value, "mihomo", source).unwrap();

        assert!(!formatted.contains("&selectall"));
        assert!(!formatted.contains("*selectall"));
        assert!(!formatted.contains("<<:"));
        assert!(formatted.contains("name: first"));
        assert!(formatted.contains("type: select"));
    }
}
