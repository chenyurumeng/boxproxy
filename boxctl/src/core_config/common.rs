use super::*;

pub(super) fn tun_uid_lists(config: &Config) -> (Vec<String>, Vec<String>) {
    proxy_uid_lists(
        config.proxy_mode.as_str(),
        &config.selected_uids,
        &config.gid_list,
    )
}

pub(super) fn proxy_uid_lists(
    proxy_mode: &str,
    selected_uids: &[String],
    gid_list: &[String],
) -> (Vec<String>, Vec<String>) {
    let uids = normalized_app_uids(selected_uids, gid_list);
    match proxy_mode {
        "whitelist" | "white" => (uids, Vec::new()),
        "blacklist" | "black" => (Vec::new(), uids),
        _ => (Vec::new(), Vec::new()),
    }
}

pub(super) fn normalized_app_uids(selected_uids: &[String], gid_list: &[String]) -> Vec<String> {
    let mut values: Vec<u64> = selected_uids
        .iter()
        .chain(gid_list)
        .filter_map(|value| value.trim().parse::<u64>().ok())
        .collect();
    values.sort_unstable();
    values.dedup();
    values.into_iter().map(|value| value.to_string()).collect()
}

pub(super) fn tun_route_managed_by_box(config: &Config) -> bool {
    config.network_mode == crate::config::NetworkMode::Tun
        && (config.bypass_cn_ip || config.mac_filter)
}

pub(super) fn tun_exclude_interfaces(config: &Config) -> Vec<String> {
    normalized_text_values(&config.blocked_interfaces)
}

pub(super) fn tun_stack_value(
    config: &Config,
    current_stack: Option<String>,
    default_stack: &str,
) -> String {
    if config.bypass_cn_ip {
        return "gvisor".to_string();
    }

    current_stack
        .map(|value| {
            value
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_stack.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_uid_lists_merge_and_deduplicate_uid_and_gid_values() {
        let selected = vec![
            "10001".to_string(),
            "10003".to_string(),
            "invalid".to_string(),
        ];
        let gids = vec!["10003".to_string(), "010002".to_string(), " ".to_string()];

        assert_eq!(
            proxy_uid_lists("whitelist", &selected, &gids),
            (
                vec!["10001", "10002", "10003"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                Vec::new()
            )
        );
        assert_eq!(
            proxy_uid_lists("blacklist", &selected, &gids),
            (
                Vec::new(),
                vec!["10001", "10002", "10003"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
    }
}
