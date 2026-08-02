use crate::Result;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn normalize_choice(label: &str, value: &str, allowed: &[&str]) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if allowed.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(format!("invalid {label}: {value}"))
    }
}

pub(super) fn normalize_port(label: &str, value: &str) -> Result<String> {
    let value = value.trim();
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid {label}: {value}"))?;
    if port == 0 {
        return Err(format!("invalid {label}: {value}"));
    }
    Ok(port.to_string())
}

pub(super) fn normalize_optional_port(label: &str, value: &str) -> Result<String> {
    if value.trim().is_empty() {
        Ok(String::new())
    } else {
        normalize_port(label, value)
    }
}

pub(super) fn normalize_optional_interface(label: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if is_valid_interface_name(value) {
        Ok(value.to_string())
    } else {
        Err(format!("invalid {label}: {value}"))
    }
}

pub(super) fn normalize_interface_list(label: &str, values: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        let value = normalize_optional_interface(label, value)?;
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

pub(super) fn normalize_optional_cidr(label: &str, value: &str, ipv6: bool) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    validate_cidr(value, ipv6)
        .map(|()| value.to_string())
        .map_err(|()| format!("invalid {label}: {value}"))
}

pub(super) fn normalize_cidr_list(
    label: &str,
    values: &[String],
    ipv6: bool,
) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        let value = normalize_optional_cidr(label, value, ipv6)?;
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

pub(super) fn normalize_numeric_list(values: &[String]) -> Vec<String> {
    let mut normalized: Vec<u64> = values
        .iter()
        .filter_map(|value| value.trim().parse::<u64>().ok())
        .collect();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
        .into_iter()
        .map(|value| value.to_string())
        .collect()
}

fn is_valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validate_cidr(value: &str, ipv6: bool) -> std::result::Result<(), ()> {
    let (address, prefix) = value.split_once('/').ok_or(())?;
    let prefix = prefix.parse::<u8>().map_err(|_| ())?;
    if ipv6 {
        address.parse::<Ipv6Addr>().map_err(|_| ())?;
        (prefix <= 128).then_some(()).ok_or(())
    } else {
        address.parse::<Ipv4Addr>().map_err(|_| ())?;
        (prefix <= 32).then_some(()).ok_or(())
    }
}
