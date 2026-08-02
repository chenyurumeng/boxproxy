use crate::Result;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    Tun,
    Tproxy,
    Ebpf,
    Redirect,
    Mixed,
    Enhance,
}

impl NetworkMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tun" => Ok(Self::Tun),
            "tproxy" => Ok(Self::Tproxy),
            "ebpf" => Ok(Self::Ebpf),
            "redirect" => Ok(Self::Redirect),
            "mixed" => Ok(Self::Mixed),
            "enhance" => Ok(Self::Enhance),
            _ => Err(format!("invalid network mode: {value}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Tproxy => "tproxy",
            Self::Ebpf => "ebpf",
            Self::Redirect => "redirect",
            Self::Mixed => "mixed",
            Self::Enhance => "enhance",
        }
    }

    pub const fn uses_tun(self) -> bool {
        matches!(self, Self::Tun | Self::Mixed)
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    Core,
    Blacklist,
    Whitelist,
}

impl ProxyMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "core" => Ok(Self::Core),
            "blacklist" | "black" => Ok(Self::Blacklist),
            "whitelist" | "white" => Ok(Self::Whitelist),
            _ => Err(format!("invalid proxy mode: {value}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Blacklist => "blacklist",
            Self::Whitelist => "whitelist",
        }
    }
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnipMode {
    Ipset,
    Ebpf,
}

impl CnipMode {
    pub fn from_storage(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("ebpf") {
            Self::Ebpf
        } else {
            Self::Ipset
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipset => "ipset",
            Self::Ebpf => "ebpf",
        }
    }
}

impl fmt::Display for CnipMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_proxy_aliases_at_the_storage_boundary() {
        assert_eq!(ProxyMode::parse("black").unwrap(), ProxyMode::Blacklist);
        assert_eq!(ProxyMode::parse("white").unwrap(), ProxyMode::Whitelist);
        assert_eq!(CnipMode::from_storage("unexpected"), CnipMode::Ipset);
    }
}
