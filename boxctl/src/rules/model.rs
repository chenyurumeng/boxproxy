use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProxyAction {
    Redirect,
    Tproxy,
    Mark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DnsNatKind {
    Hijack,
    Forward,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EbpfApplyMode {
    Start,
    UpdateThenStart,
}

#[derive(Clone, Debug)]
pub(super) struct RuleContext {
    pub(super) box_uid: String,
    pub(super) box_gid: String,
    pub(super) selected_uids: Vec<String>,
    pub(super) selected_gids: Vec<String>,
    pub(super) cnip_force_uids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Capabilities {
    pub(super) tproxy4: bool,
    pub(super) tproxy6: bool,
    pub(super) socket_match: bool,
    pub(super) socket_transparent: bool,
    pub(super) addrtype: bool,
    pub(super) conntrack_match: bool,
    pub(super) connmark_match: bool,
    pub(super) connmark_target: bool,
    pub(super) ipset: bool,
    pub(super) bpf_match: bool,
    pub(super) ip6_nat: bool,
    pub(super) restore4: bool,
    pub(super) restore6: bool,
}

pub(super) struct RuleManager<'a> {
    pub(super) config: &'a Config,
    pub(super) runner: &'a Runner,
    pub(super) capabilities: OnceCell<Capabilities>,
    pub(super) addrtype_v4_fallback_warned: OnceCell<()>,
    pub(super) addrtype_v6_fallback_warned: OnceCell<()>,
    pub(super) batch: RefCell<Option<batch::RuleBatch>>,
    pub(super) wait_support_v4: OnceCell<bool>,
    pub(super) wait_support_v6: OnceCell<bool>,
    pub(super) bypass_subnets_v4: OnceCell<Vec<String>>,
    pub(super) bypass_subnets_v6: OnceCell<Vec<String>>,
    pub(super) local_cidrs_v4: OnceCell<Vec<String>>,
    pub(super) local_cidrs_v6: OnceCell<Vec<String>>,
    pub(super) local_ip_chains_built: RefCell<HashSet<(Family, String)>>,
}
