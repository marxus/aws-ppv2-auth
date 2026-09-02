//! Envoy dynamic module: PROXY protocol v2 identity, for TCP and UDP.
//!
//! One shared object, two filters. Parser, synthesis and config are shared; only
//! the last step differs:
//!
//!   TCP  set_remote_address  -> a SecurityPolicy matches downstream
//!   UDP  in-filter allowlist -> nothing downstream can read an identity

use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

pub mod cidr;
pub mod config;
pub mod identity;
pub mod ppv2;
pub mod tcp;
pub mod udp;

declare_all_init_functions!(
    init,
    listener: new_listener_filter_config,
    udp_listener: new_udp_listener_filter_config,
);

fn init() -> bool {
    true
}

/// Returning None makes Envoy reject the listener, so a module that cannot parse
/// its config never sees traffic.
///
/// `name` is the `filter_name` from the DynamicModuleListenerFilter proto, which is
/// how one .so exposes more than one filter.
fn new_listener_filter_config<EC: EnvoyListenerFilterConfig, ELF: EnvoyListenerFilter>(
    _envoy_filter_config: &mut EC,
    name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
    match name {
        "ppv2" => {
            let cfg = load(config_bytes, validate_ppv2)?;
            Some(Box::new(tcp::Ppv2Config { cfg }))
        }
        "auth" => {
            let cfg = load(config_bytes, validate_auth)?;
            Some(Box::new(tcp::AuthConfig { cfg }))
        }
        _ => {
            eprintln!("aws-ppv2-identity: unknown filter_name {name:?}; expected ppv2 or auth");
            None
        }
    }
}

fn new_udp_listener_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    _envoy_filter_config: &mut EC,
    name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    if name != "auth" {
        // A UDP `ppv2` filter could not hand its identity anywhere: the UDP ABI has
        // no filter state and no set_remote_address, so UDP is `auth` alone. The
        // config rules are otherwise identical -- see validate_auth.
        eprintln!("aws-ppv2-identity: UDP supports only filter_name auth, got {name:?}");
        return None;
    }
    let cfg = load(config_bytes, validate_auth)?;
    Some(Box::new(udp::FilterConfig { cfg }))
}

/// The single place a config failure becomes a rejected listener. Envoy says
/// nothing about why it rejected one, so stderr is the only thread to pull.
fn load(
    bytes: &[u8],
    check: fn(&config::Config) -> Result<(), &'static str>,
) -> Option<Arc<config::Config>> {
    match parse(bytes).and_then(|c| check(&c).map(|()| c)) {
        Ok(cfg) => Some(Arc::new(cfg)),
        Err(e) => {
            eprintln!("aws-ppv2-identity: bad filter_config: {e}");
            None
        }
    }
}

fn parse(bytes: &[u8]) -> Result<config::Config, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "filter_config is not valid UTF-8")?;
    config::parse(text)
}

/// `ppv2` labels and drains, nothing else. It needs `ula` to synthesize, and an
/// allowlist here would be a rule that reads as applied and does nothing.
pub fn validate_ppv2(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_none() {
        return Err("`ppv2` needs `ula` to synthesize an identity");
    }
    if !cfg.allow.is_empty() || !cfg.scopes.is_empty() {
        return Err("`ppv2` takes only `ula`; put `allow` and `sni` on the `auth` filter");
    }
    Ok(())
}

/// `auth` needs something to permit, and exactly one way to learn the identity.
///
/// The two are positional, not about transport -- which is why this is the same
/// check for TCP and UDP, and why `auth` never has to know which it is:
///
///   `ula` -- I run BEFORE tls_inspector, so I parse the header myself.
///   `sni` -- I run AFTER it, so a preceding `ppv2` filter already labelled the
///            socket and the SNI exists to scope by.
///
/// Both at once is the contradiction "first and not first".
pub fn validate_auth(cfg: &config::Config) -> Result<(), &'static str> {
    let permits_something =
        !cfg.allow.is_empty() || cfg.scopes.iter().any(|(_, set)| !set.is_empty());
    if !permits_something {
        return Err("`auth` needs at least one `allow`, or it can never permit anything");
    }
    match (cfg.prefix.is_some(), !cfg.scopes.is_empty()) {
        (true, false) | (false, true) => Ok(()),
        (true, true) => Err("`ula` and `sni` are mutually exclusive: `ula` means this filter runs before tls_inspector, so there is no SNI yet"),
        (false, false) => Err("`auth` needs `ula` (parse the header here) or `sni` (read the label a `ppv2` filter left)"),
    }
}
