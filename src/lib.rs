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
        // no filter state and no set_remote_address, so UDP is `auth` alone.
        eprintln!("aws-ppv2-identity: UDP supports only filter_name auth, got {name:?}");
        return None;
    }
    let cfg = load(config_bytes, validate_udp_auth)?;
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

/// `ppv2` synthesizes, so it needs the prefix -- and it never enforces, so an
/// allowlist here would be a security rule that reads as applied and does nothing.
pub fn validate_ppv2(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_none() {
        return Err("`ppv2` needs `ula` to synthesize an identity");
    }
    if !cfg.allow.is_empty() || !cfg.scopes.is_empty() {
        return Err("`ppv2` does not enforce; put `allow` and `sni` on the `auth` filter");
    }
    Ok(())
}

/// `auth` takes identity either from its own PPv2 parse (`ula` present) or from the
/// label a preceding `ppv2` filter wrote. Both are valid, so nothing to require.
pub fn validate_auth(_cfg: &config::Config) -> Result<(), &'static str> {
    Ok(())
}

/// UDP has no preceding filter to read a label from, so it must parse for itself.
pub fn validate_udp_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_none() {
        return Err("UDP `auth` needs `ula`: there is no preceding filter to label it");
    }
    if !cfg.scopes.is_empty() {
        return Err("`sni` needs a TLS handshake; UDP has none");
    }
    Ok(())
}
