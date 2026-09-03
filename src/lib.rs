//! Envoy dynamic module: PROXY protocol v2 identity, for TCP and UDP.
//!
//! One shared object, three filters, chosen by `filter_name`. Each name is a
//! position in a chain, and takes exactly one config shape:
//!
//!   ppv2_auth   parse the header, synthesize, enforce a flat allowlist   `ula` + `allow`
//!   ppv2        parse the header, synthesize, label and drain only       `ula`
//!   auth        read the label, scope by SNI, enforce                    `scopes`
//!
//!   tcp  -> [ppv2_auth, ...]
//!   udp  -> [ppv2_auth, ...]
//!   tls  -> [ppv2, tls_inspector, auth, ...]
//!
//! Deny by default in every one that enforces. TLS is the only case needing the
//! split: `auth` reads the SNI, which exists only after tls_inspector, and
//! tls_inspector cannot see a ClientHello until the header is drained.

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
        "ppv2_auth" => {
            let cfg = load(config_bytes, validate_ppv2_auth)?;
            Some(Box::new(tcp::AuthConfig { cfg }))
        }
        "ppv2" => {
            let cfg = load(config_bytes, validate_ppv2)?;
            Some(Box::new(tcp::Ppv2Config { cfg }))
        }
        "auth" => {
            let cfg = load(config_bytes, validate_auth)?;
            Some(Box::new(tcp::AuthConfig { cfg }))
        }
        _ => {
            eprintln!(
                "aws-ppv2-identity: unknown filter_name {name:?}; expected ppv2_auth, ppv2 or auth"
            );
            None
        }
    }
}

fn new_udp_listener_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    _envoy_filter_config: &mut EC,
    name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    if name != "ppv2_auth" {
        // UDP is always the whole job in one filter: the ABI has no filter state
        // and no set_remote_address, so nothing can hand an identity onward, and
        // there is no handshake for `auth` to scope by.
        eprintln!("aws-ppv2-identity: UDP supports only filter_name ppv2_auth, got {name:?}");
        return None;
    }
    let cfg = load(config_bytes, validate_ppv2_auth)?;
    Some(Box::new(udp::AuthConfig { cfg }))
}

/// The single place a config failure becomes a rejected listener. Envoy says
/// nothing about why it rejected one, so stderr is the only thread to pull.
fn load(
    bytes: &[u8],
    check: fn(&config::Config) -> Result<(), &'static str>,
) -> Option<Arc<config::Config>> {
    match parse(bytes).and_then(|c| check(&c).map_err(str::to_string).map(|()| c)) {
        Ok(cfg) => Some(Arc::new(cfg)),
        Err(e) => {
            eprintln!("aws-ppv2-identity: bad filter_config: {e}");
            None
        }
    }
}

fn parse(bytes: &[u8]) -> Result<config::Config, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "filter_config is not valid UTF-8")?;
    // Envoy passes an empty string when filter_config is absent; serde would then
    // report "EOF while parsing a value", which is not a useful thing to read.
    if text.trim().is_empty() {
        return Err("filter_config is missing".into());
    }
    config::parse(text)
}

/// `ppv2` labels and drains, nothing else -- it never denies, so a rule here would
/// read as applied and do nothing.
pub fn validate_ppv2(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_none() {
        return Err("`ppv2` needs `ula` to synthesize an identity");
    }
    if !cfg.allow.is_empty() || cfg.scopes.is_some() {
        return Err("`ppv2` takes only `ula`; use `ppv2_auth` to also enforce");
    }
    Ok(())
}

/// `ppv2_auth` is the whole job in one filter: plain TCP, and UDP.
///
/// It runs before anything else, so there is no SNI to scope by -- an empty
/// `allow` is fine and denies everything, the way an empty security group does.
pub fn validate_ppv2_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_none() {
        return Err("`ppv2_auth` needs `ula` to synthesize an identity");
    }
    if cfg.scopes.is_some() {
        return Err("`ppv2_auth` runs before tls_inspector, so there is no SNI yet; use `auth`");
    }
    Ok(())
}

/// `auth` reads the label a preceding `ppv2` filter left, and scopes it by SNI.
pub fn validate_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.prefix.is_some() {
        return Err("`auth` reads the label `ppv2` left, so it takes no `ula`; use `ppv2_auth`");
    }
    if cfg.scopes.is_none() {
        return Err("`auth` needs `scopes`");
    }
    // A top-level `allow` is never consulted once scopes exist, so it would be a
    // rule that reads as applied and does nothing.
    if !cfg.allow.is_empty() {
        return Err("`auth` ignores a top-level `allow`; put those rules in a scope");
    }
    Ok(())
}
