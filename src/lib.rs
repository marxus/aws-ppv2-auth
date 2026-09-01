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
fn new_listener_filter_config<EC: EnvoyListenerFilterConfig, ELF: EnvoyListenerFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
    let cfg = load(config_bytes, Side::Tcp)?;
    Some(Box::new(tcp::FilterConfig { cfg }))
}

fn new_udp_listener_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    let cfg = load(config_bytes, Side::Udp)?;
    Some(Box::new(udp::FilterConfig { cfg }))
}

/// Which filter is being configured. Named `Side` because `tcp::Filter` and
/// `udp::Filter` are the actual filters.
enum Side {
    Tcp,
    Udp,
}

/// The single place a config failure becomes a rejected listener. Envoy says
/// nothing about why it rejected one, so stderr is the only thread to pull.
fn load(bytes: &[u8], which: Side) -> Option<Arc<config::Config>> {
    match validate(bytes, which) {
        Ok(cfg) => Some(Arc::new(cfg)),
        Err(e) => {
            eprintln!("aws-ppv2-identity: bad filter_config: {e}");
            None
        }
    }
}

/// Fail closed: a missing `ula` has no safe default to substitute.
fn validate(bytes: &[u8], which: Side) -> Result<config::Config, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "filter_config is not valid UTF-8")?;
    let cfg = config::parse(text)?;
    // The TCP filter has no enforcement point, so an `allow` line here would be
    // a security rule that reads as applied and does nothing.
    if matches!(which, Side::Tcp) && !cfg.allow.is_empty() {
        return Err("`allow` is UDP-only; match the synthesized address in a SecurityPolicy");
    }
    Ok(cfg)
}
