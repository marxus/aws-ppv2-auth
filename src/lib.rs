//! Envoy dynamic module: PROXY protocol v2 identity, for TCP and UDP.
//!
//! One shared object, three filters, chosen by `filter_name`. Each name is a
//! position in a chain, and takes exactly one config shape:
//!
//!   ppv2_auth   parse the header, synthesize, enforce a flat allowlist   `allow`
//!   ppv2        parse the header, synthesize, label and drain only       (empty)
//!   auth        read the label, scope by SNI, enforce                    `scopes`
//!   table       carry the identity table for everyone                    `ula` + `sites` + `groups`
//!
//! THE TABLE IS THE KING: ula, sites and groups ride exactly once per pod, on
//! the `table` filter parked on a listener nothing routes. Enforcing filters
//! carry rules only and re-expand them whenever the published table moves;
//! patching a listener MEANS consuming the table, and a rule config smuggling
//! `ula`/`sites`/`groups` fails its listener loudly. Until a carrier lands,
//! everything denies.
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
pub mod graph;
pub mod identity;
pub mod ppv2;
pub mod stats;
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

/// None rejects the listener; `name` is the proto's filter_name, how one .so exposes three filters.
fn new_listener_filter_config<EC: EnvoyListenerFilterConfig, ELF: EnvoyListenerFilter>(
    envoy_filter_config: &mut EC,
    name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
    match name {
        "ppv2_auth" => {
            let cfg = load(config_bytes, validate_ppv2_auth)?;
            let counters = counters(name, envoy_filter_config);
            Some(Box::new(tcp::Ppv2Config::enforcing(cfg, counters)))
        }
        "ppv2" => {
            let cfg = load(config_bytes, validate_ppv2)?;
            let counters = counters(name, envoy_filter_config);
            Some(Box::new(tcp::Ppv2Config::labelling(cfg, counters)))
        }
        "auth" => {
            let cfg = load(config_bytes, validate_auth)?;
            let counters = counters(name, envoy_filter_config);
            Some(Box::new(tcp::AuthConfig { cfg, counters }))
        }
        "table" => load_table(config_bytes).then(|| Box::new(tcp::TableConfig) as _),
        _ => {
            eprintln!(
                "ppv2-auth: unknown filter_name {name:?}; expected ppv2_auth, ppv2, auth or table"
            );
            None
        }
    }
}

fn new_udp_listener_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    envoy_filter_config: &mut EC,
    name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    // NEVER None on UDP: Envoy 1.39.1 segfaults on a null UDP dynamic-module
    // config where TCP NACKs cleanly (observed live, 0.14 -> 0.15 rollout). A
    // rejected config becomes a drop-everything filter instead -- the same
    // fail-closed denial, minus the crash. stderr still says why.
    let built: Option<Box<dyn UdpListenerFilterConfig<ELF>>> = match name {
        "ppv2_auth" => load(config_bytes, validate_ppv2_auth).map(|cfg| {
            let counters =
                stats::Counters::register(name, |n| envoy_filter_config.define_counter(n).ok());
            Box::new(udp::Ppv2AuthConfig { cfg, counters }) as _
        }),
        "table" => load_table(config_bytes).then(|| Box::new(udp::TableConfig) as _),
        _ => {
            // The UDP ABI has no way to hand an identity onward, so UDP enforcement is one filter.
            eprintln!("ppv2-auth: UDP supports only filter_name ppv2_auth or table, got {name:?}");
            None
        }
    };
    Some(built.unwrap_or_else(|| Box::new(udp::DenyAllConfig)))
}

/// Prefixed with the filter_name: all filters share one metrics namespace, so
/// unprefixed names from ppv2 and auth on the same listener would merge.
fn counters<EC: EnvoyListenerFilterConfig>(name: &str, ec: &mut EC) -> stats::Counters {
    stats::Counters::register(name, |n| ec.define_counter(n).ok())
}

/// The one place config failures become rejected listeners; Envoy says nothing, so stderr must.
fn load(
    bytes: &[u8],
    check: fn(&config::Config) -> Result<(), &'static str>,
) -> Option<Arc<config::Config>> {
    let parsed = text_of(bytes)
        .and_then(config::parse)
        .and_then(|c| check(&c).map_err(str::to_string).map(|()| c));
    match parsed {
        Ok(cfg) => Some(Arc::new(cfg)),
        Err(e) => {
            eprintln!("ppv2-auth: bad filter_config: {e}");
            None
        }
    }
}

/// The carrier's loader: parse the table and PUBLISH it -- the whole job.
fn load_table(bytes: &[u8]) -> bool {
    match text_of(bytes).and_then(|t| config::parse_table(t)) {
        Ok(table) => {
            config::publish(table);
            true
        }
        Err(e) => {
            eprintln!("ppv2-auth: bad table config: {e}");
            false
        }
    }
}

fn text_of(bytes: &[u8]) -> Result<&str, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "filter_config is not valid UTF-8".to_string())?;
    // Absent filter_config arrives as ""; serde's EOF error helps nobody.
    if text.trim().is_empty() {
        return Err("filter_config is missing".into());
    }
    Ok(text)
}

/// `ppv2` only labels and drains; a rule here would read as applied and do nothing.
pub fn validate_ppv2(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.has_allow() || cfg.has_scopes() {
        return Err("`ppv2` takes no rules; use `ppv2_auth` to also enforce");
    }
    Ok(())
}

/// `ppv2_auth`: the whole job in one filter (TCP and UDP); empty `allow` is deny-all, like an empty SG.
pub fn validate_ppv2_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.has_scopes() {
        return Err("`ppv2_auth` runs before tls_inspector, so there is no SNI yet; use `auth`");
    }
    Ok(())
}

/// `auth` reads the label a preceding `ppv2` filter left, and scopes it by SNI.
pub fn validate_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if !cfg.has_scopes() {
        return Err("`auth` needs `scopes`");
    }
    // Never consulted once scopes exist -- it would read as applied and do nothing.
    if cfg.has_allow() {
        return Err("`auth` ignores a top-level `allow`; put those rules in a scope");
    }
    // A nameless scope can never match: dead config, likely a tenant CR mistake.
    // Checked through the Config so slim raw scopes are covered too.
    if cfg.has_nameless_scope() {
        return Err("a scope needs at least one `sni`");
    }
    Ok(())
}
