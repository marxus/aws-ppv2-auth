//! Envoy dynamic module: PROXY protocol v2 identity, for TCP and UDP.
//!
//! One shared object, three filters, chosen by `filter_name`. Each name is a
//! position in a chain, and takes exactly one config shape:
//!
//!   ppv2_auth   parse the header, synthesize, enforce a flat allowlist   `allow` (+ table, or slim)
//!   ppv2        parse the header, synthesize, label and drain only       table, or slim
//!   auth        read the label, scope by SNI, enforce                    `scopes` (+ table, or slim)
//!   table       carry the identity table for every slim filter           `ula` + `sites` + `groups`
//!
//! The table -- ula, sites, groups -- may ride in each filter's own config
//! (self-contained) or ONCE per pod on a `table` filter parked on a listener
//! nothing routes; the other filters then go SLIM (rules only) and re-expand
//! whenever the published table moves. Slim filters deny until a carrier lands.
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
        "table" => {
            let cfg = load(config_bytes, validate_table)?;
            config::publish(cfg.table.clone());
            Some(Box::new(tcp::TableConfig))
        }
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
    match name {
        "ppv2_auth" => {
            let cfg = load(config_bytes, validate_ppv2_auth)?;
            let counters =
                stats::Counters::register(name, |n| envoy_filter_config.define_counter(n).ok());
            Some(Box::new(udp::Ppv2AuthConfig { cfg, counters }))
        }
        "table" => {
            let cfg = load(config_bytes, validate_table)?;
            config::publish(cfg.table.clone());
            Some(Box::new(udp::TableConfig))
        }
        _ => {
            // The UDP ABI has no way to hand an identity onward, so UDP enforcement is one filter.
            eprintln!("ppv2-auth: UDP supports only filter_name ppv2_auth or table, got {name:?}");
            None
        }
    }
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
    let parsed = std::str::from_utf8(bytes)
        .map_err(|_| "filter_config is not valid UTF-8".to_string())
        .and_then(|text| {
            // Absent filter_config arrives as ""; serde's EOF error helps nobody.
            if text.trim().is_empty() {
                return Err("filter_config is missing".into());
            }
            config::parse(text)
        })
        .and_then(|c| check(&c).map_err(str::to_string).map(|()| c));
    match parsed {
        Ok(cfg) => Some(Arc::new(cfg)),
        Err(e) => {
            eprintln!("ppv2-auth: bad filter_config: {e}");
            None
        }
    }
}

/// `ppv2` only labels and drains; a rule here would read as applied and do nothing.
/// A subscriber (`subscribe: true`) is legal: the published table synthesizes,
/// and until a carrier lands every connection is refused.
pub fn validate_ppv2(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.carries_table() && cfg.scheme().is_none() {
        return Err("`ppv2` needs `ula` to synthesize an identity");
    }
    if !cfg.allow.is_empty() || cfg.scopes.is_some() {
        return Err("`ppv2` takes only `ula`; use `ppv2_auth` to also enforce");
    }
    Ok(())
}

/// `ppv2_auth`: the whole job in one filter (TCP and UDP); empty `allow` is deny-all, like an empty SG.
/// A subscriber is legal -- see validate_ppv2.
pub fn validate_ppv2_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.carries_table() && cfg.scheme().is_none() {
        return Err("`ppv2_auth` needs `ula` to synthesize an identity");
    }
    if cfg.scopes.is_some() {
        return Err("`ppv2_auth` runs before tls_inspector, so there is no SNI yet; use `auth`");
    }
    Ok(())
}

/// `table` carries identity for every slim filter on the pod, and nothing else:
/// no rules -- it enforces nothing -- and it must actually have a table to carry.
pub fn validate_table(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.scheme().is_none() {
        return Err("`table` needs `ula`; carrying an empty table would deny every slim filter");
    }
    if !cfg.allow.is_empty() || cfg.scopes.is_some() {
        return Err("`table` carries identity, not rules; put `allow`/`scopes` on the enforcing filters");
    }
    Ok(())
}

/// `auth` reads the label a preceding `ppv2` filter left, and scopes it by SNI.
/// A `ula` AND `sites` are legal here -- members need both to ENCODE the way the
/// wire does (site-owned sources land in site space); its filter path never
/// parses a header, so neither is consulted per connection.
pub fn validate_auth(cfg: &config::Config) -> Result<(), &'static str> {
    if cfg.scopes.is_none() {
        return Err("`auth` needs `scopes`");
    }
    // Never consulted once scopes exist -- it would read as applied and do nothing.
    if !cfg.allow.is_empty() {
        return Err("`auth` ignores a top-level `allow`; put those rules in a scope");
    }
    // A nameless scope can never match: dead config, likely a tenant CR mistake.
    // Checked through the Config so slim raw scopes are covered too.
    if cfg.has_nameless_scope() {
        return Err("a scope needs at least one `sni`");
    }
    Ok(())
}
