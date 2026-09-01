//! Envoy dynamic module: PROXY protocol v2 identity, for TCP and UDP.
//!
//! ONE SHARED OBJECT, TWO FILTERS. declare_all_init_functions! registers both
//! families from a single .so, so it can be referenced as both
//! envoy.filters.listener.dynamic_modules and
//! envoy.filters.udp_listener.dynamic_modules. The parser, the identity
//! synthesis and the config format are shared; only the last step differs:
//!
//!   TCP  set_remote_address  -> a SecurityPolicy does the matching downstream
//!   UDP  in-filter allowlist -> nothing downstream can read an identity
//!
//! See src/tcp.rs and src/udp.rs for why.
//!
//! WHAT THE SDK REMOVES, relative to the hand-rolled ABI this replaces:
//!
//!   * No transcribed abi.h. bindgen generates the bindings from the header of
//!     the pinned Envoy tag, so an ABI change is a build error rather than
//!     something a human is asked to re-check.
//!   * No export boilerplate. The macro emits the entry points.
//!   * No stub hooks. Envoy resolves the ENTIRE hook set when building a filter
//!     config, and a missing symbol is a startup failure -- with hand-written
//!     exports that means writing stubs for hooks you never use. Here the traits
//!     have default methods and the SDK exports everything.
//!   * Panics are contained. Every entry point is wrapped in catch_unwind, so a
//!     bug in the parser drops a connection instead of killing an Envoy worker.

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

/// Fail closed: returning None makes Envoy reject the listener config, so a
/// module that cannot parse its config never sees traffic. Do not substitute a
/// default -- an empty allowlist is the deny-everything state, but a missing
/// `ula` has no safe interpretation at all.
fn new_listener_filter_config<EC: EnvoyListenerFilterConfig, ELF: EnvoyListenerFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
    let cfg = parse_config(config_bytes)?;
    // The TCP filter has no enforcement point -- it labels, and a SecurityPolicy
    // matches downstream. An `allow` line here would be a security rule that
    // reads as applied and does nothing, so fail the listener instead.
    if !cfg.allow.is_empty() {
        eprintln!(
            "aws-ppv2-identity: `allow` is UDP-only; the TCP filter cannot enforce it. \
             Match the synthesized address in a SecurityPolicy instead."
        );
        return None;
    }
    Some(Box::new(tcp::FilterConfig { cfg }))
}

fn new_udp_listener_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    let cfg = parse_config(config_bytes)?;
    Some(Box::new(udp::FilterConfig { cfg }))
}

/// Envoy rejects the listener when this returns None but says nothing about
/// why, and an ABI mismatch only warns -- so a silent failure here is a module
/// that does not load with no thread to pull. stderr is the one channel a
/// listener filter config hook has, and Envoy captures it.
fn parse_config(bytes: &[u8]) -> Option<Arc<config::Config>> {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("aws-ppv2-identity: filter_config is not valid UTF-8");
            return None;
        }
    };
    match config::parse(text) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            eprintln!("aws-ppv2-identity: bad filter_config: {e}");
            None
        }
    }
}
