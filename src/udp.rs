//! UDP listener filter: parse PPv2, enforce, strip. Chained before udp_proxy.
//!
//! Enforces here because no UDP callback can attach an identity to a session, so
//! nothing downstream can read one -- it is this filter or nowhere. Synthesizes
//! the same address as the TCP filter against the same allowlist format.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

/// See tcp.rs.
type Status = abi::envoy_dynamic_module_type_on_udp_listener_filter_status;

/// Counter ids, resolved once at listener build; None never fails the listener.
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub allowed: Option<EnvoyCounterId>,
    pub denied: Option<EnvoyCounterId>,
    pub not_ppv2: Option<EnvoyCounterId>,
}

impl Counters {
    pub fn register<EC: EnvoyUdpListenerFilterConfig>(ec: &mut EC) -> Counters {
        Counters {
            allowed: ec.define_counter("allowed").ok(),
            denied: ec.define_counter("denied").ok(),
            not_ppv2: ec.define_counter("not_ppv2").ok(),
        }
    }
}

fn bump<ELF: EnvoyUdpListenerFilter>(envoy: &ELF, id: Option<EnvoyCounterId>) {
    if let Some(id) = id {
        let _ = envoy.increment_counter(id, 1);
    }
}

pub struct Ppv2AuthConfig {
    pub cfg: Arc<config::Config>,
    pub counters: Counters,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilterConfig<ELF> for Ppv2AuthConfig {
    fn new_udp_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn UdpListenerFilter<ELF>> {
        Box::new(Ppv2AuthFilter {
            cfg: self.cfg.clone(),
            counters: self.counters,
            payload: Vec::new(),
        })
    }
}

struct Ppv2AuthFilter {
    cfg: Arc<config::Config>,
    counters: Counters,
    /// Reused across datagrams -- the filter is per-listener-per-worker and single threaded.
    payload: Vec<u8>,
}

enum Decision {
    /// Stripped payload is staged in `self.payload`.
    Forward,
    /// Parsed, but no rule covers the identity.
    Denied,
    /// Headerless means the datagram reached the listener directly.
    NotPpv2,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for Ppv2AuthFilter {
    fn on_data(&mut self, envoy: &mut ELF) -> Status {
        // Unreachable: lib.rs rejects a UDP config without `ula`. Deny anyway.
        let Some(prefix) = self.cfg.prefix else {
            return Status::StopIteration;
        };
        // Single chunk (every real NLB datagram) borrows in place; multi-chunk joins.
        let decision = {
            let (chunks, total) = envoy.get_datagram_data();
            let joined: Option<Vec<u8>> = if chunks.len() == 1 {
                None
            } else {
                let mut v = Vec::with_capacity(total);
                for c in &chunks {
                    v.extend_from_slice(c.as_slice());
                }
                Some(v)
            };
            let buf: &[u8] = match &joined {
                Some(v) => v,
                None => chunks[0].as_slice(),
            };

            // Datagrams are self-contained: a short one is simply not PPv2.
            match ppv2::parse(buf) {
                Ok(h) => {
                    let addr = identity::synthesize(prefix, &h);
                    if self.cfg.permits_unscoped(identity::to_u128(addr)) {
                        self.payload.clear();
                        self.payload.extend_from_slice(&buf[h.len..]);
                        Decision::Forward
                    } else {
                        Decision::Denied
                    }
                }
                Err(_) => Decision::NotPpv2,
            }
        };

        match decision {
            Decision::Forward => {
                bump(envoy, self.counters.allowed);
                if envoy.set_datagram_data(&self.payload) {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            }
            Decision::Denied => {
                bump(envoy, self.counters.denied);
                Status::StopIteration
            }
            Decision::NotPpv2 => {
                bump(envoy, self.counters.not_ppv2);
                Status::StopIteration
            }
        }
    }
}
