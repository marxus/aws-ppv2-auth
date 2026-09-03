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

pub struct Ppv2AuthConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilterConfig<ELF> for Ppv2AuthConfig {
    fn new_udp_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn UdpListenerFilter<ELF>> {
        Box::new(Ppv2AuthFilter {
            cfg: self.cfg.clone(),
            payload: Vec::new(),
        })
    }
}

struct Ppv2AuthFilter {
    cfg: Arc<config::Config>,
    /// Reused across datagrams: the filter chain is built once per listener per
    /// worker, not per datagram, and a worker is single threaded.
    payload: Vec<u8>,
}

enum Decision {
    /// Stripped payload is staged in `self.payload`.
    Forward,
    /// Not on the list, or not PPv2 at all -- no header means the datagram
    /// reached the listener directly.
    Deny,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for Ppv2AuthFilter {
    fn on_data(&mut self, envoy: &mut ELF) -> Status {
        // Unreachable: lib.rs rejects a UDP config without `ula`. Deny anyway.
        let Some(prefix) = self.cfg.prefix else {
            return Status::StopIteration;
        };
        // Several chunks are possible; the single-chunk case -- every real NLB
        // datagram -- borrows in place and costs no allocation.
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

            // Self-contained: no "read more" here, so a short datagram is simply
            // not PPv2 and is dropped like any other parse failure.
            match ppv2::parse(buf) {
                Ok(h) => {
                    let addr = identity::synthesize(prefix, &h);
                    // Through `permits` rather than reaching into `allow`, so there
                    // is one enforcement path. With no scopes it is the flat list;
                    // if `sni` ever reaches UDP the empty name matches nothing and
                    // this denies, instead of quietly ignoring the scopes.
                    if self.cfg.permits(b"", identity::to_u128(addr)) {
                        self.payload.clear();
                        self.payload.extend_from_slice(&buf[h.len..]);
                        Decision::Forward
                    } else {
                        Decision::Deny
                    }
                }
                Err(_) => Decision::Deny,
            }
        };

        match decision {
            Decision::Forward => {
                if envoy.set_datagram_data(&self.payload) {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            }
            Decision::Deny => Status::StopIteration,
        }
    }
}
