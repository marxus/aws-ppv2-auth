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

pub struct FilterConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilterConfig<ELF> for FilterConfig {
    fn new_udp_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn UdpListenerFilter<ELF>> {
        Box::new(Filter {
            cfg: self.cfg.clone(),
            payload: Vec::new(),
        })
    }
}

pub struct Filter {
    cfg: Arc<config::Config>,
    /// Reused across datagrams: the filter chain is built once per listener per
    /// worker, not per datagram, and a worker is single threaded.
    payload: Vec<u8>,
}

enum Decision {
    /// Stripped payload is staged in `self.payload`.
    Forward,
    Denied,
    NotProxyProtocol,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for Filter {
    fn on_data(&mut self, envoy: &mut ELF) -> Status {
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
            // not PPv2 and require_ppv2 governs it like any other parse failure.
            match ppv2::parse(buf) {
                Err(ppv2::Error::Need(_)) => Decision::NotProxyProtocol,
                Ok(h) => {
                    let addr = identity::synthesize(self.cfg.prefix, &h);
                    if self.cfg.allow.contains(identity::to_u128(addr)) {
                        self.payload.clear();
                        self.payload.extend_from_slice(&buf[h.len..]);
                        Decision::Forward
                    } else {
                        // Allowlist only: an empty list denies everything, so
                        // never gate this on the list being non-empty.
                        Decision::Denied
                    }
                }
                Err(_) => Decision::NotProxyProtocol,
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
            Decision::Denied => Status::StopIteration,
            Decision::NotProxyProtocol => {
                if self.cfg.require_ppv2 {
                    Status::StopIteration
                } else {
                    Status::Continue
                }
            }
        }
    }
}
