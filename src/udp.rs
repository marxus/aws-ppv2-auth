//! UDP listener filter: parse PPv2, enforce, strip.
//!
//! envoy.filters.udp_listener.dynamic_modules, chained BEFORE udp_proxy.
//!
//! Enforces here rather than delegating. The UDP ABI is not short of callbacks
//! -- there are 21, including get_peer_address, send_datagram, get_worker_index
//! and a full stats surface -- but none of them can attach an identity to the
//! session, so nothing downstream can read one. udp_proxy's tunneling_config
//! reads %FILTER_STATE(key)% and a UDP *session* filter could write it, but
//! there is no dynamic-modules session filter. So enforcement happens in this
//! filter or nowhere.
//!
//! It synthesizes the same address as the TCP filter and matches the same
//! allowlist format, so one identity scheme covers both paths. See ../README.md.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

pub struct FilterConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilterConfig<ELF> for FilterConfig {
    fn new_udp_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn UdpListenerFilter<ELF>> {
        Box::new(Filter {
            cfg: self.cfg.clone(),
        })
    }
}

pub struct Filter {
    cfg: Arc<config::Config>,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for Filter {
    fn on_data(
        &mut self,
        envoy: &mut ELF,
    ) -> abi::envoy_dynamic_module_type_on_udp_listener_filter_status {
        use abi::envoy_dynamic_module_type_on_udp_listener_filter_status as Status;

        // Envoy may hand the datagram over as several chunks. The SDK enumerates
        // them, so unlike the Zig version there is no hand-rolled flatten() and
        // the single-chunk case -- which is every real datagram from an NLB --
        // costs no allocation at all.
        let decision = {
            let (chunks, total) = envoy.get_datagram_data();
            if total < 16 {
                return Status::StopIteration;
            }
            let owned: Option<Vec<u8>> = if chunks.len() == 1 {
                None
            } else {
                let mut v = Vec::with_capacity(total);
                for c in &chunks {
                    v.extend_from_slice(c.as_slice());
                }
                Some(v)
            };
            let buf: &[u8] = match &owned {
                Some(v) => v,
                None => chunks[0].as_slice(),
            };

            // A datagram is self-contained: no "read more" here, unlike TCP.
            match ppv2::parse(buf) {
                Ok(h) => {
                    let addr = identity::synthesize(self.cfg.prefix, &h);
                    if !self.cfg.allow.contains(identity::to_u128(addr)) {
                        // Allowlist only, like a security group: allowed iff a
                        // rule covers it, so an empty list denies everything.
                        // Never gate this on the list being non-empty.
                        return Status::StopIteration;
                    }
                    Some(buf[h.len..].to_vec())
                }
                Err(_) => None,
            }
        };

        match decision {
            Some(payload) => {
                if !envoy.set_datagram_data(&payload) {
                    return Status::StopIteration;
                }
                Status::Continue
            }
            None => {
                if self.cfg.require_ppv2 {
                    Status::StopIteration
                } else {
                    Status::Continue
                }
            }
        }
    }
}
