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

/// The ABI's status enum, aliased for the same reason as in tcp.rs.
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
    /// The stripped payload, reused across datagrams instead of allocated per
    /// one. Sound because the filter chain is built once per listener per worker
    /// (createUdpListenerFilterChain), not per datagram, and a worker is single
    /// threaded -- so this outlives every on_data and is never shared.
    payload: Vec<u8>,
}

/// What one on_data pass decided, mirroring tcp.rs. Three outcomes and one
/// exhaustive match, rather than an Option that has to carry the payload and a
/// bare `return` from inside the block that computes it.
enum Decision {
    /// Header parsed and the allowlist covers it; the stripped payload is
    /// already staged in `self.payload`.
    Forward,
    /// Parsed, but no `allow` rule covers the identity.
    Denied,
    /// Not PPv2 at all.
    NotProxyProtocol,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for Filter {
    fn on_data(&mut self, envoy: &mut ELF) -> Status {
        // Envoy may hand the datagram over as several chunks. The SDK enumerates
        // them, so unlike the Zig version there is no hand-rolled flatten() and
        // the single-chunk case -- which is every real datagram from an NLB --
        // costs no allocation at all.
        let decision = {
            let (chunks, total) = envoy.get_datagram_data();
            if total < ppv2::PREAMBLE {
                return Status::StopIteration;
            }
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

            // A datagram is self-contained: no "read more" here, unlike TCP.
            match ppv2::parse(buf) {
                Ok(h) => {
                    let addr = identity::synthesize(self.cfg.prefix, &h);
                    if self.cfg.allow.contains(identity::to_u128(addr)) {
                        self.payload.clear();
                        self.payload.extend_from_slice(&buf[h.len..]);
                        Decision::Forward
                    } else {
                        // Allowlist only, like a security group: allowed iff a
                        // rule covers it, so an empty list denies everything.
                        // Never gate this on the list being non-empty.
                        Decision::Denied
                    }
                }
                Err(_) => Decision::NotProxyProtocol,
            }
        };

        match decision {
            Decision::Forward if envoy.set_datagram_data(&self.payload) => Status::Continue,
            Decision::Forward => Status::StopIteration,
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
