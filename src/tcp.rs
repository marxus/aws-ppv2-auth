//! TCP listener filter: rewrite the connection source to a synthesized ULA.
//!
//! envoy.filters.listener.dynamic_modules. Parses PPv2 itself, so do not also
//! run Envoy's proxy_protocol filter here -- only one can drain the header.
//!
//! set_remote_address rewrites the address BEFORE any RBAC filter, so the
//! identity is what network RBAC on a TCPRoute, HTTP RBAC on an HTTPRoute and
//! the access log all see. Same clientCIDRs rules at L4 and L7, no header
//! injection, no CEL. See ../README.md.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

pub struct FilterConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for FilterConfig {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        // Arc, not a global: config_new runs again on every LDS update, so a
        // OnceLock-style global would pin the first config forever and silently
        // ignore edits to the EnvoyPatchPolicy.
        Box::new(Filter {
            cfg: self.cfg.clone(),
            want: 16,
            done: false,
        })
    }
}

pub struct Filter {
    cfg: Arc<config::Config>,
    /// Envoy calls on_data repeatedly as bytes arrive; `want` asks for exactly
    /// the number still needed.
    want: usize,
    done: bool,
}

/// What one on_data pass decided to do.
enum Decision {
    /// Header complete: rewrite the source to this address and drain that many bytes.
    Label {
        addr: identity::AddrText,
        port: u32,
        len: usize,
    },
    /// Not enough bytes yet; ask Envoy for this many.
    Need(usize),
    /// Not PPv2 at all.
    NotProxyProtocol,
}

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for Filter {
    /// Always inspect bytes; never Continue straight from accept.
    fn on_accept(
        &mut self,
        _envoy: &mut ELF,
    ) -> abi::envoy_dynamic_module_type_on_listener_filter_status {
        abi::envoy_dynamic_module_type_on_listener_filter_status::StopIteration
    }

    fn max_read_bytes(&mut self, _envoy: &mut ELF) -> usize {
        self.want
    }

    fn on_data(
        &mut self,
        envoy: &mut ELF,
        _data_length: usize,
    ) -> abi::envoy_dynamic_module_type_on_listener_filter_status {
        use abi::envoy_dynamic_module_type_on_listener_filter_status as Status;

        if self.done {
            return Status::Continue;
        }

        // The buffer borrows `envoy` immutably, while set_remote_address needs it
        // mutably -- so decide inside this scope and carry out owned values only.
        let decision = {
            let chunk = envoy.get_buffer_chunk();
            let buf = chunk.as_ref().map(|c| c.as_slice()).unwrap_or(&[]);
            match ppv2::parse(buf) {
                Ok(h) => Decision::Label {
                    addr: identity::format(identity::synthesize(self.cfg.prefix, &h)),
                    port: h.src_port as u32,
                    len: h.len,
                },
                Err(ppv2::Error::Need(n)) => Decision::Need(n),
                Err(ppv2::Error::Invalid) => Decision::NotProxyProtocol,
            }
        };

        match decision {
            Decision::Need(n) => {
                self.want = n;
                Status::StopIteration
            }
            // Pass through or refuse, but never label it.
            Decision::NotProxyProtocol => {
                self.done = true;
                if self.cfg.require_ppv2 {
                    Status::StopIteration
                } else {
                    Status::Continue
                }
            }
            Decision::Label { addr, port, len } => {
                // is_ipv6 is always true: a synthesized address is a ULA, and a
                // passed-through one is a real v6 address.
                if !envoy.set_remote_address(addr.as_str(), port, true) {
                    return Status::StopIteration;
                }
                // Strip the header so the backend sees only its own protocol.
                envoy.drain_buffer(len);
                self.done = true;
                Status::Continue
            }
        }
    }
}
