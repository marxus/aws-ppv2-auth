//! TCP listener filter: rewrite the connection source to a synthesized ULA.
//!
//! Parses PPv2 itself, so do not also enable Envoy's proxy_protocol filter here
//! -- only one can drain the header. set_remote_address runs before any RBAC
//! filter, so the identity is what L4 and L7 policy and the access log all see.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

/// Aliased because the generated name crowds out every signature it appears in.
type Status = abi::envoy_dynamic_module_type_on_listener_filter_status;

pub struct FilterConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for FilterConfig {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        // Arc, not a global: config_new reruns on every LDS update, so a global
        // would pin the first config and silently ignore EnvoyPatchPolicy edits.
        Box::new(Filter {
            cfg: self.cfg.clone(),
            // The ceiling up front, so `want` never grows: one allocation, and
            // a real header completes on the first on_data instead of two.
            want: ppv2::MAX_HEADER,
            done: false,
            refused: false,
        })
    }
}

pub struct Filter {
    cfg: Arc<config::Config>,
    /// TOTAL header bytes wanted from the start of the connection, not the
    /// remainder: Envoy peeks with MSG_PEEK and never consumes.
    want: usize,
    /// Terminal, and asymmetric: `done` admits, `refused` can never later admit.
    done: bool,
    refused: bool,
}

/// What one on_data pass decided to do.
enum Decision {
    /// Rewrite the source to this address and drain that many bytes.
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
    fn on_accept(&mut self, _envoy: &mut ELF) -> Status {
        Status::StopIteration
    }

    fn max_read_bytes(&mut self, _envoy: &mut ELF) -> usize {
        self.want
    }

    fn on_data(&mut self, envoy: &mut ELF, _data_length: usize) -> Status {
        // Refusal wins. StopIteration means "wait for more data", not "reject":
        // Envoy calls on_data again as bytes arrive, so a refusal that only
        // returned it was admitted on the next call. Rejecting is
        // continue_filter_chain(false), which closes the socket.
        if self.refused {
            return Status::StopIteration;
        }
        if self.done {
            return Status::Continue;
        }

        // The buffer borrows `envoy` immutably and set_remote_address needs it
        // mutably, so decide here and carry out owned values only.
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
                if self.cfg.require_ppv2 {
                    self.refused = true;
                    envoy.continue_filter_chain(false);
                    Status::StopIteration
                } else {
                    self.done = true;
                    Status::Continue
                }
            }
            Decision::Label { addr, port, len } => {
                // is_ipv6 is always true: synthesized is a ULA, passed-through
                // is already v6. A failure cannot be retried -- the buffer holds
                // the whole header -- so refuse rather than stall.
                if !envoy.set_remote_address(addr.as_str(), port, true) {
                    self.refused = true;
                    envoy.continue_filter_chain(false);
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
