//! The two TCP listener filters.
//!
//! `ppv2` parses the PROXY protocol header, labels the socket with the synthesized
//! identity and drains the header. `auth` decides whether the connection lives.
//!
//! They are separate because TLS forces it: the header must be drained before
//! tls_inspector can see the ClientHello, and the SNI only exists after it has run.
//!
//! ```text
//! tcp  -> [auth, ...]
//! tls  -> [ppv2, tls_inspector, auth, ...]
//! ```
//!
//! Do not also enable Envoy's proxy_protocol filter -- only one can drain the header.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

/// Aliased because the generated name crowds out every signature it appears in.
type Status = abi::envoy_dynamic_module_type_on_listener_filter_status;

enum Decision {
    Label {
        /// Carried alongside the text so `auth` never has to parse the address it
        /// just formatted -- both fall out of one `synthesize`.
        id: u128,
        text: identity::AddrText,
        port: u32,
        len: usize,
    },
    /// Total bytes wanted, not the remainder.
    Need(usize),
    NotProxyProtocol,
}

/// Shared by both filters: read the buffer, parse, synthesize.
fn inspect<ELF: EnvoyListenerFilter>(envoy: &ELF, prefix: identity::Prefix) -> Decision {
    let chunk = envoy.get_buffer_chunk();
    let buf = chunk.as_ref().map(|c| c.as_slice()).unwrap_or(&[]);
    match ppv2::parse(buf) {
        Ok(h) => {
            let addr = identity::synthesize(prefix, &h);
            Decision::Label {
                id: identity::to_u128(addr),
                text: identity::format(addr),
                port: h.src_port as u32,
                len: h.len,
            }
        }
        Err(ppv2::Error::Need(n)) => Decision::Need(n),
        Err(ppv2::Error::Invalid) => Decision::NotProxyProtocol,
    }
}

// --- ppv2: parse, label, drain ---------------------------------------------

pub struct Ppv2Config {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for Ppv2Config {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        // Arc, not a global: config_new reruns on every LDS update, so a global
        // would pin the first config and silently ignore EnvoyPatchPolicy edits.
        Box::new(Ppv2Filter {
            cfg: self.cfg.clone(),
            // The ceiling up front, so `want` never grows: one allocation, and
            // a real header completes on the first on_data instead of two.
            want: ppv2::MAX_HEADER,
            done: false,
            refused: false,
        })
    }
}

struct Ppv2Filter {
    cfg: Arc<config::Config>,
    /// TOTAL header bytes wanted from the start of the connection, not the
    /// remainder: Envoy peeks with MSG_PEEK and never consumes.
    want: usize,
    /// Terminal, and asymmetric: `done` admits, `refused` can never later admit.
    done: bool,
    refused: bool,
}

impl Ppv2Filter {
    /// Close the socket. Sets the terminal flag itself, so no call site can
    /// refuse without also becoming unable to admit later.
    fn refuse<ELF: EnvoyListenerFilter>(&mut self, envoy: &mut ELF) -> Status {
        self.refused = true;
        envoy.continue_filter_chain(false);
        Status::StopIteration
    }
}

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for Ppv2Filter {
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
        // Unreachable: lib.rs rejects a `ppv2` config without `ula`.
        let Some(prefix) = self.cfg.prefix else {
            return self.refuse(envoy);
        };

        // The buffer borrows `envoy` immutably and set_remote_address needs it
        // mutably, so decide here and carry out owned values only.
        let decision = inspect(envoy, prefix);

        match decision {
            Decision::Need(n) => {
                self.want = n;
                Status::StopIteration
            }
            Decision::NotProxyProtocol => {
                if self.cfg.require_ppv2 {
                    self.refuse(envoy)
                } else {
                    self.done = true;
                    Status::Continue
                }
            }
            Decision::Label {
                text, port, len, ..
            } => {
                // is_ipv6 is always true: synthesized is a ULA, passed-through
                // is already v6. A failure cannot be retried -- the buffer holds
                // the whole header -- so refuse rather than stall.
                if !envoy.set_remote_address(text.as_str(), port, true) {
                    return self.refuse(envoy);
                }
                envoy.drain_buffer(len);
                self.done = true;
                Status::Continue
            }
        }
    }
}

// --- auth: establish identity, scope it, allow or close ---------------------

pub struct AuthConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for AuthConfig {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        Box::new(AuthFilter {
            cfg: self.cfg.clone(),
            want: ppv2::MAX_HEADER,
            settled: false,
        })
    }
}

struct AuthFilter {
    cfg: Arc<config::Config>,
    want: usize,
    /// Terminal either way: this filter admits or closes, never both.
    settled: bool,
}

impl AuthFilter {
    /// Deny by default: a scope must claim the SNI and cover the identity.
    fn judge<ELF: EnvoyListenerFilter>(&mut self, envoy: &mut ELF, id: u128) -> Status {
        let permitted = {
            let sni = envoy.get_requested_server_name();
            let sni = sni.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
            self.cfg.permits(sni, id)
        };
        if permitted {
            Status::Continue
        } else {
            self.refuse(envoy)
        }
    }

    fn refuse<ELF: EnvoyListenerFilter>(&mut self, envoy: &mut ELF) -> Status {
        self.settled = true;
        envoy.continue_filter_chain(false);
        Status::StopIteration
    }
}

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for AuthFilter {
    fn on_accept(&mut self, envoy: &mut ELF) -> Status {
        if self.cfg.prefix.is_some() {
            return Status::StopIteration; // needs the header; decides in on_data
        }
        // A `ppv2` filter already labelled the socket, so there is nothing to read
        // and no reason to wait. on_accept runs only once every preceding filter has
        // finished, which is what places this after tls_inspector.
        self.settled = true;
        match labelled_identity(envoy) {
            Some(id) => self.judge(envoy, id),
            None => self.refuse(envoy),
        }
    }

    fn max_read_bytes(&mut self, _envoy: &mut ELF) -> usize {
        // 0 makes Envoy skip on_data entirely when the label is already there.
        if self.cfg.prefix.is_some() {
            self.want
        } else {
            0
        }
    }

    fn on_data(&mut self, envoy: &mut ELF, _data_length: usize) -> Status {
        if self.settled {
            return Status::StopIteration;
        }
        let Some(prefix) = self.cfg.prefix else {
            return self.refuse(envoy);
        };

        let decision = inspect(envoy, prefix);

        match decision {
            Decision::Need(n) => {
                self.want = n;
                Status::StopIteration
            }
            // Unlabelled traffic has no identity, so no list can cover it.
            Decision::NotProxyProtocol => self.refuse(envoy),
            Decision::Label {
                id,
                text,
                port,
                len,
            } => {
                self.settled = true;
                // Label and strip even though we may then close, so the access log
                // shows the identity that was judged. The return is ignored on
                // purpose: the decision uses `id`, not the socket, so a failed
                // relabel costs a log line rather than the verdict.
                let _ = envoy.set_remote_address(text.as_str(), port, true);
                envoy.drain_buffer(len);
                self.judge(envoy, id)
            }
        }
    }
}

/// The address a preceding `ppv2` filter wrote onto the socket.
fn labelled_identity<ELF: EnvoyListenerFilter>(envoy: &ELF) -> Option<u128> {
    let (addr, _port) = envoy.get_remote_address()?;
    let ip: std::net::Ipv6Addr = addr.parse().ok()?;
    Some(identity::to_u128(ip.octets()))
}
