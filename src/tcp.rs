//! The TCP listener filters, one per filter_name.
//!
//! `ppv2` and `ppv2_auth` parse the PROXY header, synthesize the identity and
//! label the socket; `ppv2_auth` additionally judges it against the flat
//! allowlist. `auth` reads the label a `ppv2` filter left and scopes it by SNI.
//!
//! ```text
//! tcp  -> [ppv2_auth, ...]
//! tls  -> [ppv2, tls_inspector, auth, ...]
//! ```
//!
//! Non-PPv2 traffic is refused, always: this module is the first thing after the
//! NLB, so anything without a header reached the listener directly.
//!
//! Do not also enable Envoy's proxy_protocol filter -- only one can drain the header.

use crate::{config, identity, ppv2};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

/// Aliased because the generated name crowds out every signature it appears in.
type Status = abi::envoy_dynamic_module_type_on_listener_filter_status;

// --- ppv2 / ppv2_auth: parse, label, drain, maybe enforce --------------------

pub struct Ppv2Config {
    cfg: Arc<config::Config>,
    /// Fixed by filter_name at listener build, never read from config -- it cannot drift.
    enforce: bool,
}

impl Ppv2Config {
    /// `ppv2_auth`: label, then judge against the flat allowlist.
    pub fn enforcing(cfg: Arc<config::Config>) -> Ppv2Config {
        Ppv2Config { cfg, enforce: true }
    }

    /// `ppv2`: label and drain only; a later `auth` filter judges.
    pub fn labelling(cfg: Arc<config::Config>) -> Ppv2Config {
        Ppv2Config {
            cfg,
            enforce: false,
        }
    }
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for Ppv2Config {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        // Arc, not a global: config_new reruns per LDS update; a global would pin the first config.
        Box::new(Ppv2Filter {
            cfg: self.cfg.clone(),
            enforce: self.enforce,
            // Ceiling up front: `want` never grows, so one buffer alloc and one on_data.
            want: ppv2::MAX_HEADER,
            done: false,
            refused: false,
        })
    }
}

struct Ppv2Filter {
    cfg: Arc<config::Config>,
    enforce: bool,
    /// TOTAL bytes from connection start, not the remainder -- Envoy peeks, never consumes.
    want: usize,
    /// Terminal and asymmetric: `done` admits, `refused` can never later admit.
    done: bool,
    refused: bool,
}

enum Decision {
    Label {
        /// Carried beside the text so enforcement never re-parses what it just formatted.
        id: u128,
        text: identity::AddrText,
        port: u32,
        len: usize,
    },
    /// Total bytes wanted, not the remainder.
    Need(usize),
    NotProxyProtocol,
}

/// Read the buffer, parse, synthesize.
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

impl Ppv2Filter {
    /// Close the socket, setting the terminal flag so no call site can forget it.
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
        // Refusal wins: StopIteration means "wait", not "reject" -- Envoy re-calls on_data, so a bare StopIteration got admitted next call.
        if self.refused {
            return Status::StopIteration;
        }
        if self.done {
            return Status::Continue;
        }
        // Unreachable: lib.rs rejects a config without `ula`.
        let Some(prefix) = self.cfg.prefix else {
            return self.refuse(envoy);
        };

        // The buffer borrow ends here; carry out owned values only.
        match inspect(envoy, prefix) {
            Decision::Need(n) => {
                self.want = n;
                Status::StopIteration
            }
            // No header means the client reached the listener directly.
            Decision::NotProxyProtocol => self.refuse(envoy),
            Decision::Label {
                id,
                text,
                port,
                len,
            } => {
                // is_ipv6 always true; a failure cannot be retried, so refuse rather than stall.
                if !envoy.set_remote_address(text.as_str(), port, true) {
                    return self.refuse(envoy);
                }
                // Label and strip before judging, so the access log shows what was judged.
                envoy.drain_buffer(len);
                if self.enforce && !self.cfg.permits_unscoped(id) {
                    return self.refuse(envoy);
                }
                self.done = true;
                Status::Continue
            }
        }
    }
}

// --- auth: read the label, scope by SNI, allow or close ----------------------

pub struct AuthConfig {
    pub cfg: Arc<config::Config>,
}

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for AuthConfig {
    fn new_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        Box::new(AuthFilter {
            cfg: self.cfg.clone(),
            settled: false,
        })
    }
}

struct AuthFilter {
    cfg: Arc<config::Config>,
    /// Terminal either way: this filter admits or closes, never both.
    settled: bool,
}

impl AuthFilter {
    fn refuse<ELF: EnvoyListenerFilter>(&mut self, envoy: &mut ELF) -> Status {
        self.settled = true;
        envoy.continue_filter_chain(false);
        Status::StopIteration
    }
}

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for AuthFilter {
    /// The whole filter: on_accept runs after every preceding filter, so SNI and label are already set.
    fn on_accept(&mut self, envoy: &mut ELF) -> Status {
        self.settled = true;
        let Some(id) = labelled_identity(envoy) else {
            // No label means no `ppv2` filter ran ahead of us.
            return self.refuse(envoy);
        };
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

    /// 0 makes Envoy bypass on_data entirely: this filter reads no bytes.
    fn max_read_bytes(&mut self, _envoy: &mut ELF) -> usize {
        0
    }

    fn on_data(&mut self, envoy: &mut ELF, _data_length: usize) -> Status {
        // Unreachable with max_read_bytes 0; fail closed if Envoy ever changes.
        if self.settled {
            return Status::StopIteration;
        }
        self.refuse(envoy)
    }
}

/// The address a preceding `ppv2` filter wrote onto the socket.
fn labelled_identity<ELF: EnvoyListenerFilter>(envoy: &ELF) -> Option<u128> {
    let (addr, _port) = envoy.get_remote_address()?;
    let ip: std::net::Ipv6Addr = addr.parse().ok()?;
    Some(identity::to_u128(ip.octets()))
}
