//! The two filters, against the SDK's mock Envoy.
//!
//! These are the files that actually decide whether traffic is admitted, and
//! they had no tests: every case here is an enforcement path, not a parse.

mod common;

use aws_ppv2_identity::{config, tcp, udp};
use common::{build, V2_PROXY};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::sync::Arc;

use abi::envoy_dynamic_module_type_on_listener_filter_status as TcpStatus;
use abi::envoy_dynamic_module_type_on_udp_listener_filter_status as UdpStatus;

const ULA: &str = "ula fd00:dead:beef::/48\n";
/// sha256("vpce-0123456789abcdef0")[..8] -- see tests/identity.rs.
const TENANT: &str = "allow fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128\n";

fn ppv2_config(text: &str) -> tcp::Ppv2Config {
    tcp::Ppv2Config {
        cfg: Arc::new(config::parse(text).unwrap()),
    }
}

fn auth_config(text: &str) -> tcp::AuthConfig {
    tcp::AuthConfig {
        cfg: Arc::new(config::parse(text).unwrap()),
    }
}

fn udp_config(text: &str) -> udp::FilterConfig {
    udp::FilterConfig {
        cfg: Arc::new(config::parse(text).unwrap()),
    }
}

/// Leaks so the mock can hand back an EnvoyBuffer borrowed from `&self`.
fn leak(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

// --- TCP -------------------------------------------------------------------

#[test]
fn a_refused_connection_is_not_admitted_by_a_later_on_data() {
    // REGRESSION. StopIteration means "wait for more data", not "reject", so
    // Envoy calls on_data again as bytes arrive. The filter used to mark itself
    // done on the refusal path, and the done-guard returned Continue on that
    // second call -- admitting a connection with require_ppv2 on. Reproduced
    // exactly: a short non-PPv2 prefix, then more bytes.
    let fc = ppv2_config(ULA);
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(|| Some(EnvoyBuffer::new(b"GET ")));
    // The actual reject mechanism, and it must fire exactly once.
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, 4), TcpStatus::StopIteration);
    // The second call is the bug. It must not admit.
    assert_eq!(f.on_data(&mut envoy, 16), TcpStatus::StopIteration);
    assert_eq!(f.on_data(&mut envoy, 64), TcpStatus::StopIteration);
}

#[test]
fn require_ppv2_false_still_passes_non_ppv2_through() {
    let fc = ppv2_config("ula fd00:dead:beef::/48\nrequire_ppv2 false\n");
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(|| Some(EnvoyBuffer::new(b"GET / HTTP/1.1\r\n\r\n")));
    envoy.expect_continue_filter_chain().never();

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, 18), TcpStatus::Continue);
}

#[test]
fn a_tenant_header_is_labelled_with_the_synthesized_address_and_drained() {
    let hdr = leak(build(
        V2_PROXY,
        0x11,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    ));
    let fc = ppv2_config(ULA);
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(hdr)));
    envoy
        .expect_set_remote_address()
        .withf(|addr, _port, is_ipv6| addr == "fd00:dead:beef:1:7b53:e75b:6e3d:cfdb" && *is_ipv6)
        .times(1)
        .returning(|_, _, _| true);
    // The whole header is stripped, so the backend sees only its own protocol.
    envoy
        .expect_drain_buffer()
        .withf(move |len| *len == hdr.len())
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, hdr.len()), TcpStatus::Continue);
}

#[test]
fn a_partial_header_asks_for_the_total_not_the_remainder() {
    // Envoy peeks with MSG_PEEK and never consumes, so max_read_bytes is
    // counted from the first byte of the connection.
    let full = build(V2_PROXY, 0x11, &[10, 0, 1, 28], Some(b"vpce-abc"));
    let total = full.len();
    let head = leak(full[..16].to_vec());

    let fc = ppv2_config(ULA);
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(head)));

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, 16), TcpStatus::StopIteration);
    assert_eq!(f.max_read_bytes(&mut envoy), total);
}

// --- UDP -------------------------------------------------------------------

#[test]
fn a_datagram_outside_the_allowlist_is_dropped() {
    let dg = leak(build(
        V2_PROXY,
        0x12,
        &[10, 0, 1, 28],
        Some(b"vpce-somebody-else"),
    ));
    let fc = udp_config(&format!("{ULA}{TENANT}"));
    let mut envoy = MockEnvoyUdpListenerFilter::new();
    envoy
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(dg)], dg.len()));
    envoy.expect_set_datagram_data().never();

    let mut f = fc.new_udp_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy), UdpStatus::StopIteration);
}

#[test]
fn an_allowed_datagram_is_stripped_and_forwarded() {
    let payload = b"\x12\x34hello dns";
    let mut dg_vec = build(
        V2_PROXY,
        0x12,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    );
    let hdr_len = dg_vec.len();
    dg_vec.extend_from_slice(payload);
    let dg = leak(dg_vec);

    let fc = udp_config(&format!("{ULA}{TENANT}"));
    let mut envoy = MockEnvoyUdpListenerFilter::new();
    envoy
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(dg)], dg.len()));
    // Only the payload survives -- the PPv2 header is not forwarded.
    envoy
        .expect_set_datagram_data()
        .withf(move |data| data == &dg[hdr_len..])
        .times(1)
        .returning(|_| true);

    let mut f = fc.new_udp_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy), UdpStatus::Continue);
}

#[test]
fn a_short_datagram_obeys_require_ppv2_like_every_other_parse_failure() {
    // It used to be dropped unconditionally, so with require_ppv2 off a 10-byte
    // datagram died while a 20-byte non-PPv2 one passed. Same input, both flags.
    let runt: &'static [u8] = b"\x0d\x0a\x0d\x0a\x00\x0d";

    let strict = udp_config(ULA);
    let mut envoy = MockEnvoyUdpListenerFilter::new();
    envoy
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(runt)], runt.len()));
    envoy.expect_set_datagram_data().never();
    let mut f = strict.new_udp_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy), UdpStatus::StopIteration);

    let lax = udp_config("ula fd00:dead:beef::/48\nrequire_ppv2 false\n");
    let mut envoy2 = MockEnvoyUdpListenerFilter::new();
    envoy2
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(runt)], runt.len()));
    envoy2.expect_set_datagram_data().never();
    let mut f2 = lax.new_udp_listener_filter(&mut envoy2);
    assert_eq!(f2.on_data(&mut envoy2), UdpStatus::Continue);
}

#[test]
fn an_empty_allowlist_denies_a_well_formed_tenant() {
    // Security-group semantics all the way through the filter, not just the set.
    let dg = leak(build(
        V2_PROXY,
        0x12,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    ));
    let fc = udp_config(ULA);
    let mut envoy = MockEnvoyUdpListenerFilter::new();
    envoy
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(dg)], dg.len()));
    envoy.expect_set_datagram_data().never();

    let mut f = fc.new_udp_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy), UdpStatus::StopIteration);
}

// --- auth ------------------------------------------------------------------

/// The TLS chain: `ppv2` already labelled the socket, tls_inspector already set the
/// SNI, so `auth` reads both back and needs no bytes of its own.
fn labelled(addr: &'static str, sni: &'static [u8]) -> MockEnvoyListenerFilter {
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_remote_address()
        .returning(move || Some((addr.to_string(), 40000)));
    envoy
        .expect_get_requested_server_name()
        .returning(move || Some(EnvoyBuffer::new(sni)));
    envoy
}

const SCOPED: &str = "sni l7.mgmt.test\nallow fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128\n";

#[test]
fn auth_admits_a_listed_identity_on_a_matching_sni() {
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:6e3d:cfdb", b"l7.mgmt.test");
    envoy.expect_continue_filter_chain().never();

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::Continue);
    // No bytes wanted: Envoy skips on_data entirely.
    assert_eq!(f.max_read_bytes(&mut envoy), 0);
}

#[test]
fn auth_denies_an_sni_that_no_scope_claims() {
    // The headline rule: no match is a deny, even for an otherwise valid tenant.
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:6e3d:cfdb", b"other.mgmt.test");
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn auth_denies_an_unlisted_identity_on_a_matching_sni() {
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:ffff:ffff:ffff:ffff", b"l7.mgmt.test");
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn auth_denies_when_there_is_no_sni_at_all() {
    // A plaintext connection, or tls_inspector missing from the chain. Fail closed.
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:6e3d:cfdb", b"");
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn auth_denies_when_no_preceding_filter_labelled_the_socket() {
    // Without a `ppv2` filter ahead of it there is no identity to judge.
    let fc = auth_config(SCOPED);
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy.expect_get_remote_address().returning(|| None);
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn auth_with_a_ula_parses_the_header_itself() {
    // The plain TCP chain: no preceding ppv2 filter, so auth does the whole job.
    let hdr = leak(build(
        V2_PROXY,
        0x11,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    ));
    let fc = auth_config(&format!("{ULA}{TENANT}"));
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(hdr)));
    envoy.expect_get_requested_server_name().returning(|| None);
    envoy.expect_set_remote_address().returning(|_, _, _| true);
    envoy.expect_drain_buffer().returning(|_| ());
    envoy.expect_continue_filter_chain().never();

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
    assert_eq!(f.on_data(&mut envoy, hdr.len()), TcpStatus::Continue);
}
