//! The two filters, against the SDK's mock Envoy.
//!
//! These are the files that actually decide whether traffic is admitted, and
//! they had no tests: every case here is an enforcement path, not a parse.

mod common;

use common::{build, V2_PROXY};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use ppv2_auth::{config, tcp, udp};
use std::sync::Arc;

use abi::envoy_dynamic_module_type_on_listener_filter_status as TcpStatus;
use abi::envoy_dynamic_module_type_on_udp_listener_filter_status as UdpStatus;

const ULA: &str = r#""ula":"fd00:dead:beef::/48""#;
/// sha256("vpce-0123456789abcdef0")[..4] plus the client 10.0.1.28 -- see tests/identity.rs.
const TENANT: &str = r#""allow":["fd00:dead:beef:1:7b53:e75b:a00:11c/128"]"#;

fn ppv2_config(text: &str) -> tcp::Ppv2Config {
    tcp::Ppv2Config::labelling(
        Arc::new(config::parse(text).unwrap()),
        tcp::Counters::default(),
    )
}

fn ppv2_auth_config(text: &str) -> tcp::Ppv2Config {
    tcp::Ppv2Config::enforcing(
        Arc::new(config::parse(text).unwrap()),
        tcp::Counters::default(),
    )
}

fn auth_config(text: &str) -> tcp::AuthConfig {
    tcp::AuthConfig {
        cfg: Arc::new(config::parse(text).unwrap()),
        counters: tcp::Counters::default(),
    }
}

fn udp_config(text: &str) -> udp::Ppv2AuthConfig {
    udp::Ppv2AuthConfig {
        cfg: Arc::new(config::parse(text).unwrap()),
        counters: udp::Counters::default(),
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
    let fc = ppv2_config(&format!("{{{ULA}}}"));
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(|| Some(EnvoyBuffer::new(b"GET ")));
    // The actual reject mechanism, and it must fire exactly once.
    envoy
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
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
fn non_ppv2_traffic_is_refused_unconditionally() {
    // There is no require_ppv2 knob any more: this module is the first thing
    // after the NLB, so a client without a header reached the listener directly.
    // Holds for the label-only filter too, not just the enforcing one.
    for fc in [
        ppv2_config(&format!("{{{ULA}}}")),
        ppv2_auth_config(&format!("{{{ULA}}}")),
    ] {
        let mut envoy = MockEnvoyListenerFilter::new();
        envoy
            .expect_get_buffer_chunk()
            .returning(|| Some(EnvoyBuffer::new(b"GET / HTTP/1.1\r\n\r\n")));
        envoy
            .expect_set_downstream_transport_failure_reason()
            .returning(|_| ());
        envoy
            .expect_continue_filter_chain()
            .withf(|success| !success)
            .times(1)
            .returning(|_| ());

        let mut f = fc.new_listener_filter(&mut envoy);
        assert_eq!(f.on_data(&mut envoy, 18), TcpStatus::StopIteration);
    }
}

#[test]
fn ppv2_auth_enforces_the_flat_list_after_labelling() {
    // The `enforce` half of ppv2_auth: same parse and label as ppv2, then the
    // identity must be covered or the socket closes.
    let listed = leak(build(
        V2_PROXY,
        0x11,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    ));
    let unlisted = leak(build(
        V2_PROXY,
        0x11,
        &[10, 0, 1, 28],
        Some(b"vpce-somebody-else"),
    ));

    let fc = ppv2_auth_config(&format!("{{{ULA},{TENANT}}}"));
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(listed)));
    envoy.expect_set_remote_address().returning(|_, _, _| true);
    envoy
        .expect_set_dynamic_metadata_string()
        .returning(|_, _, _| ());
    envoy.expect_drain_buffer().returning(|_| ());
    envoy.expect_continue_filter_chain().never();
    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, listed.len()), TcpStatus::Continue);

    let fc = ppv2_auth_config(&format!("{{{ULA},{TENANT}}}"));
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(unlisted)));
    // Still labelled, attributed and stripped, so the access log shows what was
    // judged AND who it was -- a refused connection is the case where knowing
    // that matters most.
    envoy.expect_set_remote_address().returning(|_, _, _| true);
    envoy
        .expect_set_dynamic_metadata_string()
        .withf(|ns, key, value| {
            ns == "ppv2_auth"
                && match key {
                    "vpce_id" => value == "vpce-somebody-else",
                    "src" => value == "10.0.1.28",
                    _ => false,
                }
        })
        .times(2)
        .returning(|_, _, _| ());
    envoy.expect_drain_buffer().returning(|_| ());
    envoy
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());
    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(
        f.on_data(&mut envoy, unlisted.len()),
        TcpStatus::StopIteration
    );
}

#[test]
fn a_tenant_header_is_labelled_with_the_synthesized_address_and_drained() {
    let hdr = leak(build(
        V2_PROXY,
        0x11,
        &[10, 0, 1, 28],
        Some(b"vpce-0123456789abcdef0"),
    ));
    let fc = ppv2_config(&format!("{{{ULA}}}"));
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(move || Some(EnvoyBuffer::new(hdr)));
    envoy
        .expect_set_remote_address()
        .withf(|addr, _port, is_ipv6| addr == "fd00:dead:beef:1:7b53:e75b:a00:11c" && *is_ipv6)
        .times(1)
        .returning(|_, _, _| true);
    // What the NLB attested, for the access log. The vpce-id is the TLV the load
    // balancer wrote, NOT the request header that used to be logged and was a
    // bypass -- and `src` is the tenant's own machine, which the identity may not
    // carry once a site matches by NAT prefix.
    envoy
        .expect_set_dynamic_metadata_string()
        .withf(|ns, key, value| {
            ns == "ppv2_auth"
                && match key {
                    "vpce_id" => value == "vpce-0123456789abcdef0",
                    "src" => value == "10.0.1.28",
                    _ => false,
                }
        })
        .times(2)
        .returning(|_, _, _| ());
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

    let fc = ppv2_config(&format!("{{{ULA}}}"));
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
    let fc = udp_config(&format!("{{{ULA},{TENANT}}}"));
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

    let fc = udp_config(&format!("{{{ULA},{TENANT}}}"));
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
fn non_ppv2_datagrams_are_dropped_unconditionally() {
    // Short, and well-formed-but-not-PPv2: both are just "no header", and a
    // datagram without a header reached the listener directly.
    for dg in [
        &b"\x0d\x0a\x0d\x0a\x00\x0d"[..],
        &b"GET / HTTP/1.1\r\n\r\n"[..],
    ] {
        let dg: &'static [u8] = Box::leak(dg.to_vec().into_boxed_slice());
        let fc = udp_config(&format!("{{{ULA}}}"));
        let mut envoy = MockEnvoyUdpListenerFilter::new();
        envoy
            .expect_get_datagram_data()
            .returning(move || (vec![EnvoyBuffer::new(dg)], dg.len()));
        envoy.expect_set_datagram_data().never();
        let mut f = fc.new_udp_listener_filter(&mut envoy);
        assert_eq!(f.on_data(&mut envoy), UdpStatus::StopIteration);
    }
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
    let fc = udp_config(&format!("{{{ULA}}}"));
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

const SCOPED: &str =
    r#"{"scopes":[{"sni":["l7.mgmt.test"],"allow":["fd00:dead:beef:1:7b53:e75b:a00:11c/128"]}]}"#;

#[test]
fn auth_admits_a_listed_identity_on_a_matching_sni() {
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:a00:11c", b"l7.mgmt.test");
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
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:a00:11c", b"other.mgmt.test");
    envoy
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
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
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
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
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:a00:11c", b"");
    envoy
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
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
        .expect_set_downstream_transport_failure_reason()
        .returning(|_| ());
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn auth_never_reads_bytes() {
    // The scopes filter decides everything in on_accept; max_read_bytes 0 makes
    // Envoy bypass on_data entirely.
    let fc = auth_config(SCOPED);
    let mut envoy = labelled("fd00:dead:beef:1:7b53:e75b:a00:11c", b"l7.mgmt.test");
    envoy.expect_continue_filter_chain().never();
    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::Continue);
    assert_eq!(f.max_read_bytes(&mut envoy), 0);
}

// --- observability -----------------------------------------------------------

#[test]
fn refusals_carry_a_failure_reason_and_bump_the_denied_counter() {
    // The reason is the only "why" the listener access log gets; the counter is
    // the only signal at all on UDP. Underscore tokens, because the formatter
    // folds spaces to underscores anyway (stream_info_formatter.cc:2289).
    let fc = tcp::AuthConfig {
        cfg: Arc::new(config::parse(SCOPED).unwrap()),
        counters: tcp::Counters {
            denied: Some(EnvoyCounterId(7)),
            ..Default::default()
        },
    };
    let mut envoy = labelled("fd00:dead:beef:1:ffff::1", b"l7.mgmt.test");
    envoy
        .expect_set_downstream_transport_failure_reason()
        .withf(|r| r == "denied_by_allowlist")
        .times(1)
        .returning(|_| ());
    envoy
        .expect_increment_counter()
        .withf(|id, n| id.0 == 7 && *n == 1)
        .times(1)
        .returning(|_, _| Ok(()));
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_accept(&mut envoy), TcpStatus::StopIteration);
}

#[test]
fn non_ppv2_refusal_says_so_and_counts_separately() {
    let fc = tcp::Ppv2Config::enforcing(
        Arc::new(config::parse(&format!("{{{ULA}}}")).unwrap()),
        tcp::Counters {
            not_ppv2: Some(EnvoyCounterId(9)),
            ..Default::default()
        },
    );
    let mut envoy = MockEnvoyListenerFilter::new();
    envoy
        .expect_get_buffer_chunk()
        .returning(|| Some(EnvoyBuffer::new(b"GET / HTTP/1.1\r\n\r\n")));
    envoy
        .expect_set_downstream_transport_failure_reason()
        .withf(|r| r == "not_proxy_protocol")
        .times(1)
        .returning(|_| ());
    envoy
        .expect_increment_counter()
        .withf(|id, n| id.0 == 9 && *n == 1)
        .times(1)
        .returning(|_, _| Ok(()));
    envoy
        .expect_continue_filter_chain()
        .withf(|success| !success)
        .times(1)
        .returning(|_| ());

    let mut f = fc.new_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy, 18), TcpStatus::StopIteration);
}

#[test]
fn udp_denials_bump_the_only_signal_udp_has() {
    // No session, no access log, no failure reason on UDP -- the counter is it.
    let dg = leak(build(
        V2_PROXY,
        0x12,
        &[10, 0, 1, 28],
        Some(b"vpce-somebody-else"),
    ));
    let fc = udp::Ppv2AuthConfig {
        cfg: Arc::new(config::parse(&format!("{{{ULA},{TENANT}}}")).unwrap()),
        counters: udp::Counters {
            denied: Some(EnvoyCounterId(3)),
            ..Default::default()
        },
    };
    let mut envoy = MockEnvoyUdpListenerFilter::new();
    envoy
        .expect_get_datagram_data()
        .returning(move || (vec![EnvoyBuffer::new(dg)], dg.len()));
    envoy
        .expect_increment_counter()
        .withf(|id, n| id.0 == 3 && *n == 1)
        .times(1)
        .returning(|_, _| Ok(()));
    envoy.expect_set_datagram_data().never();

    let mut f = fc.new_udp_listener_filter(&mut envoy);
    assert_eq!(f.on_data(&mut envoy), UdpStatus::StopIteration);
}

#[test]
fn counter_names_are_prefixed_with_the_filter_name() {
    // All filters on a listener share one metrics_namespace (default
    // dynamicmodulescustom), so unprefixed names from ppv2 and auth on the same
    // TLS listener would merge into a single meaningless stat.
    let mut names = Vec::new();
    let c = ppv2_auth::stats::Counters::register("auth", |n| {
        names.push(n.to_string());
        None
    });
    assert_eq!(names, ["auth_allowed", "auth_denied", "auth_not_ppv2"]);
    assert!(c.allowed.is_none() && c.denied.is_none() && c.not_ppv2.is_none());
}
