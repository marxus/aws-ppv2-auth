//! Pure-logic benchmark: 112-byte PrivateLink header, 10,000-entry allowlist,
//! worst-case lookup (last entry).
use aws_ppv2_identity::{cidr, identity, ppv2 as pp};
use std::time::Instant;

const PREFIX: identity::Prefix = [0xfd, 0x2a, 0x5c, 0x1b, 0x7e, 0x90];

fn pl_header() -> Vec<u8> {
    let vpce = b"vpce-028ff61de1d1fea8c";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[10, 0, 1, 28, 10, 1, 2, 67, 0x9c, 0x40, 0x00, 0x50]);
    body.extend_from_slice(&[0x03, 0x00, 0x04, 0, 0, 0, 0]); // CRC32C
    body.push(pp::TLV_AWS);
    body.extend_from_slice(&((1 + vpce.len()) as u16).to_be_bytes());
    body.push(pp::AWS_SUBTYPE_VPCE_ID);
    body.extend_from_slice(vpce);
    let pad = 112 - 16 - body.len() - 3;
    body.push(0x04);
    body.extend_from_slice(&(pad as u16).to_be_bytes());
    body.resize(body.len() + pad, 0u8);

    let mut out = Vec::new();
    out.extend_from_slice(&pp::SIGNATURE);
    out.push(0x21);
    out.push(0x11);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn bench(name: &str, iters: u64, mut f: impl FnMut(u64) -> u64) {
    let mut best = u64::MAX;
    let mut sink = 0u64;
    for _ in 0..3 {
        let t = Instant::now();
        sink = sink.wrapping_add(f(iters));
        let el = t.elapsed().as_nanos() as u64;
        best = best.min(el);
    }
    println!("  {:<26} {:>10.2} ns/op", name, best as f64 / iters as f64);
    std::hint::black_box(sink);
}

fn main() {
    let hdr = pl_header();
    println!("header = {} bytes", hdr.len());

    let mut list = String::new();
    for i in 0..10_000u32 {
        list.push_str(&format!(
            "fd2a:5c1b:7e90:1:0:0:{:x}:{:x}/128,",
            i >> 16,
            i & 0xffff
        ));
    }

    let mut best = u64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let s = cidr::build(&list).unwrap();
        best = best.min(t.elapsed().as_nanos() as u64);
        std::hint::black_box(s.len());
    }
    println!("  {:<26} {:>10.2} ns/op", "BuildSet10k", best as f64);

    let set = cidr::build(&list).unwrap();
    let key = identity::to_u128(
        "fd2a:5c1b:7e90:1:0:0:0:270f"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert!(set.contains(key), "worst-case key must be present");

    bench("Parse", 50_000_000, |n| {
        let mut s = 0u64;
        for _ in 0..n {
            s = s.wrapping_add(pp::parse(&hdr).unwrap().vpce.len() as u64);
        }
        s
    });
    bench("ParseAndSynthesize", 20_000_000, |n| {
        let mut s = 0u64;
        for _ in 0..n {
            let h = pp::parse(&hdr).unwrap();
            s = s.wrapping_add(identity::synthesize(PREFIX, &h)[15] as u64);
        }
        s
    });
    bench("Lookup10k", 50_000_000, |n| {
        let mut s = 0u64;
        for _ in 0..n {
            s = s.wrapping_add(set.contains(key) as u64);
        }
        s
    });
    // Deny path: a real internet address sits outside the allowlist's span, so
    // this measures the short circuit rather than the search.
    let outside = identity::to_u128(
        "2a05:d014:10da:7800::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert!(!set.contains(outside));
    bench("Lookup10kDeny", 50_000_000, |n| {
        let mut s = 0u64;
        for _ in 0..n {
            s = s.wrapping_add(set.contains(outside) as u64);
        }
        s
    });
    bench("FullPath", 20_000_000, |n| {
        let mut s = 0u64;
        for _ in 0..n {
            let h = pp::parse(&hdr).unwrap();
            let a = identity::synthesize(PREFIX, &h);
            s = s.wrapping_add(identity::format(a).as_str().len() as u64);
        }
        s
    });
}
