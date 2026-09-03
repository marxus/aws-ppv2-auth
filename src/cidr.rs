//! IPv6 CIDR allowlist. Merged disjoint ranges plus a binary search, which is
//! enough because an allowlist needs "inside ANY range", not longest-prefix-wins.
//!
//! (start, end) adjacent rather than two parallel Vecs: splitting them measured
//! no faster and costs a second cache line on the bounds check.

use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy)]
struct Range {
    start: u128,
    end: u128,
}

#[derive(Debug, Default)]
pub struct Set {
    ranges: Vec<Range>,
    /// First start and last end. Empty set is (MAX, 0), which nothing satisfies.
    span: (u128, u128),
}

impl Set {
    /// Last range whose start <= addr, then one bounds check -- disjoint+sorted, so at most one can contain it.
    pub fn contains(&self, addr: u128) -> bool {
        // O(1) on the deny path, the one an attacker controls (19.0 -> 0.3 ns measured).
        if addr < self.span.0 || addr > self.span.1 {
            return false;
        }
        let i = self.ranges.partition_point(|r| r.start <= addr);
        i > 0 && addr <= self.ranges[i - 1].end
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// IPv6 only. Returns the inclusive range the prefix covers.
fn parse_cidr(text: &str) -> Result<Range, &'static str> {
    let (ip_text, bits_text) = text.split_once('/').ok_or("missing prefix length")?;
    let ip: Ipv6Addr = ip_text.parse().map_err(|_| "bad IPv6 address")?;
    let bits: u32 = bits_text.parse().map_err(|_| "bad prefix length")?;
    if bits > 128 {
        return Err("prefix length above 128");
    }

    let base = u128::from_be_bytes(ip.octets());
    // Shifting a u128 by 128 is undefined, so handle /0 explicitly.
    let mask: u128 = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    Ok(Range {
        start: base & mask,
        end: (base & mask) | !mask,
    })
}

/// Comma/whitespace separated CIDRs.
pub fn build(list: &str) -> Result<Set, &'static str> {
    build_from(std::iter::once(list))
}

/// The same, taking one string per `allow` entry -- no join-then-resplit.
pub fn build_from<'a>(lists: impl Iterator<Item = &'a str>) -> Result<Set, &'static str> {
    let mut raw: Vec<Range> = Vec::new();
    for list in lists {
        for tok in list.split([',', ' ', '\t', '\r', '\n']) {
            if tok.is_empty() {
                continue;
            }
            raw.push(parse_cidr(tok)?);
        }
    }
    raw.sort_unstable_by_key(|r| r.start);

    // Overlaps collapse; adjacent ranges deliberately do not -- the `+ 1` overflows at u128::MAX.
    let mut ranges: Vec<Range> = Vec::with_capacity(raw.len());
    for r in raw {
        match ranges.last_mut() {
            Some(last) if r.start <= last.end => {
                if r.end > last.end {
                    last.end = r.end;
                }
            }
            _ => ranges.push(r),
        }
    }
    // (MAX, 0) for an empty set, so `contains` short-circuits to false.
    let span = match (ranges.first(), ranges.last()) {
        (Some(f), Some(l)) => (f.start, l.end),
        _ => (u128::MAX, 0),
    };
    Ok(Set { ranges, span })
}
