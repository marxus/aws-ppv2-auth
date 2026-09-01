//! IPv6 CIDR allowlist sized for SecurityPolicy-scale rule counts.
//!
//! Envoy's RBAC uses an LC-trie for clientCIDRs. This does the equivalent with
//! merged disjoint ranges plus a binary search, which is simpler and is enough
//! because an allowlist only needs "is this address inside ANY range", not
//! longest-prefix-wins. Overlaps are collapsed at config time, so lookup is
//! O(log n) with no tree to walk and no per-lookup allocation.
//!
//! Ranges are stored as (start, end) pairs in one Vec rather than two parallel
//! Vecs: the binary search reads `start` and then the matching `end`, so keeping
//! them adjacent costs one cache line instead of two.

use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy)]
struct Range {
    start: u128,
    end: u128,
}

#[derive(Debug, Default)]
pub struct Set {
    ranges: Vec<Range>,
}

impl Set {
    /// Binary search for the last range whose start <= addr, then one bounds
    /// check. Ranges are disjoint and sorted, so at most one can contain addr.
    pub fn contains(&self, addr: u128) -> bool {
        let mut lo = 0usize;
        let mut hi = self.ranges.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.ranges[mid].start <= addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo > 0 && addr <= self.ranges[lo - 1].end
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Parses "addr/len" (IPv6 only). Returns the inclusive range it covers.
fn parse_cidr(text: &str) -> Result<Range, &'static str> {
    let (ip_text, bits_text) = text.split_once('/').ok_or("missing prefix length")?;
    let ip: Ipv6Addr = ip_text.parse().map_err(|_| "bad IPv6 address")?;
    let bits: u32 = bits_text.parse().map_err(|_| "bad prefix length")?;
    if bits > 128 {
        return Err("prefix length above 128");
    }

    let base = u128::from_be_bytes(ip.octets());
    // Shifting a u128 by 128 is undefined; handle the /0 edge explicitly.
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

/// Builds the set once, at config load. Comma/whitespace separated CIDRs.
pub fn build(list: &str) -> Result<Set, &'static str> {
    let mut raw: Vec<Range> = Vec::new();
    for tok in list.split([',', ' ', '\t', '\r', '\n']) {
        if tok.is_empty() {
            continue;
        }
        raw.push(parse_cidr(tok)?);
    }
    raw.sort_unstable_by_key(|r| r.start);

    // Collapse overlapping ranges so lookup is a single bounds check. Adjacent
    // but non-overlapping ranges are deliberately NOT merged -- it would save
    // one entry and cost a `+ 1` that can overflow at u128::MAX.
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
    Ok(Set { ranges })
}
