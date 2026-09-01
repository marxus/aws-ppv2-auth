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

// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str) -> u128 {
        u128::from_be_bytes(t.parse::<Ipv6Addr>().unwrap().octets())
    }

    #[test]
    fn membership_boundaries_and_gaps() {
        let s = build("fd2a:5c1b:7e90:1::/64, fd2a:5c1b:7e90:4::12c7:0/112").unwrap();
        assert!(s.contains(p("fd2a:5c1b:7e90:1::1"))); // in /64
        assert!(s.contains(p("fd2a:5c1b:7e90:1:ffff:ffff:ffff:ffff"))); // last of /64
        assert!(!s.contains(p("fd2a:5c1b:7e90:2::1"))); // next /64 out
        assert!(s.contains(p("fd2a:5c1b:7e90:4::12c7:e6a1"))); // in /112
        assert!(!s.contains(p("fd2a:5c1b:7e90:4::a00:11c"))); // outside /112
        assert!(!s.contains(p("fd00:dead::1"))); // unrelated
    }

    #[test]
    fn single_host_slash_128_and_slash_0_edges() {
        let s = build("fd2a:5c1b:7e90:1::1/128").unwrap();
        assert!(s.contains(p("fd2a:5c1b:7e90:1::1")));
        assert!(!s.contains(p("fd2a:5c1b:7e90:1::2")));
        assert!(!s.contains(p("fd2a:5c1b:7e90:1::0")));

        let all = build("::/0").unwrap();
        assert!(all.contains(p("2a05:d014::1")));
        assert!(all.contains(0));
        assert!(all.contains(u128::MAX));
    }

    #[test]
    fn overlaps_collapse() {
        let s = build("fd00::/16, fd00:1::/32, fd00:2::/32").unwrap(); // all inside /16
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn an_empty_list_denies_everything() {
        // Security-group semantics: allowed iff a rule covers it. No rules means
        // nothing is permitted. See config.rs for why there is no enforce flag.
        let s = build("").unwrap();
        assert!(s.is_empty());
        assert!(!s.contains(p("fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a")));
    }

    #[test]
    fn ten_thousand_unique_slash_128_host_addresses() {
        let mut list = String::new();
        for i in 0..10_000u32 {
            list.push_str(&format!(
                "fd2a:5c1b:7e90:1:0:0:{:x}:{:x}/128,",
                i >> 16,
                i & 0xffff
            ));
        }
        let s = build(&list).unwrap();
        assert_eq!(s.len(), 10_000);

        let hit = p("fd2a:5c1b:7e90:1:0:0:0:1388");
        assert!(s.contains(hit));
        // NB: entries here are sequential, so hit^1 is the NEXT entry, not a
        // miss. Flip a high bit to land outside the populated block.
        assert!(!s.contains(hit ^ (1u128 << 100)));
        assert!(!s.contains(p("fe80::1")));
    }

    #[test]
    fn malformed_entries_fail_the_build() {
        // A typo must fail the config rather than silently shrinking the
        // allowlist, which under deny-by-default would lock tenants out with no
        // other symptom.
        assert!(build("fd00::/16, notanaddress/64").is_err());
        assert!(build("fd00::/999").is_err());
        assert!(build("fd00::1").is_err()); // no prefix length
    }
}
