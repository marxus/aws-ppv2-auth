//! Turning a PROXY protocol header into an IPv6 address that policy can match.
//! See README for why. ONE ULA holds all three cases, told apart by the kind in
//! group 4 -- the invariant is that everything inside the /48 was synthesized
//! here and everything outside it is a real client address.
//!
//! ```text
//! fd0b:1003:5ec0 : 0b1a : 0000 : 0007 : 0a00:011c   KIND_SITE, an onboarded tenant
//! fd0b:1003:5ec0 : 0001 : 7b53:e75b   : 0a00:011c   KIND_VPCE, a tenant no site claims
//! fd0b:1003:5ec0 : 0004 : 0000:0000   : 0a00:011c   KIND_ADDR, no vpce-id at all
//! └── /48 ULA ──┘  └kind┘  └ body ───┘  client IPv4
//! ```
//!
//! 0xb1a spells "via" the way tailscale's own 4via6 range does, and the site sits
//! in group 6 where tailscale keeps it -- so a site address is the same SHAPE as
//! a 4via6 address without being one. It deliberately is not: 4via6 translation
//! is keyed to tailscale's own prefix inside the client, so an address here is an
//! identity and never a route. Routes stay tailscale's; identity is ours.
//!
//! The kind-1 hash is 32 bits rather than 64. It only ever labels STRANGERS now
//! -- an onboarded tenant has an allocated site -- and a mined collision costs
//! ~2^32 endpoint creations, so the width buys nothing next to carrying the
//! address that says WHICH machine called.

use crate::cidr;
use crate::ppv2;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

/// An onboarded tenant. 0xb1a spells "via" the way tailscale's own range does,
/// and it is a KIND here rather than a second prefix -- one /48 holds all three.
pub const KIND_SITE: u16 = 0x0b1a;
/// The quarantine site: a source two sites claim resolves HERE, not to either
/// claimant -- trust is revoked until the contest is fixed, but the traffic stays
/// nameable ("!0" in a group admits it for examination) instead of silently
/// riding as somebody. Not declarable in `sites`; only contests mint it.
pub const SITE_CONTESTED: u16 = 0;
pub const KIND_VPCE: u16 = 1;
pub const KIND_ADDR: u16 = 4;

/// The /48 ULA prefix: per RFC 4193, `fd` + 40 random bits, generated once.
pub type Prefix = [u8; 6];

/// One onboarded tenant: the identifiers that resolve to it, and the id they resolve to.
#[derive(Debug)]
pub struct Site {
    pub id: u16,
    /// Exact `vpce-id` matches. AWS-assigned, so a tenant cannot choose one.
    pub vpce: Vec<Box<[u8]>>,
    /// Source prefixes, IPv4 held as ::ffff:a.b.c.d so one Set covers both families.
    pub cidrs: cidr::Set,
}

/// What a header is encoded against, plus the flat indices site matching runs on.
/// Built ONCE at config load (Scheme::new); the per-connection path never touches
/// the per-site structures.
#[derive(Debug)]
pub struct Scheme {
    pub prefix: Prefix,
    /// The parse artifact, kept for inspection; matching uses the indices below.
    /// Empty means nothing is onboarded, so every header falls to kind 1 or 4.
    pub sites: Vec<Site>,
    /// vpce bytes -> site id. O(1); a label two sites list resolves to site 0.
    vpce_index: HashMap<Box<[u8]>, u16>,
    /// All sites' ranges flattened DISJOINT: overlaps split at boundaries, a
    /// segment with one claimant keeps its id and a contested one gets site 0,
    /// adjacent same-id merged. One binary search per lookup, whatever the count.
    segments: Vec<(u128, u128, u16)>,
}

impl Scheme {
    pub fn new(prefix: Prefix, mut sites: Vec<Site>) -> Scheme {
        // Sorted for deterministic warnings; contests resolve to site 0 either way.
        sites.sort_unstable_by_key(|s| s.id);

        let mut vpce_index: HashMap<Box<[u8]>, u16> = HashMap::new();
        for site in &sites {
            for v in &site.vpce {
                match vpce_index.entry(v.clone()) {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(site.id);
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        // Same site twice is harmless; a second site is a contest.
                        if *e.get() != site.id && *e.get() != SITE_CONTESTED {
                            eprintln!(
                                "ppv2-auth: sites {} and {} both list {:?}; the label resolves to site 0 until fixed",
                                e.get(),
                                site.id,
                                String::from_utf8_lossy(v),
                            );
                            e.insert(SITE_CONTESTED);
                        }
                    }
                }
            }
        }

        // Sweep: a range opens at start and closes AFTER end; the winner over any
        // stretch is the lowest active id. end == MAX never closes (no +1 exists).
        let mut events: Vec<(u128, bool, u16)> = Vec::new();
        for site in &sites {
            for (start, end) in site.cidrs.ranges() {
                events.push((start, true, site.id));
                if end < u128::MAX {
                    events.push((end + 1, false, site.id));
                }
            }
        }
        events.sort_unstable();

        let mut segments: Vec<(u128, u128, u16)> = Vec::new();
        let mut active: BTreeMap<u16, u32> = BTreeMap::new();
        let mut cur_start = 0u128;
        let mut cur_id: Option<u16> = None;
        let mut i = 0;
        while i < events.len() {
            let pos = events[i].0;
            if let Some(id) = cur_id {
                if pos > cur_start {
                    segments.push((cur_start, pos - 1, id));
                }
            }
            while i < events.len() && events[i].0 == pos {
                let (_, open, id) = events[i];
                if open {
                    *active.entry(id).or_insert(0) += 1;
                } else if let Some(c) = active.get_mut(&id) {
                    *c -= 1;
                    if *c == 0 {
                        active.remove(&id);
                    }
                }
                i += 1;
            }
            // One claimant is a site; two or more is a CONTEST, and a contest
            // resolves to site 0 -- nobody's privileges, everybody's visibility.
            cur_id = match active.len() {
                0 => None,
                1 => active.keys().next().copied(),
                _ => {
                    let claimants: Vec<String> =
                        active.keys().map(|id| id.to_string()).collect();
                    eprintln!(
                        "ppv2-auth: sites {} contest addresses from {}; the range resolves to site 0 until fixed",
                        claimants.join(", "),
                        Ipv6Addr::from(pos.to_be_bytes()),
                    );
                    Some(SITE_CONTESTED)
                }
            };
            cur_start = pos;
        }
        if let Some(id) = cur_id {
            segments.push((cur_start, u128::MAX, id));
        }
        // Merge same-id neighbours the winner-change emission split needlessly.
        let mut merged: Vec<(u128, u128, u16)> = Vec::with_capacity(segments.len());
        for seg in segments {
            match merged.last_mut() {
                Some(last) if last.2 == seg.2 && last.1.wrapping_add(1) == seg.0 => last.1 = seg.1,
                _ => merged.push(seg),
            }
        }

        Scheme {
            prefix,
            sites,
            vpce_index,
            segments: merged,
        }
    }

    /// The site whose space this address synthesizes into. One binary search.
    fn addr_site(&self, addr: u128) -> Option<u16> {
        let i = self.segments.partition_point(|s| s.0 <= addr);
        (i > 0 && addr <= self.segments[i - 1].1).then(|| self.segments[i - 1].2)
    }

    /// The site owning EVERY address in [start, end] -- None on mixed or partial
    /// ownership, because no single encoding would match what the wire does.
    /// Adjacent same-id segments are merged, so one segment must cover it all.
    fn range_site(&self, start: u128, end: u128) -> Option<u16> {
        let i = self.segments.partition_point(|s| s.0 <= start);
        (i > 0 && end <= self.segments[i - 1].1).then(|| self.segments[i - 1].2)
    }

    fn label_site(&self, label: &[u8]) -> Option<u16> {
        self.vpce_index.get(label).copied()
    }
}

/// A resolved site, and whether the header's source is the tenant's OWN address.
struct SiteMatch {
    id: u16,
    inner: bool,
}

/// IPv4 as ::ffff:a.b.c.d, so site prefixes of both families live in one cidr::Set.
fn mapped(h: &ppv2::Header) -> u128 {
    if h.is_v6 {
        return to_u128(h.src);
    }
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&h.src[..4]);
    to_u128(out)
}

/// vpce-id first: an AWS-assigned id outranks an address the sender chose.
///
/// A vpce match means the source is the tenant's own machine -- measured, the NLB
/// reports the consumer-side 5-tuple through an endpoint. A CIDR match means it is
/// a NAT in front of them, which is not an address in their space, so `inner` is
/// false and the low 32 bits stay zero.
///
/// One hash lookup + one binary search, whatever the site count -- this runs per
/// datagram on UDP, so it must not be linear over sites. Contested sources are
/// baked to site 0 in the indices at load.
fn site_of(scheme: &Scheme, h: &ppv2::Header) -> Option<SiteMatch> {
    if !h.vpce.is_empty() {
        if let Some(id) = scheme.label_site(h.vpce) {
            return Some(SiteMatch { id, inner: true });
        }
    }
    scheme
        .addr_site(mapped(h))
        .map(|id| SiteMatch { id, inner: false })
}

/// Four cases, and the order matters.
pub fn synthesize(scheme: &Scheme, h: &ppv2::Header) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&scheme.prefix);

    // An onboarded tenant: kind b1a, then the site, then the machine.
    if let Some(m) = site_of(scheme, h) {
        out[6..8].copy_from_slice(&KIND_SITE.to_be_bytes());
        out[10..12].copy_from_slice(&m.id.to_be_bytes());
        // Zero unless the source is the tenant's own address: <via>:0:<site>:: reads
        // as "this tenant, machine unknown" and stays inside the tenant's own /96.
        if m.inner && !h.is_v6 {
            out[12..16].copy_from_slice(&h.src[..4]);
        }
        return out;
    }

    // A vpce-id is not an address, so give it one.
    if !h.vpce.is_empty() {
        out[6..8].copy_from_slice(&KIND_VPCE.to_be_bytes());
        let digest = Sha256::digest(h.vpce);
        out[8..12].copy_from_slice(&digest[..4]);
        // The tenant's own machine, same as the site space. Zero for a v6 client.
        if !h.is_v6 {
            out[12..16].copy_from_slice(&h.src[..4]);
        }
        return out;
    }

    // Pass-through keeps kind 4 purely IPv4 -- 2000::/3 read as IPv4 used to collide with real rules.
    if h.is_v6 {
        return h.src;
    }

    // Low 32 bits, so a v4 /N becomes a v6 /(96+N).
    out[6..8].copy_from_slice(&KIND_ADDR.to_be_bytes());
    out[12..16].copy_from_slice(&h.src[..4]);
    out
}

/// RFC 5952 text via std's formatter, in a stack buffer -- no `to_string()` heap alloc.
pub struct AddrText {
    buf: [u8; 46],
    len: usize,
}

impl AddrText {
    pub fn as_str(&self) -> &str {
        // The formatter only ever writes ASCII hex digits, ':' and '.'.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl std::fmt::Write for AddrText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        if end > self.buf.len() {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub fn format(addr: [u8; 16]) -> AddrText {
    use std::fmt::Write;
    let mut t = AddrText {
        buf: [0u8; 46],
        len: 0,
    };
    // Infallible: 46 bytes always suffices.
    let _ = write!(t, "{}", Ipv6Addr::from(addr));
    t
}

/// The raw header source, for the log. IPv4 as dotted quad, not ::ffff: form --
/// what is wanted here is what the tenant's own machine calls itself.
pub fn format_src(src: [u8; 16], is_v6: bool) -> AddrText {
    use std::fmt::Write;
    let mut t = AddrText {
        buf: [0u8; 46],
        len: 0,
    };
    if is_v6 {
        let _ = write!(t, "{}", Ipv6Addr::from(src));
    } else {
        let _ = write!(t, "{}", Ipv4Addr::new(src[0], src[1], src[2], src[3]));
    }
    t
}

pub fn to_u128(addr: [u8; 16]) -> u128 {
    u128::from_be_bytes(addr)
}

pub fn parse_prefix(text: &str) -> Result<Prefix, &'static str> {
    let (ip_text, bits) = match text.split_once('/') {
        Some((ip, b)) => (ip, Some(b.parse::<u8>().map_err(|_| "bad prefix length")?)),
        None => (text, None),
    };
    let ip: Ipv6Addr = ip_text.parse().map_err(|_| "bad IPv6 address")?;
    if let Some(b) = bits {
        if b != 48 {
            return Err("prefix must be /48");
        }
    }
    let o = ip.octets();
    if o[0] & 0xfe != 0xfc {
        return Err("not unique-local");
    }
    // Only the first 6 bytes are kept, so lower bits would vanish silently.
    if o[6..].iter().any(|&b| b != 0) {
        return Err("prefix has bits set below /48");
    }
    let mut p = [0u8; 6];
    p.copy_from_slice(&o[..6]);
    Ok(p)
}

/// Config-time twin of `synthesize`: encode one authored source exactly the way
/// the packet path encodes a header carrying it, so the two meet by construction.
/// Site table first, mirroring site_of:
///
///   !N          -> site N's space, /96 (whatever its sources are, even none yet)
///   site-owned  -> that site's space, /96 -- a label a site lists, or an address
///                  range CONTAINED in a site's cidrs (lowest id wins; partial
///                  overlap does not count, split the range or use !N)
///   ipv6_cidr   -> itself          ipv6 -> /128
///   ipv4[/N]    -> kind-4 lift, /(96+N)
///   label       -> kind-1 hash of the whole string, /96
///
/// TOTAL over strings, like the wire: a label is anything that is not a valid
/// address or a valid !site -- "10.0.0.1/99", "!x", "fd00::1/129" included --
/// because the packet side hashes the vpce bytes verbatim and this must land on
/// the same address. The one refusal is a source with no `scheme` to encode into.
pub fn encode_member(scheme: Option<&Scheme>, member: &str) -> Result<String, String> {
    let need = || -> Result<&Scheme, String> {
        scheme.ok_or_else(|| format!("{member:?} needs `ula` to encode"))
    };

    // A site ref resolves only against a DECLARED site -- "!5" with no site 5 is
    // an unresolvable ref, and everything unresolvable is a label, same as
    // "@ghost". A site declared later (watch-fed) re-renders the config and the
    // ref resolves then. "!0" always resolves: the quarantine space is
    // system-owned, minted by contests rather than declared, and a group like
    // `unknown-site: ["!0"]` is how contested traffic is admitted for examination.
    if let Some(id) = member.strip_prefix('!').and_then(|t| t.parse::<u16>().ok()) {
        let sch = need()?;
        if id == SITE_CONTESTED || sch.sites.iter().any(|s| s.id == id) {
            return Ok(site_space(&sch.prefix, id));
        }
    }

    let (addr_text, width) = match member.split_once('/') {
        Some((a, w)) => (a, Some(w)),
        None => (member, None),
    };
    // Absent defaults to max; invalid returns None, demoting the member to a label.
    let bits = |max: u8| -> Option<u8> {
        match width {
            None => Some(max),
            Some(w) => w.parse::<u8>().ok().filter(|b| *b <= max),
        }
    };

    if let (Ok(v4), Some(b)) = (addr_text.parse::<Ipv4Addr>(), bits(32)) {
        let sch = need()?;
        // Mapped form, because that is how site cidrs hold v4.
        let base = 0xffff_0000_0000u128 | u32::from_be_bytes(v4.octets()) as u128;
        let (start, end) = range_of(base, 96 + b);
        if let Some(id) = sch.range_site(start, end) {
            return Ok(site_space(&sch.prefix, id));
        }
        let mut out = [0u8; 16];
        out[..6].copy_from_slice(&sch.prefix);
        out[6..8].copy_from_slice(&KIND_ADDR.to_be_bytes());
        out[12..16].copy_from_slice(&v4.octets());
        return Ok(std::format!("{}/{}", format(out).as_str(), 96 + b as u32));
    }
    if let (Ok(v6), Some(b)) = (addr_text.parse::<Ipv6Addr>(), bits(128)) {
        // v6 passes through UNLESS a site claims the range -- the wire labels
        // those connections with the site space, so the config must too.
        if let Some(sch) = scheme {
            let (start, end) = range_of(to_u128(v6.octets()), b);
            if let Some(id) = sch.range_site(start, end) {
                return Ok(site_space(&sch.prefix, id));
            }
        }
        return Ok(std::format!("{v6}/{b}"));
    }

    let sch = need()?;
    if let Some(id) = sch.label_site(member.as_bytes()) {
        return Ok(site_space(&sch.prefix, id));
    }
    let digest = Sha256::digest(member.as_bytes());
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&sch.prefix);
    out[6..8].copy_from_slice(&KIND_VPCE.to_be_bytes());
    out[8..12].copy_from_slice(&digest[..4]);
    Ok(std::format!("{}/96", format(out).as_str()))
}

/// The whole tenant: kind SITE, the id in group 6, machine bits open -- /96.
fn site_space(prefix: &Prefix, id: u16) -> String {
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(prefix);
    out[6..8].copy_from_slice(&KIND_SITE.to_be_bytes());
    out[10..12].copy_from_slice(&id.to_be_bytes());
    std::format!("{}/96", format(out).as_str())
}

/// The inclusive range a prefix covers.
fn range_of(addr: u128, bits: u8) -> (u128, u128) {
    if bits == 0 {
        return (0, u128::MAX);
    }
    let mask: u128 = u128::MAX << (128 - bits as u32);
    (addr & mask, (addr & mask) | !mask)
}
