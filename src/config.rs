//! filter_config, shared by both filters.
//!
//! Written as a `google.protobuf.Struct`, which Envoy serializes to JSON before
//! handing it over (`MessageUtil::knownAnyToBytes`, utility.h:460). Structured
//! rather than a string blob so separate CRs can contribute scopes with a JSON
//! Patch append -- see README.
//!
//! ```yaml
//! filter_config:
//!   "@type": type.googleapis.com/google.protobuf.Struct
//!   value:
//!     scopes:
//!       - sni: [l7.mgmt.test, "*.pass.mgmt.test"]
//!         allow: [fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128]
//! ```
//!
//! A scope may name several hostnames sharing one list -- the shape Envoy's
//! ServerNameMatcher uses, where one `domains` list maps to one action.
//!
//! Each filter_name takes exactly one shape -- see the validators in lib.rs:
//! `ppv2` and `ppv2_auth` take `ula` (they parse the header themselves, before
//! tls_inspector), `auth` takes `scopes` (it runs after, reading the label a
//! `ppv2` filter left).
//!
//! Deny by default, with no knobs. Traffic without a PPv2 header reached the
//! listener directly and is refused; an identity nothing covers is refused. There
//! is deliberately no `enforce` or `require_ppv2` flag -- the filter_name already
//! says what happens, and a flag derived from config contents would make the safe
//! state mean allow-any.

use crate::{cidr, identity};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct Config {
    /// Present iff this filter parses PPv2 itself; `auth` has none and reads the label.
    pub scheme: Option<identity::Scheme>,
    /// Used when `scopes` is absent.
    pub allow: cidr::Set,
    /// None = flat-list mode. Some([]) = SNI mode, nothing claimed, deny all -- the appendable base state.
    pub scopes: Option<Vec<Scope>>,
}

/// Several hostnames sharing one allowlist.
#[derive(Debug)]
pub struct Scope {
    pub names: Vec<Pattern>,
    pub allow: cidr::Set,
}

/// One `sni` entry, lowercased; `*.foo.com` is `Suffix("foo.com")` per domain_matcher.h:264.
#[derive(Debug, PartialEq, Eq)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
}

impl Pattern {
    fn parse(text: &str) -> Pattern {
        let lower = text.to_ascii_lowercase();
        // Only a whole leading `*.` is a wildcard (domain_matcher.h:225); `foo.*` etc. stay Exact and never match.
        match lower.strip_prefix("*.") {
            Some(rest) if !rest.is_empty() => Pattern::Suffix(rest.to_string()),
            _ => Pattern::Exact(lower),
        }
    }
}

/// Byte-wise fold-compare: unlike domain_matcher.h we fold BOTH sides, so a mixed-case config still matches.
fn eq_fold(pat: &str, sni: &[u8]) -> bool {
    pat.len() == sni.len()
        && pat
            .bytes()
            .zip(sni.iter())
            .all(|(p, s)| p == s.to_ascii_lowercase())
}

impl Config {
    /// Deny by default: false unless a list covers this identity.
    pub fn permits(&self, sni: &[u8], addr: u128) -> bool {
        self.allowlist_for(sni)
            .is_some_and(|set| set.contains(addr))
    }

    /// Flat-list judgment via `permits`, so stray scopes deny instead of being ignored.
    pub fn permits_unscoped(&self, addr: u128) -> bool {
        self.permits(b"", addr)
    }

    /// ServerNameMatcher order (domain_matcher.h:78-101): exact, then wildcards longest-suffix-first.
    fn allowlist_for(&self, sni: &[u8]) -> Option<&cidr::Set> {
        let Some(scopes) = &self.scopes else {
            return Some(&self.allow);
        };
        // Empty SNI claims nothing, per domain_matcher.h:74-76.
        if sni.is_empty() {
            return None;
        }

        for s in scopes {
            if s.names
                .iter()
                .any(|p| matches!(p, Pattern::Exact(e) if eq_fold(e, sni)))
            {
                return Some(&s.allow);
            }
        }
        let mut rest = sni;
        while let Some(i) = rest.iter().position(|&b| b == b'.') {
            rest = &rest[i + 1..];
            for s in scopes {
                if s.names
                    .iter()
                    .any(|p| matches!(p, Pattern::Suffix(x) if eq_fold(x, rest)))
                {
                    return Some(&s.allow);
                }
            }
        }
        None
    }
}

// --- the JSON shape --------------------------------------------------------

/// deny_unknown_fields: a typo fails the config instead of silently disabling enforcement.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    ula: Option<String>,
    /// The tenant table: an id, and the vpce-ids and source prefixes that resolve to it.
    ///
    /// A LIST OF OBJECTS, not a map keyed by id, and that is a constraint from the
    /// generator rather than a preference: CEL can build a list from a
    /// comprehension but not a map, so a ConfigMap of id -> text can be reshaped
    /// into this and not into the other.
    #[serde(default)]
    sites: Vec<RawSite>,
    #[serde(default)]
    allow: Vec<String>,
    scopes: Option<Vec<RawScope>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSite {
    id: u16,
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

fn build(list: &[String]) -> Result<cidr::Set, String> {
    cidr::build_from(list.iter().map(|s| s.as_str())).map_err(str::to_string)
}

/// A site member is a vpce-id or a source prefix, told apart the way the CRs do it:
/// try to read it as an address, and treat what is left as an opaque id.
///
/// IPv4 becomes ::ffff:a.b.c.d/(96+N) so one cidr::Set covers both families --
/// cidr::build parses IPv6 only, and it requires an explicit width, so a bare
/// address is normalized to /128 rather than rejected.
fn classify(member: &str) -> Result<Option<String>, String> {
    let (addr, width) = match member.split_once('/') {
        Some((a, w)) => (
            a,
            Some(
                w.parse::<u8>()
                    .map_err(|_| format!("bad prefix length in site member {member:?}"))?,
            ),
        ),
        None => (member, None),
    };
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        let bits = width.unwrap_or(32);
        if bits > 32 {
            return Err(format!("prefix length above /32 in site member {member:?}"));
        }
        return Ok(Some(format!("::ffff:{v4}/{}", 96 + bits)));
    }
    if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        return Ok(Some(format!("{v6}/{}", width.unwrap_or(128))));
    }
    // Not an address, so it is an endpoint id.
    Ok(None)
}

fn build_sites(raw: Vec<RawSite>) -> Result<Vec<identity::Site>, String> {
    let mut seen: Vec<u16> = Vec::new();
    raw.into_iter()
        .map(|site| {
            // 0 is not reserved for anything, but tailscale renders it as the bare
            // prefix, which reads as "no site" -- so refuse it rather than emit it.
            if site.id == 0 {
                return Err("site 0 is not usable: it renders as the bare via prefix".to_string());
            }
            // Two entries for one id would make which members apply depend on order.
            if seen.contains(&site.id) {
                return Err(format!("site {} appears twice", site.id));
            }
            seen.push(site.id);

            let mut vpce = Vec::new();
            let mut prefixes = Vec::new();
            // Trimmed and empties dropped: the generator splits a text block, so a
            // trailing newline would otherwise become a member named "".
            for m in site
                .members
                .iter()
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
            {
                match classify(m)? {
                    Some(cidr_text) => prefixes.push(cidr_text),
                    None => vpce.push(m.as_bytes().to_vec().into_boxed_slice()),
                }
            }
            Ok(identity::Site {
                id: site.id,
                vpce,
                cidrs: build(&prefixes)?,
            })
        })
        .collect()
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;

    // `via` and `sites` belong to whoever owns `ula`: they only matter to a filter
    // that parses the header itself, and the validators enforce that.
    let scheme = match &raw.ula {
        Some(u) => Some(identity::Scheme {
            prefix: identity::parse_prefix(u).map_err(str::to_string)?,
            sites: build_sites(raw.sites)?,
        }),
        None => {
            if !raw.sites.is_empty() {
                return Err("`sites` needs `ula`; it describes how a header is encoded".to_string());
            }
            None
        }
    };
    let allow = build(&raw.allow)?;
    let scopes = match raw.scopes {
        None => None,
        Some(list) => Some(
            list.into_iter()
                .map(|s| {
                    Ok(Scope {
                        names: s.sni.iter().map(|n| Pattern::parse(n)).collect(),
                        allow: build(&s.allow)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        ),
    };

    Ok(Config {
        scheme,
        allow,
        scopes,
    })
}
