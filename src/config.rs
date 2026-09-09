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
//! `allow` entries (flat or scoped) may be `@group` references into `groups`, a
//! list of named source bags that may themselves nest via `@refs` -- see graph.rs
//! for the walk rules and identity::encode_member for how each source becomes a
//! CIDR. Expansion happens at parse; the running filter holds plain cidr::Sets
//! and the packet path is unchanged.
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

use crate::{cidr, graph, identity};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct Config {
    /// Present iff the config carries `ula`. The header-parsing filters need it to
    /// synthesize; `auth` may carry one purely so its members can encode, and its
    /// filter path never reads this.
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
    /// Named source bags for `@refs` in `allow` and `scopes[].allow`. A member is
    /// any source (encode_member's grammar) or `@other-group`; expansion happens
    /// here at parse, so the running filter still holds plain cidr::Sets. May sit
    /// unreferenced -- that is the appendable base state, same as an empty
    /// `scopes`. A LIST OF OBJECTS like `sites`, and for the same reason: CEL can
    /// build a list from a comprehension but not a map.
    #[serde(default)]
    groups: Vec<RawGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    name: String,
    #[serde(default)]
    members: Vec<String>,
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

/// `@refs` expand through the graph first (unknown refs contribute nothing --
/// see graph.rs); every literal that comes out is then encoded the way the
/// packet path encodes a header carrying it (identity::encode_member), so an
/// allow entry and the wire meet on the same address by construction.
fn build(
    list: &[String],
    groups: &graph::Graph,
    prefix: Option<&identity::Prefix>,
) -> Result<cidr::Set, String> {
    let encoded = groups
        .resolve(list)
        .into_iter()
        .map(|m| identity::encode_member(prefix, m))
        .collect::<Result<Vec<_>, String>>()?;
    cidr::build_from(encoded.iter().map(String::as_str)).map_err(str::to_string)
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
                // No graph here: site members are classifier inputs, not allowlists, and `@x` classifies as a vpce-id long before this.
                cidrs: cidr::build_from(prefixes.iter().map(|s| s.as_str()))
                    .map_err(str::to_string)?,
            })
        })
        .collect()
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;

    // The prefix serves two masters: packet-time synthesis (scheme) and
    // config-time member encoding (build). `auth` may carry a `ula` for the
    // second alone -- its filter path never reads scheme.
    let prefix = match &raw.ula {
        Some(u) => Some(identity::parse_prefix(u).map_err(str::to_string)?),
        None => None,
    };
    let scheme = match prefix {
        Some(p) => Some(identity::Scheme {
            prefix: p,
            sites: build_sites(raw.sites)?,
        }),
        None => {
            if !raw.sites.is_empty() {
                return Err("`sites` needs `ula`; it describes how a header is encoded".to_string());
            }
            None
        }
    };
    // Literals are encoded NOW, referenced or not -- otherwise a bad member hides
    // in an unreferenced group until some later tenant append references it, and
    // fails THAT config. The graph itself accepts any shape; see graph.rs, and a
    // name appearing twice is last-wins, upsert semantics.
    let mut groups = graph::Graph::default();
    for g in raw.groups {
        for m in g.members.iter().filter(|m| !m.starts_with('@')) {
            identity::encode_member(prefix.as_ref(), m)
                .map_err(|e| format!("group {:?}: {e}", g.name))?;
        }
        groups.upsert(g.name, g.members);
    }

    let allow = build(&raw.allow, &groups, prefix.as_ref())?;
    let scopes = match raw.scopes {
        None => None,
        Some(list) => Some(
            list.into_iter()
                .map(|s| {
                    Ok(Scope {
                        names: s.sni.iter().map(|n| Pattern::parse(n)).collect(),
                        allow: build(&s.allow, &groups, prefix.as_ref())?,
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
