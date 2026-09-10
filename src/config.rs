//! Two config shapes, one identity table.
//!
//! Written as a `google.protobuf.Struct`, which Envoy serializes to JSON before
//! handing it over (`MessageUtil::knownAnyToBytes`, utility.h:460).
//!
//! The TABLE -- ula, sites, groups -- rides exactly once per pod, on a `table`
//! filter parked on a listener nothing routes. Every enforcing filter carries
//! RULES ONLY (`allow` or `scopes`) and expands them against the published table,
//! re-expanding whenever it moves. There is no self-contained mode: patching a
//! listener with an enforcing filter MEANS it consumes the table, and a rule
//! config carrying `ula`/`sites`/`groups` fails its listener loudly
//! (deny_unknown_fields). Before a carrier lands, everything denies.
//!
//! ```yaml
//! # the carrier                            # an enforcer
//! filter_config:                           filter_config:
//!   value:                                   value:
//!     ula: fd0b:1003:5ec0::/48                 allow: ["@tenant-a", "!2"]
//!     sites: { "1": [vpce-...] }
//!     groups: { tenant-a: ["!1"] }
//! ```
//!
//! A scope may name several hostnames sharing one list -- the shape Envoy's
//! ServerNameMatcher uses, where one `domains` list maps to one action.
//!
//! Rule entries are the source grammar -- CIDRs of either family, labels,
//! `@group` and `!site` refs -- see graph.rs for the walk and
//! identity::encode_member for how each source becomes a CIDR.
//!
//! Deny by default, with no knobs. Traffic without a PPv2 header reached the
//! listener directly and is refused; an identity nothing covers is refused; a
//! rule that cannot expand yet covers nothing. There is deliberately no
//! `enforce` or `require_ppv2` flag -- the filter_name already says what
//! happens. Unknown fields fail the config, so a typo cannot silently disable
//! enforcement.

use crate::{cidr, graph, identity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock, RwLock};

// --- the table ---------------------------------------------------------------

/// The identity table: how a header encodes (scheme) and what names mean
/// (groups). Parsed from a `table` carrier config, published process-wide.
#[derive(Debug)]
pub struct Table {
    pub scheme: identity::Scheme,
    pub groups: graph::Graph,
}

impl Table {
    /// Expand rule entries -- `@refs` walk the groups, then every literal is
    /// encoded the way the packet path encodes a header carrying it, so a rule
    /// and the wire meet on the same address by construction. `!*` is the one
    /// member that expands to many entries, so it lives here rather than in
    /// encode_member's one-in-one-out grammar.
    pub fn resolve(&self, list: &[String]) -> Result<cidr::Set, String> {
        let mut encoded: Vec<String> = Vec::new();
        for m in self.groups.resolve(list) {
            if m == "!*" {
                encoded.extend(identity::encode_all_sites(&self.scheme));
            } else {
                encoded.push(identity::encode_member(&self.scheme, m));
            }
        }
        cidr::build_from(encoded.iter().map(String::as_str)).map_err(str::to_string)
    }
}

/// The published table plus a generation, so consumers know when to re-expand.
/// None until a carrier lands: rules expand to nothing and everything denies.
static PUBLISHED: OnceLock<RwLock<(u64, Option<Arc<Table>>)>> = OnceLock::new();

fn published_cell() -> &'static RwLock<(u64, Option<Arc<Table>>)> {
    PUBLISHED.get_or_init(|| RwLock::new((0, None)))
}

/// Deliver a new table to every enforcing filter on this pod.
pub fn publish(table: Arc<Table>) {
    let mut w = published_cell().write().unwrap();
    w.0 += 1;
    w.1 = Some(table);
}

pub fn published() -> (u64, Option<Arc<Table>>) {
    let r = published_cell().read().unwrap();
    (r.0, r.1.clone())
}

// --- rules -------------------------------------------------------------------

/// An enforcing filter's config: raw rules and their expansion against the
/// published table, rebuilt when the table's generation moves.
#[derive(Debug)]
pub struct Config {
    raw_allow: Vec<String>,
    raw_scopes: Option<Vec<(Vec<Pattern>, Vec<String>)>>,
    cache: RwLock<(u64, Judged)>,
}

/// Rules expanded against one specific table -- the pure half of `permits`,
/// separated so tests can judge against a local table with no global state.
#[derive(Debug)]
pub struct Judged {
    pub allow: cidr::Set,
    /// None = flat-list mode. Some([]) = SNI mode, nothing claimed, deny all -- the appendable base state.
    pub scopes: Option<Vec<Scope>>,
}

impl Judged {
    fn deny_all(scoped: bool) -> Judged {
        Judged {
            allow: cidr::Set::default(),
            scopes: scoped.then(Vec::new),
        }
    }

    /// Deny by default: false unless a list covers this identity.
    pub fn permits(&self, sni: &[u8], addr: u128) -> bool {
        let set = match &self.scopes {
            None => Some(&self.allow),
            Some(list) => match_scopes(list, sni),
        };
        set.is_some_and(|s| s.contains(addr))
    }

    pub fn permits_unscoped(&self, addr: u128) -> bool {
        self.permits(b"", addr)
    }
}

/// Several hostnames sharing one allowlist.
#[derive(Debug)]
pub struct Scope {
    pub names: Vec<Pattern>,
    pub allow: cidr::Set,
}

/// One `sni` entry, lowercased; `*.foo.com` is `Suffix("foo.com")` per domain_matcher.h:264.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
}

impl Pattern {
    pub fn parse(text: &str) -> Pattern {
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

/// ServerNameMatcher order (domain_matcher.h:78-101): exact, then wildcards
/// longest-suffix-first.
///
/// DELIBERATE DIVERGENCE from domain_matcher.h:74-76, which makes empty SNI claim
/// nothing: here an absent SNI falls through to the exact loop, so a scope naming
/// `""` (Pattern::Exact("")) can claim the no-SNI lane -- a NON-SNI client (raw
/// TLS to an IP, some DB protocols) still needs an identity, but can be admitted
/// on purpose. It is NOT a wildcard: a present-but-unmatched SNI still denies
/// (the loops below miss it and return None), and `Exact("")` only ever matches a
/// zero-length name. No `""` scope => empty SNI still dies. Do not re-add the
/// short-circuit; it silently removes the ability to name the no-SNI lane.
pub fn match_scopes<'a>(scopes: &'a [Scope], sni: &[u8]) -> Option<&'a cidr::Set> {
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

impl Config {
    /// Deny by default, judged against the PUBLISHED table, re-expanding when it
    /// moves. Expansion failures log once per generation and leave deny-all --
    /// never a stale allow, never a crash.
    pub fn permits(&self, sni: &[u8], addr: u128) -> bool {
        let (gen, table) = published();
        if self.cache.read().unwrap().0 != gen {
            let mut w = self.cache.write().unwrap();
            // Another worker may have rebuilt while we waited for the lock.
            if w.0 != gen {
                w.1 = match &table {
                    Some(t) => self.judge_against(t).unwrap_or_else(|e| {
                        eprintln!("ppv2-auth: rules do not expand against the published table (gen {gen}): {e}; denying all");
                        Judged::deny_all(self.raw_scopes.is_some())
                    }),
                    None => Judged::deny_all(self.raw_scopes.is_some()),
                };
                w.0 = gen;
            }
        }
        self.cache.read().unwrap().1.permits(sni, addr)
    }

    pub fn permits_unscoped(&self, addr: u128) -> bool {
        self.permits(b"", addr)
    }

    /// The pure expansion -- `permits` uses it against the published table,
    /// tests use it against a local one.
    pub fn judge_against(&self, table: &Table) -> Result<Judged, String> {
        Ok(Judged {
            allow: table.resolve(&self.raw_allow)?,
            scopes: match &self.raw_scopes {
                None => None,
                Some(list) => Some(
                    list.iter()
                        .map(|(names, raw)| {
                            Ok(Scope {
                                names: names.clone(),
                                allow: table.resolve(raw)?,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                ),
            },
        })
    }

    // --- what the validators need to see ------------------------------------

    pub fn has_allow(&self) -> bool {
        !self.raw_allow.is_empty()
    }

    pub fn has_scopes(&self) -> bool {
        self.raw_scopes.is_some()
    }

    /// A scope with no `sni` can never match -- dead config.
    pub fn has_nameless_scope(&self) -> bool {
        self.raw_scopes
            .iter()
            .flatten()
            .any(|(names, _)| names.is_empty())
    }
}

// --- the JSON shapes ---------------------------------------------------------

/// deny_unknown_fields: a typo fails the config instead of silently disabling
/// enforcement -- and `ula`/`sites`/`groups` on an enforcing filter fail HERE,
/// because the table is the carrier's alone.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    #[serde(default)]
    allow: Vec<String>,
    scopes: Option<Vec<RawScope>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

/// The carrier's shape; `allow`/`scopes` fail here for the mirror reason.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    ula: String,
    /// The tenant table, keyed by site id -- a map like `groups`, and buildable
    /// the same way: CEL's transformMapEntry folds a CR collection into this
    /// shape. JSON keys are strings, so the id parses here; a key that is not
    /// 1-65535 fails the config (structure, not wire data -- no label fallback).
    #[serde(default)]
    sites: BTreeMap<String, Vec<String>>,
    /// Named source bags for `@refs`, keyed by group name. May sit unreferenced;
    /// literals are validated eagerly so a bad member cannot hide until some
    /// later tenant references the group.
    #[serde(default)]
    groups: BTreeMap<String, Vec<String>>,
}

/// A rules config: `allow` and/or `scopes`, nothing else.
pub fn parse(text: &str) -> Result<Config, String> {
    let raw: RawRules = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let raw_scopes = raw.scopes.map(|list| {
        list.into_iter()
            .map(|s| {
                (
                    s.sni.iter().map(|n| Pattern::parse(n)).collect::<Vec<_>>(),
                    s.allow,
                )
            })
            .collect::<Vec<_>>()
    });
    let scoped = raw_scopes.is_some();
    Ok(Config {
        raw_allow: raw.allow,
        raw_scopes,
        // Stale on arrival (no generation is u64::MAX), so the first connection
        // expands against whatever is published by then.
        cache: RwLock::new((u64::MAX, Judged::deny_all(scoped))),
    })
}

/// The carrier's config: the whole identity table, nothing else.
pub fn parse_table(text: &str) -> Result<Arc<Table>, String> {
    let raw: RawTable = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let prefix = identity::parse_prefix(&raw.ula).map_err(str::to_string)?;
    let scheme = identity::Scheme::new(prefix, build_sites(raw.sites)?);
    // Encoding is total (the table always has a scheme), so group members need no
    // eager validation any more -- whatever is authored lands somewhere lawful.
    let mut groups = graph::Graph::default();
    for (name, members) in raw.groups {
        groups.upsert(name, members);
    }
    Ok(Arc::new(Table { scheme, groups }))
}

/// A site source is a vpce-id or a source prefix, told apart the way the CRs do
/// it: try to read it as an address, and treat what is left as an opaque id.
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
                    .map_err(|_| format!("bad prefix length in site source {member:?}"))?,
            ),
        ),
        None => (member, None),
    };
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        let bits = width.unwrap_or(32);
        if bits > 32 {
            return Err(format!("prefix length above /32 in site source {member:?}"));
        }
        return Ok(Some(format!("::ffff:{v4}/{}", 96 + bits)));
    }
    if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        return Ok(Some(format!("{v6}/{}", width.unwrap_or(128))));
    }
    // Not an address, so it is an endpoint id.
    Ok(None)
}

fn build_sites(raw: BTreeMap<String, Vec<String>>) -> Result<Vec<identity::Site>, String> {
    // No ordering promise -- Scheme::new sorts and bakes the contested tiebreak
    // into its indices.
    raw.into_iter()
        .map(|(key, sources)| {
            // Site 0 is the system's: contested sources resolve there (identity.rs
            // SITE_CONTESTED), so no tenant may declare it.
            let id = key
                .parse::<u16>()
                .ok()
                .filter(|id| *id != 0)
                .ok_or_else(|| format!("site key {key:?} is not 1-65535"))?;

            let mut vpce = Vec::new();
            let mut prefixes = Vec::new();
            // Trimmed and empties dropped: a generator splitting a text block would
            // otherwise turn a trailing newline into a source named "".
            for m in sources.iter().map(|m| m.trim()).filter(|m| !m.is_empty()) {
                // Sources, not members: classifier inputs only. `@refs` are not
                // followed -- an @-string is an opaque byte pattern here.
                match classify(m)? {
                    Some(cidr_text) => prefixes.push(cidr_text),
                    None => vpce.push(m.as_bytes().to_vec().into_boxed_slice()),
                }
            }
            Ok(identity::Site {
                id,
                vpce,
                cidrs: cidr::build_from(prefixes.iter().map(|s| s.as_str()))
                    .map_err(str::to_string)?,
            })
        })
        .collect()
}
