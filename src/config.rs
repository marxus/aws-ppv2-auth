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
//! map of named source bags that may themselves nest via `@refs` -- see graph.rs
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
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Debug)]
pub struct Config {
    /// The identity table -- ula, sites, groups -- INTERNED per process: every
    /// filter on this pod whose table content is identical shares one Arc, one
    /// parse, one set of match indices. allow/scopes below are the listener's
    /// own concern and stay per-filter.
    pub table: Arc<Table>,
    /// Used when `scopes` is absent.
    pub allow: cidr::Set,
    /// None = flat-list mode. Some([]) = SNI mode, nothing claimed, deny all -- the appendable base state.
    pub scopes: Option<Vec<Scope>>,
}

/// What every listener shares: how a header encodes (scheme) and what names mean
/// (groups). Content-addressed -- see `intern`.
#[derive(Debug)]
pub struct Table {
    /// Present iff the config carries `ula`. The header-parsing filters need it to
    /// synthesize; `auth` may carry one purely so its members can encode, and its
    /// filter path never reads this.
    pub scheme: Option<identity::Scheme>,
    pub groups: graph::Graph,
}

impl Config {
    pub fn scheme(&self) -> Option<&identity::Scheme> {
        self.table.scheme.as_ref()
    }
}

/// The per-process table registry. Weak so a table lives exactly as long as some
/// listener's config holds it; dead entries are pruned on insert. Keyed by the
/// canonical JSON of (ula, sites, groups) -- BTreeMaps serialize sorted, so equal
/// content is equal text.
static TABLES: OnceLock<Mutex<HashMap<String, Weak<Table>>>> = OnceLock::new();

fn intern(key: String, build: impl FnOnce() -> Result<Table, String>) -> Result<Arc<Table>, String> {
    let mut reg = TABLES.get_or_init(Default::default).lock().unwrap();
    if let Some(t) = reg.get(&key).and_then(Weak::upgrade) {
        return Ok(t);
    }
    // Built under the lock: config load is rare, and this stops two listeners
    // racing to build the same table twice.
    let t = Arc::new(build()?);
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(key, Arc::downgrade(&t));
    Ok(t)
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
    /// The tenant table, keyed by site id: the vpce-ids and source prefixes that
    /// resolve to each. A map like `groups`, and buildable the same way -- CEL's
    /// transformMapEntry folds a CR collection into this shape. JSON keys are
    /// strings, so the id parses here; a key that is not 1-65535 fails the config
    /// (this is structure, not wire data -- no label fallback for table keys).
    #[serde(default)]
    sites: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    allow: Vec<String>,
    scopes: Option<Vec<RawScope>>,
    /// Named source bags for `@refs` in `allow` and `scopes[].allow`, keyed by
    /// group name. A member is any source (encode_member's grammar) or
    /// `@other-group`; expansion happens here at parse, so the running filter
    /// still holds plain cidr::Sets. May sit unreferenced -- that is the
    /// appendable base state, same as an empty `scopes`. A map rather than a list
    /// like `sites`: CEL's transformMapEntry folds a CR collection into exactly
    /// this shape, dynamic keys included.
    #[serde(default)]
    groups: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

/// `@refs` expand through the graph first (an unknown ref falls through as a
/// label -- see graph.rs); every literal that comes out is then encoded the way
/// the packet path encodes a header carrying it (identity::encode_member), so an
/// allow entry and the wire meet on the same address by construction.
fn build(list: &[String], table: &Table) -> Result<cidr::Set, String> {
    let (groups, scheme) = (&table.groups, table.scheme.as_ref());
    let mut encoded: Vec<String> = Vec::new();
    for m in groups.resolve(list) {
        // The one member that expands to MANY entries, so it lives here in the
        // expansion rather than in encode_member's one-in-one-out grammar.
        if m == "!*" {
            let sch = scheme.ok_or_else(|| "\"!*\" needs `ula` to encode".to_string())?;
            encoded.extend(identity::encode_all_sites(sch));
        } else {
            encoded.push(identity::encode_member(scheme, m)?);
        }
    }
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

fn build_sites(raw: BTreeMap<String, Vec<String>>) -> Result<Vec<identity::Site>, String> {
    let sites = raw
        .into_iter()
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
        .collect::<Result<Vec<_>, String>>()?;
    // No ordering promise here -- Scheme::new sorts and bakes lowest-id-wins into
    // its indices, one tiebreak applied identically at packet and config time.
    Ok(sites)
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;

    // The table's identity is its content; allow/scopes are excluded on purpose.
    let key = serde_json::to_string(&(&raw.ula, &raw.sites, &raw.groups))
        .map_err(|e| e.to_string())?;
    let (ula, raw_sites, raw_groups) = (raw.ula, raw.sites, raw.groups);
    let table = intern(key, move || {
        // The prefix serves two masters: packet-time synthesis (scheme) and
        // config-time member encoding (build). `auth` may carry a `ula` for the
        // second alone -- its filter path never reads scheme.
        let scheme = match &ula {
            Some(u) => {
                let p = identity::parse_prefix(u).map_err(str::to_string)?;
                Some(identity::Scheme::new(p, build_sites(raw_sites)?))
            }
            None => {
                if !raw_sites.is_empty() {
                    return Err(
                        "`sites` needs `ula`; it describes how a header is encoded".to_string()
                    );
                }
                None
            }
        };
        // Literals are encoded NOW, referenced or not -- otherwise a bad member
        // hides in an unreferenced group until some later tenant append references
        // it, and fails THAT config. The graph accepts any shape; see graph.rs.
        let mut groups = graph::Graph::default();
        for (name, members) in raw_groups {
            for m in members.iter().filter(|m| !m.starts_with('@')) {
                identity::encode_member(scheme.as_ref(), m)
                    .map_err(|e| format!("group {name:?}: {e}"))?;
            }
            groups.upsert(name, members);
        }
        Ok(Table { scheme, groups })
    })?;

    let allow = build(&raw.allow, &table)?;
    let scopes = match raw.scopes {
        None => None,
        Some(list) => Some(
            list.into_iter()
                .map(|s| {
                    Ok(Scope {
                        names: s.sni.iter().map(|n| Pattern::parse(n)).collect(),
                        allow: build(&s.allow, &table)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        ),
    };

    Ok(Config {
        table,
        allow,
        scopes,
    })
}
