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
    /// parse, one set of match indices. A SLIM config (no ula, no sites, no
    /// groups) pins the empty table and reads the PUBLISHED one instead -- see
    /// `publish`; its rules re-expand lazily whenever the published table moves.
    pub table: Arc<Table>,
    /// Used when `scopes` is absent. The pinned expansion; a slim config keeps
    /// this empty and judges through its cache.
    pub allow: cidr::Set,
    /// None = flat-list mode. Some([]) = SNI mode, nothing claimed, deny all -- the appendable base state.
    pub scopes: Option<Vec<Scope>>,
    /// Some = subscriber: rules kept raw, expanded against the published table.
    slim: Option<Slim>,
}

/// The raw rules of a slim config plus their expansion, rebuilt when the
/// published table's generation moves. Deny-safe at every stage: before any
/// table is published the empty table expands @refs to nothing and refuses
/// sources that need encoding (logged, empty set, deny-all).
#[derive(Debug)]
struct Slim {
    raw_allow: Vec<String>,
    raw_scopes: Option<Vec<(Vec<Pattern>, Vec<String>)>>,
    cache: std::sync::RwLock<Expanded>,
}

#[derive(Debug)]
struct Expanded {
    gen: u64,
    allow: cidr::Set,
    scopes: Option<Vec<Scope>>,
}

/// The process-published table: what a `table` carrier filter last delivered.
/// Starts empty (generation 0), so slim consumers deny until a carrier lands.
static PUBLISHED: OnceLock<std::sync::RwLock<(u64, Arc<Table>)>> = OnceLock::new();

fn published_cell() -> &'static std::sync::RwLock<(u64, Arc<Table>)> {
    PUBLISHED.get_or_init(|| {
        std::sync::RwLock::new((
            0,
            Arc::new(Table {
                scheme: None,
                groups: graph::Graph::default(),
            }),
        ))
    })
}

/// Deliver a new table to every slim consumer on this pod. Same Arc twice is a
/// no-op -- interning makes an unchanged carrier config hit exactly that.
pub fn publish(table: Arc<Table>) {
    let mut w = published_cell().write().unwrap();
    if !Arc::ptr_eq(&w.1, &table) {
        w.0 += 1;
        w.1 = table;
    }
}

pub fn published() -> (u64, Arc<Table>) {
    let r = published_cell().read().unwrap();
    (r.0, r.1.clone())
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
    /// The PINNED scheme -- what this config itself carried. A slim config
    /// answers None here; its per-connection scheme comes from `table_now`.
    pub fn scheme(&self) -> Option<&identity::Scheme> {
        self.table.scheme.as_ref()
    }

    /// True when this config carried its own identity table (any of ula, sites,
    /// groups); false = slim, fed by the published table.
    pub fn carries_table(&self) -> bool {
        self.slim.is_none()
    }

    /// A scope with no `sni` can never match -- dead config, checked by
    /// validate_auth in BOTH modes (a slim config's Scope structs do not exist
    /// until expansion, so the pinned `scopes` field cannot answer this).
    pub fn has_nameless_scope(&self) -> bool {
        match &self.slim {
            None => self
                .scopes
                .iter()
                .flatten()
                .any(|scope| scope.names.is_empty()),
            Some(slim) => slim
                .raw_scopes
                .iter()
                .flatten()
                .any(|(names, _)| names.is_empty()),
        }
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        match &self.slim {
            None => allowlist_for(&self.allow, &self.scopes, sni).is_some_and(|set| set.contains(addr)),
            Some(slim) => {
                slim.refresh(self);
                let cache = slim.cache.read().unwrap();
                allowlist_for(&cache.allow, &cache.scopes, sni).is_some_and(|set| set.contains(addr))
            }
        }
    }

    /// Flat-list judgment via `permits`, so stray scopes deny instead of being ignored.
    pub fn permits_unscoped(&self, addr: u128) -> bool {
        self.permits(b"", addr)
    }

    /// The table this connection should encode against: the pinned one, or for a
    /// slim config whatever is currently published. An Arc clone, so the borrow
    /// never blocks the publisher.
    pub fn table_now(&self) -> Arc<Table> {
        match &self.slim {
            None => self.table.clone(),
            Some(_) => published().1,
        }
    }
}

impl Slim {
    /// Re-expand if the published table moved. Expansion failures (a source that
    /// needs encoding before any carrier delivered a ula) log once per generation
    /// and leave DENY-ALL -- never a stale allow.
    fn refresh(&self, _cfg: &Config) {
        let (gen, table) = published();
        if self.cache.read().unwrap().gen == gen {
            return;
        }
        let mut w = self.cache.write().unwrap();
        if w.gen == gen {
            return; // another worker already rebuilt
        }
        let allow = build(&self.raw_allow, &table).unwrap_or_else(|e| {
            eprintln!("ppv2-auth: allow does not expand against the published table (gen {gen}): {e}; denying all");
            cidr::build("").unwrap()
        });
        let scopes = self.raw_scopes.as_ref().map(|list| {
            list.iter()
                .map(|(names, raw)| Scope {
                    names: names.clone(),
                    allow: build(raw, &table).unwrap_or_else(|e| {
                        eprintln!("ppv2-auth: scope does not expand against the published table (gen {gen}): {e}; denying scope");
                        cidr::build("").unwrap()
                    }),
                })
                .collect()
        });
        *w = Expanded { gen, allow, scopes };
    }
}

/// ServerNameMatcher order (domain_matcher.h:78-101): exact, then wildcards longest-suffix-first.
fn allowlist_for<'a>(
    allow: &'a cidr::Set,
    scopes: &'a Option<Vec<Scope>>,
    sni: &[u8],
) -> Option<&'a cidr::Set> {
    {
        let Some(scopes) = scopes else {
            return Some(allow);
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
    /// EXPLICIT opt-in to the published table: the config carries rules only and
    /// re-expands them whenever a `table` carrier publishes. Explicit, never
    /// inferred from a missing `ula` -- a forgotten field must stay a loud parse
    /// error, not a silent deny-all subscriber.
    #[serde(default)]
    subscribe: bool,
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

    // A subscriber carries rules only; mixing in table fields would make it
    // ambiguous whose table applies, so that is refused outright.
    if raw.subscribe && (raw.ula.is_some() || !raw.sites.is_empty() || !raw.groups.is_empty()) {
        return Err(
            "`subscribe` means the table comes from the `table` carrier; drop `ula`/`sites`/`groups`"
                .to_string(),
        );
    }
    let slim_mode = raw.subscribe;

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

    if slim_mode {
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
        let slim = Slim {
            raw_allow: raw.allow,
            raw_scopes,
            // Stale on arrival (no generation is u64::MAX), so the first
            // connection expands against whatever is published by then.
            cache: std::sync::RwLock::new(Expanded {
                gen: u64::MAX,
                allow: cidr::build("").map_err(str::to_string)?,
                scopes: None,
            }),
        };
        return Ok(Config {
            table,
            allow: cidr::build("").map_err(str::to_string)?,
            scopes: slim.raw_scopes.as_ref().map(|_| Vec::new()),
            slim: Some(slim),
        });
    }

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
        slim: None,
    })
}
