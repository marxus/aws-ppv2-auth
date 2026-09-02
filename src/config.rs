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
//! `ula` and `scopes` are the two ways `auth` can learn an identity and are
//! mutually exclusive -- see validate_auth in lib.rs. `ula` means it runs before
//! tls_inspector and parses the header itself; `scopes` means it runs after, and a
//! `ppv2` filter already labelled the socket.
//!
//! Deny by default. No scope matches the SNI, or none covers the identity, and the
//! connection is closed -- which is why there is no `enforce` flag: deriving one
//! from "is the list non-empty" would make the safe state mean allow-any.

use crate::{cidr, identity};
use serde::Deserialize;

#[derive(Debug)]
pub struct Config {
    /// Present when this filter derives identity itself by parsing PPv2. Absent on
    /// the `auth` filter of a TLS chain, where `ppv2` already labelled the socket.
    pub prefix: Option<identity::Prefix>,
    /// Used when `scopes` is absent.
    pub allow: cidr::Set,
    /// `None` is "not SNI mode". `Some([])` is SNI mode with nothing claimed yet,
    /// which denies everything -- the state a base config ships in so tenant CRs
    /// have a `scopes` array to append to.
    pub scopes: Option<Vec<Scope>>,
    /// Drop anything without a PROXY header.
    pub require_ppv2: bool,
}

/// Several hostnames sharing one allowlist.
#[derive(Debug)]
pub struct Scope {
    pub names: Vec<Pattern>,
    pub allow: cidr::Set,
}

/// One `sni` entry, stored ASCII-lowercased.
///
/// `Suffix` holds the hostname with `*.` already stripped, so `*.foo.com` becomes
/// `Suffix("foo.com")` -- the shape domain_matcher.h:264-267 uses.
#[derive(Debug, PartialEq, Eq)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
}

impl Pattern {
    fn parse(text: &str) -> Pattern {
        let lower = text.to_ascii_lowercase();
        // Only a whole leading `*.` is a wildcard (domain_matcher.h:225). Anything
        // else -- `foo.*`, `*bla.com` -- stays Exact, so it never matches a real SNI
        // rather than failing the config. Erring toward deny, not toward allow.
        match lower.strip_prefix("*.") {
            Some(rest) if !rest.is_empty() => Pattern::Suffix(rest.to_string()),
            _ => Pattern::Exact(lower),
        }
    }
}

/// Compare a lowercased pattern against raw SNI bytes, folding as we go.
///
/// Envoy's own domain_matcher never folds its config, so a pattern written
/// `L7.Mgmt.Test` silently never matches there -- the SNI always arrives lowercased
/// from the socket. We fold both sides. SNI is ASCII by spec, so this needs no
/// allocation and no UTF-8 check.
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

    /// The list this connection is judged against, or None if no scope claims it.
    ///
    /// Envoy's ServerNameMatcher order (domain_matcher.h:78-101): exact first, then
    /// wildcards longest-suffix-first. The walk consumes through each dot, so the
    /// loop variable IS the next candidate -- `a.b.foo.com` probes `b.foo.com`,
    /// then `foo.com`, then `com`.
    fn allowlist_for(&self, sni: &[u8]) -> Option<&cidr::Set> {
        let Some(scopes) = &self.scopes else {
            return Some(&self.allow);
        };
        // Empty SNI claims nothing, per domain_matcher.h:74-76.
        if sni.is_empty() {
            return None;
        }

        let find = |f: &dyn Fn(&Pattern) -> bool| {
            scopes
                .iter()
                .find(|s| s.names.iter().any(f))
                .map(|s| &s.allow)
        };

        if let Some(set) = find(&|p| matches!(p, Pattern::Exact(e) if eq_fold(e, sni))) {
            return Some(set);
        }
        let mut rest = sni;
        while let Some(i) = rest.iter().position(|&b| b == b'.') {
            rest = &rest[i + 1..];
            if let Some(set) = find(&|p| matches!(p, Pattern::Suffix(s) if eq_fold(s, rest))) {
                return Some(set);
            }
        }
        None
    }
}

// --- the JSON shape --------------------------------------------------------

/// `deny_unknown_fields` is what makes a typo fail the config rather than silently
/// disable enforcement -- the same reason the old line format rejected stray keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    ula: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
    scopes: Option<Vec<RawScope>>,
    #[serde(default = "yes")]
    require_ppv2: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

fn yes() -> bool {
    true
}

fn build(list: &[String]) -> Result<cidr::Set, String> {
    cidr::build_from(list.iter().map(|s| s.as_str())).map_err(str::to_string)
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;

    let prefix = match &raw.ula {
        Some(u) => Some(identity::parse_prefix(u).map_err(str::to_string)?),
        None => None,
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

    // With require_ppv2 off, unparseable traffic passes through -- straight past
    // every rule. Refuse the combination rather than document it.
    if !raw.require_ppv2 && !(allow.is_empty() && scopes.is_none()) {
        return Err(
            "`require_ppv2: false` passes unparseable traffic straight past `allow`".into(),
        );
    }

    Ok(Config {
        prefix,
        allow,
        scopes,
        require_ppv2: raw.require_ppv2,
    })
}
