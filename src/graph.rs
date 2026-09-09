//! The group graph behind `@refs`. A group is a name and a member list; a member
//! is either a source (handed to identity::encode_member unchanged) or `@name`,
//! a reference to another group.
//!
//! The walk is total, one mental model for everything unresolvable: an unknown
//! ref falls through as a literal, so encode_member hashes it as a label -- the
//! same fate as a malformed address, and just as harmless, since nothing on the
//! wire ever presents "@name" as its identity. A group that appears later
//! (watch-fed) re-renders the config and the ref expands then. A revisited group
//! is skipped, which also makes a cycle just terminate instead of failing, so
//! the seen-set is the load-bearing wall and insertion never judges the shape.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct Graph {
    groups: HashMap<String, Vec<String>>,
}

impl Graph {
    /// Insert or replace a group. Any member list is accepted; the walk sorts it out.
    pub fn upsert(&mut self, name: String, members: Vec<String>) {
        self.groups.insert(name, members);
    }

    /// Walk from `entry`, collecting literals; known `@refs` expand, revisits
    /// skip, unknown refs pass through as literals (labels-to-be). Duplicates are
    /// left in -- cidr::build merges overlaps anyway.
    pub fn resolve<'a>(&'a self, entry: &'a [String]) -> Vec<&'a str> {
        let mut out = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for m in entry {
            self.walk(m, &mut out, &mut seen);
        }
        out
    }

    fn walk<'a>(&'a self, member: &'a str, out: &mut Vec<&'a str>, seen: &mut HashSet<&'a str>) {
        match member.strip_prefix('@') {
            Some(name) => match self.groups.get(name) {
                Some(members) if seen.insert(name) => {
                    for m in members {
                        self.walk(m, out, seen);
                    }
                }
                Some(_) => {} // already expanded on this walk; how a cycle terminates
                None => out.push(member), // unknown ref: a label like any other unresolvable string
            },
            None => out.push(member),
        }
    }
}
