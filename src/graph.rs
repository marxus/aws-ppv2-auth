//! The group graph behind `@refs`. A group is a name and a member list; a member
//! is either a source (handed to identity::encode_member unchanged) or `@name`,
//! a reference to another group.
//!
//! The walk is total: an unknown ref contributes nothing (deny-safe, and a
//! watch-fed group can legitimately not exist yet), and a revisited group is
//! skipped -- which also makes a cycle just terminate instead of failing, so the
//! seen-set is the load-bearing wall and insertion never judges the shape.

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

    /// Walk from `entry`, collecting literals; `@refs` expand, revisits and
    /// unknowns skip. Duplicates are left in -- cidr::build merges overlaps anyway.
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
            Some(name) if seen.insert(name) => {
                for m in self.groups.get(name).map(Vec::as_slice).unwrap_or(&[]) {
                    self.walk(m, out, seen);
                }
            }
            Some(_) => {} // already expanded on this walk; how a cycle terminates
            None => out.push(member),
        }
    }
}
