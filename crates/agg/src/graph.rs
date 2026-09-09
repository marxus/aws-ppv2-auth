//! Namespace-scoped identity graph. Nodes are groups keyed by (namespace, name); edges are @refs inside `members`. A group's `members` list is the raw authored value -- unresolved @refs stay as-is until `resolve()` walks them.
//!
//! Nothing here talks to k8s. The graph is a pure data structure fed by the watcher and read by consumers (Step 1: HTTP debug endpoints; Step 2: the envoy filter's config-load path).

use std::collections::{BTreeMap, HashMap, HashSet};

pub type Ns = String;
pub type GroupName = String;
pub type Member = String;

/// Key = (namespace, group name). @refs are namespace-local -- a member `"@foo"` in ns `bar` resolves to key `(bar, foo)`.
pub type Key = (Ns, GroupName);

#[derive(Default, Debug)]
pub struct Graph {
    groups: HashMap<Key, Vec<Member>>,
}

/// Reason a change was rejected. Kept as an enum so callers can log distinct outcomes.
#[derive(Debug, PartialEq, Eq)]
pub enum UpsertError {
    /// Adding this group with these members would close a cycle.
    Cycle {
        via: Vec<GroupName>,
    },
}

impl Graph {
    /// Upsert a group's raw members. Rejects if it would close a cycle in this namespace (self-ref counts). Everything else -- unknown @refs, empty members, mixed shapes -- is accepted; resolution deals with the mess later.
    pub fn upsert(&mut self, key: Key, members: Vec<Member>) -> Result<(), UpsertError> {
        if let Some(path) = Self::cycle_probe(&self.groups, &key, &members) {
            return Err(UpsertError::Cycle { via: path });
        }
        self.groups.insert(key, members);
        Ok(())
    }

    pub fn remove(&mut self, key: &Key) {
        self.groups.remove(key);
    }

    /// Wipe on relist. The watcher emits Init before replaying, so callers use this to drop stale entries before InitApply repopulates.
    pub fn reset(&mut self) {
        self.groups.clear();
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Full dump, sorted for readability. Debug endpoint only.
    pub fn dump(&self) -> BTreeMap<String, Vec<Member>> {
        self.groups
            .iter()
            .map(|((ns, name), m)| (format!("{ns}/{name}"), m.clone()))
            .collect()
    }

    /// Walk from `entry` in `ns`, unioning concrete (non-@) members. Cycle-safe at walk time: a visited-set guards revisits. Unknown @refs contribute nothing.
    pub fn resolve(&self, ns: &str, entry: &[Member]) -> HashSet<Member> {
        let mut out = HashSet::new();
        let mut seen: HashSet<Key> = HashSet::new();
        for m in entry {
            self.walk(ns, m, &mut out, &mut seen);
        }
        out
    }

    fn walk(&self, ns: &str, m: &str, out: &mut HashSet<Member>, seen: &mut HashSet<Key>) {
        match m.strip_prefix('@') {
            Some(name) => {
                let key = (ns.to_string(), name.to_string());
                if !seen.insert(key.clone()) {
                    return;
                }
                if let Some(children) = self.groups.get(&key) {
                    for c in children {
                        self.walk(ns, c, out, seen);
                    }
                }
            }
            None => {
                out.insert(m.to_string());
            }
        }
    }

    /// DFS to see if inserting `members` into `key` would put `key` reachable from any @ref it names. Returns the offending path if it would.
    fn cycle_probe(
        g: &HashMap<Key, Vec<Member>>,
        key: &Key,
        members: &[Member],
    ) -> Option<Vec<GroupName>> {
        let (ns, name) = key;
        for m in members {
            let Some(target) = m.strip_prefix('@') else {
                continue;
            };
            if target == name {
                return Some(vec![name.clone(), name.clone()]);
            }
            let start = (ns.clone(), target.to_string());
            let mut stack: Vec<(Key, Vec<GroupName>)> = vec![(start, vec![target.to_string()])];
            let mut seen: HashSet<Key> = HashSet::new();
            while let Some((cur, path)) = stack.pop() {
                if &cur == key {
                    let mut full = vec![name.clone()];
                    full.extend(path);
                    return Some(full);
                }
                if !seen.insert(cur.clone()) {
                    continue;
                }
                if let Some(children) = g.get(&cur) {
                    for c in children {
                        if let Some(t) = c.strip_prefix('@') {
                            let mut np = path.clone();
                            np.push(t.to_string());
                            stack.push(((cur.0.clone(), t.to_string()), np));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> String {
        "ns".into()
    }
    fn k(name: &str) -> Key {
        (ns(), name.into())
    }
    fn m(s: &[&str]) -> Vec<Member> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn resolve_literals() {
        let mut g = Graph::default();
        g.upsert(k("a"), m(&["vpce-x", "10.0.0.0/24"])).unwrap();
        let out = g.resolve(&ns(), &m(&["@a"]));
        assert_eq!(out.len(), 2);
        assert!(out.contains("vpce-x"));
        assert!(out.contains("10.0.0.0/24"));
    }

    #[test]
    fn resolve_transitive() {
        let mut g = Graph::default();
        g.upsert(k("leaf"), m(&["vpce-1"])).unwrap();
        g.upsert(k("mid"), m(&["@leaf", "10.0.0.0/8"])).unwrap();
        g.upsert(k("top"), m(&["@mid", "vpce-2"])).unwrap();
        let out = g.resolve(&ns(), &m(&["@top"]));
        assert_eq!(out.len(), 3);
        assert!(out.contains("vpce-1"));
        assert!(out.contains("vpce-2"));
        assert!(out.contains("10.0.0.0/8"));
    }

    #[test]
    fn resolve_dedups_diamond() {
        let mut g = Graph::default();
        g.upsert(k("leaf"), m(&["vpce-1"])).unwrap();
        g.upsert(k("a"), m(&["@leaf"])).unwrap();
        g.upsert(k("b"), m(&["@leaf"])).unwrap();
        g.upsert(k("top"), m(&["@a", "@b"])).unwrap();
        let out = g.resolve(&ns(), &m(&["@top"]));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn resolve_ignores_unknown_ref() {
        let mut g = Graph::default();
        g.upsert(k("a"), m(&["@missing", "vpce-x"])).unwrap();
        let out = g.resolve(&ns(), &m(&["@a"]));
        assert_eq!(out.len(), 1);
        assert!(out.contains("vpce-x"));
    }

    #[test]
    fn cycle_self() {
        let mut g = Graph::default();
        assert!(matches!(
            g.upsert(k("a"), m(&["@a"])),
            Err(UpsertError::Cycle { .. })
        ));
    }

    #[test]
    fn cycle_two_hop() {
        let mut g = Graph::default();
        g.upsert(k("a"), m(&["@b"])).unwrap();
        assert!(matches!(
            g.upsert(k("b"), m(&["@a"])),
            Err(UpsertError::Cycle { .. })
        ));
        // graph state unchanged after rejection
        assert!(g.groups.get(&k("b")).is_none());
    }

    #[test]
    fn cycle_scoped_to_namespace() {
        let mut g = Graph::default();
        g.upsert(("ns1".into(), "a".into()), m(&["@b"])).unwrap();
        // @b in ns2 -> different group; not a cycle even though names collide across namespaces.
        assert!(g
            .upsert(("ns2".into(), "b".into()), m(&["@a"]))
            .is_ok());
    }

    #[test]
    fn resolve_scoped_to_namespace() {
        let mut g = Graph::default();
        g.upsert(("ns1".into(), "a".into()), m(&["vpce-1"])).unwrap();
        g.upsert(("ns2".into(), "a".into()), m(&["vpce-2"])).unwrap();
        assert_eq!(
            g.resolve("ns1", &m(&["@a"])).into_iter().collect::<Vec<_>>(),
            vec!["vpce-1".to_string()]
        );
    }
}
