//! `IndexedMap<K, V>` — a height-versioned `Map<K, V>` plus framework-maintained
//! secondary indexes, so filtered reads are prefix scans of a declared index
//! rather than a `keys()` scan-and-filter.
//!
//! Layout (all ordinary path-prefixed `contract_state` rows, so versioned,
//! reorg-safe, and folded into the checkpoint hash):
//! ```text
//!   <primary>/<key>                       -> V
//!   <index>/<index_name>/<index_key>/<key> -> ()   (sibling of <primary>)
//! ```
//! `by_index(name, key)` scans `<index>/<name>/<key>/`, whose child segments
//! ARE the primary keys. The index set is derived from the value via [`Indexed`]
//! and kept consistent on every `set`/`remove`: stale entries (from the prior
//! value) are deleted, fresh ones written. The maintenance lives here, once —
//! not hand-rolled per contract.

use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::str::FromStr;

use crate::{DotPathBuf, ReadStorage, Retrieve, Store, WriteStorage};

/// A value's secondary-index memberships: `(index_name, index_key)` pairs.
/// An empty result means "in no index" — partial indexes fall out by omitting
/// the pair when a predicate is false. `index_key` becomes a path segment, so
/// it must serialise deterministically (reproducible across nodes).
pub trait Indexed {
    fn index_entries(&self) -> Vec<(&'static str, String)>;
}

pub struct IndexedMap<K, V, S: ?Sized> {
    ctx: Rc<S>,
    /// Primary map root, e.g. `challenges`.
    primary: DotPathBuf,
    /// Index root, a sibling of `primary`, e.g. `challenges#idx`. Kept separate
    /// so index rows never appear in the primary's `keys()`.
    index: DotPathBuf,
    _marker: PhantomData<(K, V)>,
}

impl<K, V, S> IndexedMap<K, V, S>
where
    K: ToString + FromStr + Clone,
    <K as FromStr>::Err: Debug,
    V: Store<S> + Retrieve<S> + Indexed,
    S: ReadStorage + WriteStorage + ?Sized,
{
    pub fn new(ctx: Rc<S>, primary: DotPathBuf, index: DotPathBuf) -> Self {
        Self {
            ctx,
            primary,
            index,
            _marker: PhantomData,
        }
    }

    fn index_entry(&self, name: &str, index_key: &str, key: &K) -> DotPathBuf {
        self.index.push(name).push(index_key).push(key.to_string())
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.ctx.__get(self.primary.push(key.to_string()))
    }

    /// Upsert. Diffs the prior value's index entries against the new ones so
    /// only the entries that actually changed are touched: delete `old − new`,
    /// write `new − old`. An index whose key is unchanged (or a re-set with no
    /// change) costs zero storage ops, instead of a delete-then-rewrite per
    /// index. Index counts per value are tiny, so the linear membership checks
    /// are far cheaper than the storage ops they avoid.
    pub fn set(&self, key: &K, value: V) {
        let key_path = self.primary.push(key.to_string());
        let new_entries = value.index_entries();
        let old_entries = self
            .ctx
            .__get::<V>(key_path.clone())
            .map(|old| old.index_entries())
            .unwrap_or_default();

        for (name, index_key) in &old_entries {
            if !new_entries.iter().any(|(n, k)| n == name && k == index_key) {
                self.ctx.__delete(&self.index_entry(name, index_key, key));
            }
        }
        for (name, index_key) in &new_entries {
            if !old_entries.iter().any(|(n, k)| n == name && k == index_key) {
                self.ctx.__set_void(&self.index_entry(name, index_key, key));
            }
        }
        self.ctx.__set(key_path, value);
    }

    /// Remove the entry and its index rows. Returns true if a value existed.
    pub fn remove(&self, key: &K) -> bool {
        let key_path = self.primary.push(key.to_string());
        match self.ctx.__get::<V>(key_path.clone()) {
            Some(old) => {
                for (name, index_key) in old.index_entries() {
                    self.ctx.__delete(&self.index_entry(name, &index_key, key));
                }
                self.ctx.__delete(&key_path)
            }
            None => false,
        }
    }

    /// All primary keys (deterministic order). Lazy, like `Map::keys` — it
    /// borrows the stored primary path.
    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        self.ctx.__get_keys(&self.primary)
    }

    /// Primary keys in the `(name, index_key)` bucket — the indexed lookup that
    /// replaces a scan-and-filter. Lazy: `__get_keys`'s iterator owns its key
    /// source, so it does not borrow the per-call `bucket` path.
    pub fn by_index(&self, name: &str, index_key: &str) -> impl Iterator<Item = K> {
        let bucket = self.index.push(name).push(index_key);
        self.ctx.__get_keys(&bucket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::{format, vec};
    use core::cell::RefCell;

    // Two independent indexes so a value can change one while leaving the other
    // untouched — that's what exercises the diff.
    impl Indexed for u64 {
        fn index_entries(&self) -> Vec<(&'static str, String)> {
            let parity = if self.is_multiple_of(2) {
                "even"
            } else {
                "odd"
            };
            let zeroness = if *self == 0 { "zero" } else { "nonzero" };
            vec![
                ("parity", parity.to_string()),
                ("zeroness", zeroness.to_string()),
            ]
        }
    }

    #[derive(Clone)]
    enum Cell {
        U64(u64),
        Void,
    }

    #[derive(Default)]
    struct Mock {
        map: RefCell<BTreeMap<String, Cell>>,
        // Count index-write / delete ops so a test can assert the diff only
        // touches what changed.
        void_sets: RefCell<usize>,
        deletes: RefCell<usize>,
    }

    impl ReadStorage for Mock {
        fn __get_u64(self: &Rc<Self>, path: &str) -> Option<u64> {
            match self.map.borrow().get(path) {
                Some(Cell::U64(v)) => Some(*v),
                _ => None,
            }
        }
        fn __get_keys<T: ToString + FromStr + Clone>(
            self: &Rc<Self>,
            path: &str,
        ) -> impl Iterator<Item = T> + use<T>
        where
            <T as FromStr>::Err: Debug,
        {
            let prefix = format!("{path}.");
            let mut segs: Vec<String> = self
                .map
                .borrow()
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix))
                .map(|rest| rest.split('.').next().unwrap().to_string())
                .collect();
            segs.sort();
            segs.dedup();
            segs.into_iter().map(|s| T::from_str(&s).unwrap())
        }
        fn __get<T: Retrieve<Self>>(self: &Rc<Self>, path: DotPathBuf) -> Option<T> {
            T::__get(self, path)
        }
        fn __get_str(self: &Rc<Self>, _: &str) -> Option<String> {
            unimplemented!()
        }
        fn __get_s64(self: &Rc<Self>, _: &str) -> Option<i64> {
            unimplemented!()
        }
        fn __get_bool(self: &Rc<Self>, _: &str) -> Option<bool> {
            unimplemented!()
        }
        fn __get_list_u8(self: &Rc<Self>, _: &str) -> Option<Vec<u8>> {
            unimplemented!()
        }
        fn __exists(self: &Rc<Self>, path: &str) -> bool {
            self.map.borrow().contains_key(path)
        }
        fn __extend_path_with_match(self: &Rc<Self>, _: &str, _: &[&str]) -> Option<String> {
            unimplemented!()
        }
    }

    impl WriteStorage for Mock {
        fn __set_u64(self: &Rc<Self>, path: &str, value: u64) {
            self.map
                .borrow_mut()
                .insert(path.to_string(), Cell::U64(value));
        }
        fn __set_void(self: &Rc<Self>, path: &str) {
            *self.void_sets.borrow_mut() += 1;
            self.map.borrow_mut().insert(path.to_string(), Cell::Void);
        }
        fn __delete(self: &Rc<Self>, path: &str) -> bool {
            *self.deletes.borrow_mut() += 1;
            self.map.borrow_mut().remove(path).is_some()
        }
        fn __set<T: Store<Self>>(self: &Rc<Self>, path: DotPathBuf, value: T) {
            T::__set(self, path, value)
        }
        fn __set_str(self: &Rc<Self>, _: &str, _: &str) {
            unimplemented!()
        }
        fn __set_s64(self: &Rc<Self>, _: &str, _: i64) {
            unimplemented!()
        }
        fn __set_bool(self: &Rc<Self>, _: &str, _: bool) {
            unimplemented!()
        }
        fn __set_list_u8(self: &Rc<Self>, _: &str, _: Vec<u8>) {
            unimplemented!()
        }
        fn __delete_matching_paths(self: &Rc<Self>, _: &str, _: &[&str]) -> u64 {
            unimplemented!()
        }
    }

    fn map(ctx: &Rc<Mock>) -> IndexedMap<u64, u64, Mock> {
        IndexedMap::new(
            ctx.clone(),
            DotPathBuf::new().push("nums"),
            DotPathBuf::new().push("nums#idx"),
        )
    }

    #[test]
    fn maintains_indexes_on_set_update_remove() {
        let ctx = Rc::new(Mock::default());
        let m = map(&ctx);

        m.set(&1, 10); // even
        m.set(&2, 11); // odd
        m.set(&3, 12); // even

        assert_eq!(m.by_index("parity", "even").collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(m.by_index("parity", "odd").collect::<Vec<_>>(), vec![2]);

        // Update key 1 to an odd value: it must leave `even` and enter `odd`.
        m.set(&1, 13);
        assert_eq!(m.by_index("parity", "even").collect::<Vec<_>>(), vec![3]);
        assert_eq!(m.by_index("parity", "odd").collect::<Vec<_>>(), vec![1, 2]);

        // Remove key 2: gone from the primary and its index bucket.
        assert!(m.remove(&2));
        assert!(!m.remove(&2)); // idempotent: nothing left to remove
        assert_eq!(m.get(&2), None);
        assert_eq!(m.by_index("parity", "odd").collect::<Vec<_>>(), vec![1]);

        assert_eq!(m.keys().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn set_diff_only_touches_changed_indexes() {
        let ctx = Rc::new(Mock::default());
        let m = map(&ctx);

        m.set(&1, 0); // parity=even, zeroness=zero
        *ctx.void_sets.borrow_mut() = 0;
        *ctx.deletes.borrow_mut() = 0;

        // 0 -> 2: parity stays `even`, zeroness flips `zero` -> `nonzero`. Only
        // the zeroness entry should move; parity must not be touched.
        m.set(&1, 2);
        assert_eq!(
            *ctx.deletes.borrow(),
            1,
            "only the changed index is deleted"
        );
        assert_eq!(
            *ctx.void_sets.borrow(),
            1,
            "only the changed index is written"
        );

        // A re-set with no change touches no index entries at all.
        *ctx.void_sets.borrow_mut() = 0;
        *ctx.deletes.borrow_mut() = 0;
        m.set(&1, 2);
        assert_eq!(*ctx.deletes.borrow(), 0, "no-op re-set deletes nothing");
        assert_eq!(*ctx.void_sets.borrow(), 0, "no-op re-set writes nothing");

        // ...and the indexes are still correct after the churn-free updates.
        assert_eq!(m.by_index("parity", "even").collect::<Vec<_>>(), vec![1]);
        assert_eq!(
            m.by_index("zeroness", "nonzero").collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            m.by_index("zeroness", "zero").collect::<Vec<_>>(),
            Vec::<u64>::new()
        );
    }
}
