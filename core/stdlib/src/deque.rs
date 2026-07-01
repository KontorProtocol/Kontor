//! `Deque<V>` — a height-versioned double-ended queue (and index-accessible list)
//! over key-value storage, modeled on CosmWasm's `cw-storage-plus::Deque`.
//!
//! Layout under the field's base path: two `u64` cursors (`head`, `tail`) plus the
//! elements keyed by absolute position. `head` is the first element's position;
//! `tail` is the first empty slot past the last. Positions use wrapping `u64`
//! arithmetic, so the cursors ride a ring over the index space and never need
//! resetting (capacity `u64::MAX - 1`). All external indexing is RELATIVE —
//! `get(0)` is the front.
//!
//! The generated field model is the real accessor (push/pop/get/len/iter); these
//! free functions hold the logic so the codegen stays thin (cf. `apply_index_diff`
//! for `Map`). `iter`/`len`-scans are O(n) storage reads — use on bounded
//! deques (or paginate), never an unbounded load.

use crate::{KeyPath, ReadStorage, Retrieve, Store, WriteStorage};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::marker::PhantomData;

// Interned structural markers within a deque's own subtree (cf. a struct's field
// ids). Distinct from element keys, which are encoded `u64` positions under ENTRIES.
const HEAD: u8 = 0;
const TAIL: u8 = 1;
const ENTRIES: u8 = 2;

fn head_path(base: &KeyPath) -> KeyPath {
    base.push_interned(HEAD)
}

fn tail_path(base: &KeyPath) -> KeyPath {
    base.push_interned(TAIL)
}

/// Storage path of the element at absolute position `pos`. Public so the generated
/// model can build a value-model over a struct/enum element (which is a subtree,
/// not a single cell).
pub fn entry_path(base: &KeyPath, pos: u64) -> KeyPath {
    base.push_interned(ENTRIES).push_element(&pos)
}

/// Head cursor (first element's position); 0 if unset.
pub fn head<S: ReadStorage + ?Sized>(ctx: &Rc<S>, base: &KeyPath) -> u64 {
    ctx.__get_u64(&head_path(base)).unwrap_or(0)
}

/// Tail cursor (one past the last element); 0 if unset.
pub fn tail<S: ReadStorage + ?Sized>(ctx: &Rc<S>, base: &KeyPath) -> u64 {
    ctx.__get_u64(&tail_path(base)).unwrap_or(0)
}

/// Set the head cursor. Public for the generated model's struct/enum `pop_front`,
/// which materializes the value via the value model then advances the cursor here.
pub fn set_head<S: WriteStorage + ?Sized>(ctx: &Rc<S>, base: &KeyPath, value: u64) {
    ctx.__set_u64(&head_path(base), value);
}

/// Set the tail cursor. See [`set_head`].
pub fn set_tail<S: WriteStorage + ?Sized>(ctx: &Rc<S>, base: &KeyPath, value: u64) {
    ctx.__set_u64(&tail_path(base), value);
}

/// Number of live elements.
pub fn len<S: ReadStorage + ?Sized>(ctx: &Rc<S>, base: &KeyPath) -> u64 {
    tail(ctx, base).wrapping_sub(head(ctx, base))
}

/// Element at relative position `pos` (0 = front), or `None` if out of bounds.
pub fn get<S, V>(ctx: &Rc<S>, base: &KeyPath, pos: u64) -> Option<V>
where
    S: ReadStorage + ?Sized,
    V: Retrieve<S>,
{
    let h = head(ctx, base);
    if pos >= tail(ctx, base).wrapping_sub(h) {
        return None;
    }
    ctx.__get(entry_path(base, h.wrapping_add(pos)))
}

/// Overwrite the element at relative position `pos`. Returns false if out of bounds.
pub fn set<S, V>(ctx: &Rc<S>, base: &KeyPath, pos: u64, value: V) -> bool
where
    S: ReadStorage + WriteStorage + ?Sized,
    V: Store<S>,
{
    let h = head(ctx, base);
    if pos >= tail(ctx, base).wrapping_sub(h) {
        return false;
    }
    ctx.__set(entry_path(base, h.wrapping_add(pos)), value);
    true
}

/// Append to the back.
pub fn push_back<S, V>(ctx: &Rc<S>, base: &KeyPath, value: V)
where
    S: ReadStorage + WriteStorage + ?Sized,
    V: Store<S>,
{
    let pos = tail(ctx, base);
    ctx.__set(entry_path(base, pos), value);
    ctx.__set_u64(&tail_path(base), pos.wrapping_add(1));
}

/// Prepend to the front.
pub fn push_front<S, V>(ctx: &Rc<S>, base: &KeyPath, value: V)
where
    S: ReadStorage + WriteStorage + ?Sized,
    V: Store<S>,
{
    // Subtract first: head points at an existing element (or the empty slot).
    let pos = head(ctx, base).wrapping_sub(1);
    ctx.__set(entry_path(base, pos), value);
    ctx.__set_u64(&head_path(base), pos);
}

/// Remove and return the front element.
pub fn pop_front<S, V>(ctx: &Rc<S>, base: &KeyPath) -> Option<V>
where
    S: ReadStorage + WriteStorage + ?Sized,
    V: Retrieve<S>,
{
    let h = head(ctx, base);
    if h == tail(ctx, base) {
        return None;
    }
    let value = ctx.__get(entry_path(base, h));
    ctx.__delete(&entry_path(base, h));
    ctx.__set_u64(&head_path(base), h.wrapping_add(1));
    value
}

/// Remove and return the back element.
pub fn pop_back<S, V>(ctx: &Rc<S>, base: &KeyPath) -> Option<V>
where
    S: ReadStorage + WriteStorage + ?Sized,
    V: Retrieve<S>,
{
    let t = tail(ctx, base);
    if head(ctx, base) == t {
        return None;
    }
    let pos = t.wrapping_sub(1);
    let value = ctx.__get(entry_path(base, pos));
    ctx.__delete(&entry_path(base, pos));
    ctx.__set_u64(&tail_path(base), pos);
    value
}

/// Inert placeholder a contract declares as a `Deque<V>` field. The generated field
/// model is the real accessor; this only holds entries for a wholesale `Store`
/// write (e.g. seeding on `init`).
pub struct StorageDeque<V, S: ?Sized> {
    pub entries: Vec<V>,
    pub _marker: PhantomData<S>,
}

impl<V: Clone, S: ?Sized> StorageDeque<V, S> {
    pub fn new(entries: &[V]) -> Self {
        Self {
            entries: entries.to_vec(),
            _marker: PhantomData,
        }
    }
}

impl<V: Clone, S: ?Sized> Clone for StorageDeque<V, S> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            _marker: PhantomData,
        }
    }
}

impl<V, S: ?Sized> Default for StorageDeque<V, S> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<V: Store<S>, S: WriteStorage + ?Sized> Store<S> for StorageDeque<V, S> {
    fn __set(ctx: &Rc<S>, base_path: KeyPath, value: StorageDeque<V, S>) {
        // Wholesale REPLACE, not overlay. A deque may already exist at this path
        // (e.g. a parent struct re-set via its own `Store::__set`), carrying stale
        // state: a non-zero `head` from earlier `push_front` (head wraps toward
        // u64::MAX), a larger prior length, or entries at out-of-window positions.
        // So: (1) tombstone the whole prior subtree, then (2) seed the new entries at
        // 0..count and reset BOTH cursors to the canonical `[0, count)` window.
        // Resetting `head` is the load-bearing part — a leftover `head` makes
        // `len()`/`get()` read the wrong window. (The explicit cursor writes also
        // hold the invariant under a backing store whose `delete` isn't subtree-wide.)
        //
        // The blanket subtree delete (not a surgical "overwrite 0..count, delete the
        // leftover tail") is deliberate: after an earlier `push_front` the old entries
        // sit at wrapped absolute positions (near u64::MAX), which the new `[0, count)`
        // writes don't overlap — so overwriting in place would leave those wrapped rows
        // live (unread, since head resets to 0, but storage bloat plus a landmine if
        // head later wraps back onto them). Deleting the whole subtree needs no
        // knowledge of where the old entries physically live; the cost is double-writing
        // only the non-wrapped overlap, and this path is cold (push/pop mutate in place).
        ctx.__delete(&base_path);
        let count = value.entries.len() as u64;
        for (i, v) in value.entries.into_iter().enumerate() {
            ctx.__set(entry_path(&base_path, i as u64), v);
        }
        ctx.__set_u64(&head_path(&base_path), 0);
        ctx.__set_u64(&tail_path(&base_path), count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyElement;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    // Minimal in-memory storage backing `u64` cells — enough to exercise the deque
    // logic (cursors + entries are all `u64` here; `Vec<u8>` values are covered by
    // the filestorage integration tests).
    #[derive(Default)]
    struct Mock {
        map: RefCell<BTreeMap<Vec<u8>, u64>>,
    }

    impl ReadStorage for Mock {
        fn __get_u64(self: &Rc<Self>, path: &[u8]) -> Option<u64> {
            self.map.borrow().get(path).copied()
        }
        fn __get<T: Retrieve<Self>>(self: &Rc<Self>, path: KeyPath) -> Option<T> {
            T::__get(self, path)
        }
        fn __exists(self: &Rc<Self>, path: &[u8]) -> bool {
            self.map.borrow().contains_key(path)
        }
        fn __get_keys_from<T: KeyElement + Clone>(
            self: &Rc<Self>,
            _: &[u8],
            _: Option<&[u8]>,
        ) -> impl Iterator<Item = T> + use<T> {
            core::iter::empty()
        }
        fn __get_str(self: &Rc<Self>, _: &[u8]) -> Option<String> {
            unimplemented!()
        }
        fn __get_s64(self: &Rc<Self>, _: &[u8]) -> Option<i64> {
            unimplemented!()
        }
        fn __get_bool(self: &Rc<Self>, _: &[u8]) -> Option<bool> {
            unimplemented!()
        }
        fn __get_list_u8(self: &Rc<Self>, _: &[u8]) -> Option<Vec<u8>> {
            unimplemented!()
        }
        fn __extend_path_with_match(self: &Rc<Self>, _: &[u8], _: &[Vec<u8>]) -> Option<u32> {
            unimplemented!()
        }
    }

    impl WriteStorage for Mock {
        fn __set_u64(self: &Rc<Self>, path: &[u8], value: u64) {
            self.map.borrow_mut().insert(path.to_vec(), value);
        }
        fn __delete(self: &Rc<Self>, path: &[u8]) -> bool {
            self.map.borrow_mut().remove(path).is_some()
        }
        fn __set<T: Store<Self>>(self: &Rc<Self>, path: KeyPath, value: T) {
            T::__set(self, path, value)
        }
        fn __set_str(self: &Rc<Self>, _: &[u8], _: &str) {
            unimplemented!()
        }
        fn __set_s64(self: &Rc<Self>, _: &[u8], _: i64) {
            unimplemented!()
        }
        fn __set_bool(self: &Rc<Self>, _: &[u8], _: bool) {
            unimplemented!()
        }
        fn __set_list_u8(self: &Rc<Self>, _: &[u8], _: Vec<u8>) {
            unimplemented!()
        }
        fn __set_void(self: &Rc<Self>, _: &[u8]) {
            unimplemented!()
        }
        fn __delete_matching_paths(self: &Rc<Self>, _: &[u8], _: &[Vec<u8>]) -> u64 {
            unimplemented!()
        }
    }

    fn base() -> KeyPath {
        KeyPath::from("dq")
    }

    #[test]
    fn fifo_push_back_pop_front() {
        let ctx = Rc::new(Mock::default());
        let b = base();
        assert_eq!(len(&ctx, &b), 0);
        assert_eq!(pop_front::<_, u64>(&ctx, &b), None);

        push_back(&ctx, &b, 10u64);
        push_back(&ctx, &b, 20u64);
        push_back(&ctx, &b, 30u64);
        assert_eq!(len(&ctx, &b), 3);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(10));
        assert_eq!(get::<_, u64>(&ctx, &b, 2), Some(30));
        assert_eq!(get::<_, u64>(&ctx, &b, 3), None);

        assert_eq!(pop_front::<_, u64>(&ctx, &b), Some(10));
        assert_eq!(len(&ctx, &b), 2);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(20)); // front shifted
    }

    #[test]
    fn both_ends() {
        let ctx = Rc::new(Mock::default());
        let b = base();
        push_back(&ctx, &b, 2u64);
        push_front(&ctx, &b, 1u64);
        push_back(&ctx, &b, 3u64); // [1, 2, 3]
        assert_eq!(len(&ctx, &b), 3);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(1));
        assert_eq!(get::<_, u64>(&ctx, &b, 2), Some(3));
        assert_eq!(pop_back::<_, u64>(&ctx, &b), Some(3));
        assert_eq!(pop_front::<_, u64>(&ctx, &b), Some(1));
        assert_eq!(len(&ctx, &b), 1);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(2));
    }

    #[test]
    fn set_in_bounds_only() {
        let ctx = Rc::new(Mock::default());
        let b = base();
        push_back(&ctx, &b, 5u64);
        push_back(&ctx, &b, 6u64);
        assert!(set(&ctx, &b, 1, 60u64));
        assert_eq!(get::<_, u64>(&ctx, &b, 1), Some(60));
        assert!(!set(&ctx, &b, 2, 99u64)); // out of bounds, no-op
    }

    #[test]
    fn push_front_wraps_head() {
        // push_front from empty drives head to u64::MAX (wrapping); len stays right.
        let ctx = Rc::new(Mock::default());
        let b = base();
        push_front(&ctx, &b, 7u64);
        assert_eq!(head(&ctx, &b), u64::MAX);
        assert_eq!(len(&ctx, &b), 1);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(7));
        assert_eq!(pop_front::<_, u64>(&ctx, &b), Some(7));
        assert_eq!(len(&ctx, &b), 0);
    }

    #[test]
    fn wholesale_set_resets_cursors_after_push_front() {
        // Regression: a wholesale `Store::__set` (e.g. a parent struct re-set) over a
        // deque whose `head` was driven non-zero by `push_front` must reset head to 0,
        // not inherit the stale cursor — else len()/get() read the wrong window.
        let ctx = Rc::new(Mock::default());
        let b = base();
        push_back(&ctx, &b, 1u64);
        push_front(&ctx, &b, 0u64); // head now u64::MAX
        assert_eq!(head(&ctx, &b), u64::MAX);

        WriteStorage::__set(&ctx, b.clone(), StorageDeque::<u64, Mock>::new(&[9, 8, 7]));
        assert_eq!(head(&ctx, &b), 0);
        assert_eq!(len(&ctx, &b), 3);
        assert_eq!(get::<_, u64>(&ctx, &b, 0), Some(9));
        assert_eq!(get::<_, u64>(&ctx, &b, 2), Some(7));

        WriteStorage::__set(&ctx, b.clone(), StorageDeque::<u64, Mock>::new(&[]));
        assert_eq!(head(&ctx, &b), 0);
        assert_eq!(len(&ctx, &b), 0);
    }
}
