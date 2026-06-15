use alloc::{string::String, vec::Vec};

use crate::KeyPath;
use crate::keycodec::KeyElement;

pub trait ReadStorage {
    fn __get_str(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<String>;

    fn __get_u64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<u64>;

    fn __get_s64(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<i64>;

    fn __get_bool(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<bool>;

    fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8]) -> Option<Vec<u8>>;

    // The returned iterator owns its key source (see `make_keys_iterator`), so it
    // does not borrow `path`. `use<Self, T>` makes that explicit — capturing only
    // the types, not the `self`/`path` lifetimes — so callers can scan a
    // freshly-built path (e.g. an index bucket) and still return the iterator.
    // `T` is decoded from each child's codec element (the map key, or an
    // `(sort, pk)` tuple for a sorted-index member), so it sorts and round-trips
    // natively — no stringify/parse.
    fn __get_keys<T: KeyElement + Clone>(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
    ) -> impl Iterator<Item = T> + use<Self, T>;

    fn __exists(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool;

    /// Resolve which of `candidates` (already-encoded discriminant elements) is the
    /// current child under `path`, returning its INDEX, or `None` if unset. The host
    /// byte-compares, so the candidate encoding (string element or interned dict-ref)
    /// is the guest's choice.
    fn __extend_path_with_match(
        self: &alloc::rc::Rc<Self>,
        path: &[u8],
        candidates: &[Vec<u8>],
    ) -> Option<u32>;

    fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: KeyPath) -> Option<T>;
}

pub trait Retrieve<T: ?Sized>: Clone {
    fn __get(ctx: &alloc::rc::Rc<T>, base_path: KeyPath) -> Option<Self>;
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for u64 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_u64(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for i64 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_s64(&path)
    }
}

// u32/i32 are stored through the underlying u64/s64 slots — the WIT
// proc-storage interface only carries 64-bit getters/setters, but every
// in-range value round-trips. Out-of-range bits would indicate storage
// corruption; the truncating `as` cast keeps the read path infallible.
impl<T: ReadStorage + ?Sized> Retrieve<T> for u32 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_u64(&path).map(|v| v as u32)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for i32 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_s64(&path).map(|v| v as i32)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for String {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_str(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for bool {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_bool(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for Vec<u8> {
    fn __get(ctx: &alloc::rc::Rc<T>, path: KeyPath) -> Option<Self> {
        ctx.__get_list_u8(&path)
    }
}

pub trait WriteStorage {
    fn __set_str(self: &alloc::rc::Rc<Self>, path: &[u8], value: &str);

    fn __set_u64(self: &alloc::rc::Rc<Self>, path: &[u8], value: u64);

    fn __set_s64(self: &alloc::rc::Rc<Self>, path: &[u8], value: i64);

    fn __set_bool(self: &alloc::rc::Rc<Self>, path: &[u8], value: bool);

    fn __set_list_u8(self: &alloc::rc::Rc<Self>, path: &[u8], value: Vec<u8>);

    fn __set_void(self: &alloc::rc::Rc<Self>, path: &[u8]);

    fn __set<T: Store<Self>>(self: &alloc::rc::Rc<Self>, path: KeyPath, value: T);

    /// Tombstone a path and its whole subtree (every live descendant), so a
    /// struct/map value stored under child paths is fully removed — not just the
    /// exact path. Returns true if any live row was tombstoned. (A leaf path,
    /// e.g. an index void, has no descendants, so this is a single tombstone.)
    fn __delete(self: &alloc::rc::Rc<Self>, path: &[u8]) -> bool;

    fn __delete_matching_paths(
        self: &alloc::rc::Rc<Self>,
        base_path: &[u8],
        candidates: &[Vec<u8>],
    ) -> u64;
}

pub trait Store<T: WriteStorage + ?Sized> {
    fn __set(ctx: &alloc::rc::Rc<T>, base_path: KeyPath, value: Self);
}

impl<T: WriteStorage + ?Sized> Store<T> for u64 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: u64) {
        ctx.__set_u64(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for i64 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: i64) {
        ctx.__set_s64(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for u32 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: u32) {
        ctx.__set_u64(&path, value as u64);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for i32 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: i32) {
        ctx.__set_s64(&path, value as i64);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for &str {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: &str) {
        ctx.__set_str(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for String {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: String) {
        ctx.__set_str(&path, &value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for bool {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: bool) {
        ctx.__set_bool(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for Vec<u8> {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, value: Vec<u8>) {
        ctx.__set_list_u8(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for () {
    fn __set(ctx: &alloc::rc::Rc<T>, path: KeyPath, _: ()) {
        ctx.__set_void(&path);
    }
}

impl<S: WriteStorage + ?Sized, T: Store<S>> Store<S> for Option<T> {
    fn __set(ctx: &alloc::rc::Rc<S>, path: KeyPath, value: Self) {
        // `none`/`some` stay STRING discriminant segments (Option is generic, with
        // no per-type dict to intern them into); the host byte-compares, so this
        // mixes fine with interned enum variants elsewhere.
        ctx.__delete_matching_paths(
            &path,
            &[
                crate::keycodec::string_element("none"),
                crate::keycodec::string_element("some"),
            ],
        );
        match value {
            Some(inner) => ctx.__set(path.push("some"), inner),
            None => ctx.__set(path.push("none"), ()),
        }
    }
}

pub trait HasNext {
    /// The next child key's codec element bytes (a string element), or `None`.
    fn next(&self) -> Option<Vec<u8>>;
}

pub fn make_keys_iterator<K, T>(keys: K) -> impl Iterator<Item = T>
where
    K: HasNext,
    T: KeyElement,
{
    struct KeysIterator<K, T>
    where
        K: HasNext,
        T: KeyElement,
    {
        keys: K,
        _phantom: core::marker::PhantomData<T>,
    }

    impl<K, T> Iterator for KeysIterator<K, T>
    where
        K: HasNext,
        T: KeyElement,
    {
        type Item = T;
        fn next(&mut self) -> Option<Self::Item> {
            // Each child segment is one codec element; decode it directly into `T`
            // (the map key, or a `(sort, pk)` tuple for a sorted member).
            self.keys.next().map(|elem| {
                let (v, _) = T::decode_from(&elem).expect("keys() element decodes into T");
                v
            })
        }
    }

    KeysIterator {
        keys,
        _phantom: core::marker::PhantomData,
    }
}

storage_placeholder!(
    /// The declared `Map<K, V>` field placeholder. The generated field model is
    /// the real accessor; this only holds entries for a wholesale `Store` write.
    StorageMap
);

impl<K: KeyElement + Clone, V: Store<S> + Clone, S: WriteStorage + ?Sized> Store<S>
    for StorageMap<K, V, S>
{
    fn __set(ctx: &alloc::rc::Rc<S>, base_path: KeyPath, value: StorageMap<K, V, S>) {
        for (k, v) in value.entries.into_iter() {
            ctx.__set(base_path.push_element(&k), v)
        }
    }
}
