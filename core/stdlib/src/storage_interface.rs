use core::{fmt::Debug, str::FromStr};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::DotPathBuf;

pub trait ReadStorage {
    fn __get_str(self: &alloc::rc::Rc<Self>, path: &str) -> Option<String>;

    fn __get_u64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<u64>;

    fn __get_s64(self: &alloc::rc::Rc<Self>, path: &str) -> Option<i64>;

    fn __get_bool(self: &alloc::rc::Rc<Self>, path: &str) -> Option<bool>;

    fn __get_list_u8(self: &alloc::rc::Rc<Self>, path: &str) -> Option<Vec<u8>>;

    // The returned iterator owns its key source (see `make_keys_iterator`), so it
    // does not borrow `path`. `use<Self, T>` makes that explicit — capturing only
    // the types, not the `self`/`path` lifetimes — so callers can scan a
    // freshly-built path (e.g. an index bucket) and still return the iterator.
    fn __get_keys<T: ToString + FromStr + Clone>(
        self: &alloc::rc::Rc<Self>,
        path: &str,
    ) -> impl Iterator<Item = T> + use<Self, T>
    where
        <T as FromStr>::Err: Debug;

    fn __exists(self: &alloc::rc::Rc<Self>, path: &str) -> bool;

    fn __extend_path_with_match(
        self: &alloc::rc::Rc<Self>,
        path: &str,
        variants: &[&str],
    ) -> Option<String>;

    fn __get<T: Retrieve<Self>>(self: &alloc::rc::Rc<Self>, path: DotPathBuf) -> Option<T>;
}

pub trait Retrieve<T: ?Sized>: Clone {
    fn __get(ctx: &alloc::rc::Rc<T>, base_path: DotPathBuf) -> Option<Self>;
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for u64 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_u64(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for i64 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_s64(&path)
    }
}

// u32/i32 are stored through the underlying u64/s64 slots — the WIT
// proc-storage interface only carries 64-bit getters/setters, but every
// in-range value round-trips. Out-of-range bits would indicate storage
// corruption; the truncating `as` cast keeps the read path infallible.
impl<T: ReadStorage + ?Sized> Retrieve<T> for u32 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_u64(&path).map(|v| v as u32)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for i32 {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_s64(&path).map(|v| v as i32)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for String {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_str(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for bool {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_bool(&path)
    }
}

impl<T: ReadStorage + ?Sized> Retrieve<T> for Vec<u8> {
    fn __get(ctx: &alloc::rc::Rc<T>, path: DotPathBuf) -> Option<Self> {
        ctx.__get_list_u8(&path)
    }
}

pub trait WriteStorage {
    fn __set_str(self: &alloc::rc::Rc<Self>, path: &str, value: &str);

    fn __set_u64(self: &alloc::rc::Rc<Self>, path: &str, value: u64);

    fn __set_s64(self: &alloc::rc::Rc<Self>, path: &str, value: i64);

    fn __set_bool(self: &alloc::rc::Rc<Self>, path: &str, value: bool);

    fn __set_list_u8(self: &alloc::rc::Rc<Self>, path: &str, value: Vec<u8>);

    fn __set_void(self: &alloc::rc::Rc<Self>, path: &str);

    fn __set<T: Store<Self>>(self: &alloc::rc::Rc<Self>, path: DotPathBuf, value: T);

    /// Tombstone a single path. Returns true if a live value was removed.
    fn __delete(self: &alloc::rc::Rc<Self>, path: &str) -> bool;

    fn __delete_matching_paths(
        self: &alloc::rc::Rc<Self>,
        base_path: &str,
        variants: &[&str],
    ) -> u64;
}

pub trait Store<T: WriteStorage + ?Sized> {
    fn __set(ctx: &alloc::rc::Rc<T>, base_path: DotPathBuf, value: Self);
}

impl<T: WriteStorage + ?Sized> Store<T> for u64 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: u64) {
        ctx.__set_u64(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for i64 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: i64) {
        ctx.__set_s64(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for u32 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: u32) {
        ctx.__set_u64(&path, value as u64);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for i32 {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: i32) {
        ctx.__set_s64(&path, value as i64);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for &str {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: &str) {
        ctx.__set_str(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for String {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: String) {
        ctx.__set_str(&path, &value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for bool {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: bool) {
        ctx.__set_bool(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for Vec<u8> {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, value: Vec<u8>) {
        ctx.__set_list_u8(&path, value);
    }
}

impl<T: WriteStorage + ?Sized> Store<T> for () {
    fn __set(ctx: &alloc::rc::Rc<T>, path: DotPathBuf, _: ()) {
        ctx.__set_void(&path);
    }
}

impl<S: WriteStorage + ?Sized, T: Store<S>> Store<S> for Option<T> {
    fn __set(ctx: &alloc::rc::Rc<S>, path: DotPathBuf, value: Self) {
        ctx.__delete_matching_paths(&path, &["none", "some"]);
        match value {
            Some(inner) => ctx.__set(path.push("some"), inner),
            None => ctx.__set(path.push("none"), ()),
        }
    }
}

pub trait HasNext {
    fn next(&self) -> Option<String>;
}

pub fn make_keys_iterator<K, T>(keys: K) -> impl Iterator<Item = T>
where
    K: HasNext,
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    struct KeysIterator<K, T>
    where
        K: HasNext,
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        keys: K,
        _phantom: core::marker::PhantomData<T>,
    }

    impl<K, T> Iterator for KeysIterator<K, T>
    where
        K: HasNext,
        T: FromStr,
        <T as FromStr>::Err: Debug,
    {
        type Item = T;
        fn next(&mut self) -> Option<Self::Item> {
            self.keys.next().map(|s| T::from_str(&s).unwrap())
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

impl<K: ToString + FromStr + Clone, V: Store<S> + Clone, S: WriteStorage + ?Sized> Store<S>
    for StorageMap<K, V, S>
{
    fn __set(ctx: &alloc::rc::Rc<S>, base_path: DotPathBuf, value: StorageMap<K, V, S>) {
        for (k, v) in value.entries.into_iter() {
            ctx.__set(base_path.push(k.to_string()), v)
        }
    }
}
