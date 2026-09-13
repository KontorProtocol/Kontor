use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::{
    marker::PhantomData,
    ops::{Bound, RangeBounds},
};

use crate::{KeyElement, KeyPath, ReadStorage, ScalarStorage, decode_storage, keycodec};

/// The generated model supplies a bucket once; every query uses the same
/// bounded storage cursor rather than a separate scan implementation per index kind.
pub trait IndexScan<K: KeyElement + Clone> {
    type Storage: ReadStorage + 'static;

    #[doc(hidden)]
    fn __index_bucket(&self, index_id: u8, bucket: &[&[u8]]) -> KeyRange<K, Self::Storage>;
}

#[derive(Default)]
struct ScanBounds {
    lo: Option<Vec<u8>>,
    hi: Option<Vec<u8>>,
}

impl ScanBounds {
    fn new<T>(
        range: &impl RangeBounds<T>,
        lower: impl Fn(&T) -> Vec<u8>,
        upper: impl Fn(&T) -> Vec<u8>,
    ) -> Self {
        Self {
            lo: match range.start_bound() {
                Bound::Unbounded => None,
                Bound::Included(value) => Some(lower(value)),
                Bound::Excluded(value) => Some(upper(value)),
            },
            hi: match range.end_bound() {
                Bound::Unbounded => None,
                Bound::Included(value) => Some(upper(value)),
                Bound::Excluded(value) => Some(lower(value)),
            },
        }
    }

    fn keys<K: KeyElement>(range: &impl RangeBounds<K>) -> Self {
        // Advancing beyond the entire element also skips a struct value's
        // descendants; merely excluding its parent row would re-emit the key.
        Self::new(range, KeyElement::encode, |key| {
            keycodec::subtree_end(&key.encode())
        })
    }

    fn sorted<S: KeyElement>(range: &impl RangeBounds<S>) -> Self {
        Self::new(range, sort_lower_bound, sort_upper_bound)
    }
}

/// Inclusive seek before every `(sort, primary_key)` member with this sort value.
pub fn sort_lower_bound<S: KeyElement>(value: &S) -> Vec<u8> {
    keycodec::tuple_from_elements(&[value.encode().as_slice()])
}

/// Exclusive seek after every `(sort, primary_key)` member with this sort value.
pub fn sort_upper_bound<S: KeyElement>(value: &S) -> Vec<u8> {
    keycodec::tuple_lead_upper_bound(&value.encode())
}

/// A key-bounded map or index scan. Bounds are database seeks; `.rev()` changes
/// direction without changing membership. No full-map or bucket count is exposed.
pub struct KeyRange<K, S, V = ()> {
    ctx: Rc<S>,
    path: KeyPath,
    bounds: ScanBounds,
    descending: bool,
    _key: PhantomData<(K, V)>,
}

impl<K: KeyElement + Clone + 'static, S: ReadStorage + 'static, V> KeyRange<K, S, V> {
    #[doc(hidden)]
    pub fn new(ctx: Rc<S>, path: KeyPath, range: impl RangeBounds<K>) -> Self {
        Self {
            ctx,
            path,
            bounds: ScanBounds::keys(&range),
            descending: false,
            _key: PhantomData,
        }
    }

    pub fn rev(mut self) -> Self {
        self.descending = !self.descending;
        self
    }

    pub fn keys(self) -> impl Iterator<Item = K> {
        self.ctx.__get_keys_range(
            &self.path,
            self.bounds.lo.as_deref(),
            self.bounds.hi.as_deref(),
            self.descending,
        )
    }

    pub fn iter(self) -> impl Iterator<Item = K> {
        self.keys()
    }

    fn rows(self) -> impl Iterator<Item = (K, Vec<u8>)> {
        self.ctx
            .__get_storage_rows_range(
                &self.path,
                self.bounds.lo.as_deref(),
                self.bounds.hi.as_deref(),
                self.descending,
            )
            .map(|(member, value)| {
                (
                    K::decode_from(&member)
                        .expect("index member decodes into its key")
                        .0,
                    value,
                )
            })
    }

    fn restrict(mut self, range: impl RangeBounds<K>) -> Self {
        self.bounds = ScanBounds::keys(&range);
        self
    }

    fn sorted<T: KeyElement + Clone + 'static>(
        self,
        range: impl RangeBounds<T>,
    ) -> KeyRange<(T, K), S> {
        KeyRange {
            ctx: self.ctx,
            path: self.path,
            bounds: ScanBounds::sorted(&range),
            descending: self.descending,
            _key: PhantomData,
        }
    }

    fn bucket_count(&self) -> u64 {
        self.ctx.__get_u64(&self.path).unwrap_or(0)
    }
}

impl<K: KeyElement + Clone + 'static, S: ReadStorage + 'static, V: 'static> IntoIterator
    for KeyRange<K, S, V>
{
    type Item = K;
    type IntoIter = Box<dyn Iterator<Item = K>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.keys())
    }
}

impl<K, S, V> KeyRange<K, S, V>
where
    K: KeyElement + Clone + 'static,
    S: ReadStorage + 'static,
    V: ScalarStorage,
{
    pub fn entries(self) -> impl Iterator<Item = (K, V)> {
        self.rows()
            .map(|(key, value)| (key, V::decode_storage(&value)))
    }
}

fn bucket<K: KeyElement + Clone, Src: IndexScan<K>>(
    src: &Src,
    index_id: u8,
    values: &[Vec<u8>],
) -> KeyRange<K, Src::Storage> {
    let refs: Vec<_> = values.iter().map(Vec::as_slice).collect();
    src.__index_bucket(index_id, &refs)
}

/// All primary keys in one equality bucket. Only this unrestricted view has the
/// framework-maintained O(1) `.len()`; `.range()` returns a bounded key scan.
pub struct IndexQuery<'a, K, Src> {
    src: &'a Src,
    index_id: u8,
    bucket: Vec<Vec<u8>>,
    descending: bool,
    _key: PhantomData<K>,
}

impl<'a, K, Src> IndexQuery<'a, K, Src>
where
    K: KeyElement + Clone + 'static,
    Src: IndexScan<K>,
{
    pub fn new(src: &'a Src, index_id: u8, bucket: Vec<Vec<u8>>) -> Self {
        Self {
            src,
            index_id,
            bucket,
            descending: false,
            _key: PhantomData,
        }
    }
    pub fn len(&self) -> u64 {
        bucket(self.src, self.index_id, &self.bucket).bucket_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn rev(mut self) -> Self {
        self.descending = !self.descending;
        self
    }
    pub fn range(self, range: impl RangeBounds<K>) -> KeyRange<K, Src::Storage> {
        let mut scan = bucket(self.src, self.index_id, &self.bucket).restrict(range);
        scan.descending = self.descending;
        scan
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.range(..).keys()
    }
    pub fn iter(self) -> impl Iterator<Item = K> {
        self.keys()
    }
}

impl<K, Src> IntoIterator for IndexQuery<'_, K, Src>
where
    K: KeyElement + Clone + 'static,
    Src: IndexScan<K>,
{
    type Item = K;
    type IntoIter = Box<dyn Iterator<Item = K>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.range(..).keys())
    }
}

/// An index bounded by its declared sort value, with the primary key breaking ties.
pub struct SortedRange<K, T, S> {
    scan: KeyRange<(T, K), S>,
}

impl<K, T, S> SortedRange<K, T, S>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    S: ReadStorage + 'static,
{
    pub fn rev(mut self) -> Self {
        self.scan = self.scan.rev();
        self
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.scan.keys().map(|(_, key)| key)
    }
    pub fn values(self) -> impl Iterator<Item = T> {
        self.scan.keys().map(|(sort, _)| sort)
    }
    pub fn iter(self) -> impl Iterator<Item = (K, T)> {
        self.scan.keys().map(|(sort, key)| (key, sort))
    }
}

impl<K, T, S> IntoIterator for SortedRange<K, T, S>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    S: ReadStorage + 'static,
{
    type Item = (K, T);
    type IntoIter = Box<dyn Iterator<Item = (K, T)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

pub struct SortedIndexQuery<'a, K, T, Src> {
    src: &'a Src,
    index_id: u8,
    bucket: Vec<Vec<u8>>,
    descending: bool,
    _key: PhantomData<(K, T)>,
}

impl<'a, K, T, Src> SortedIndexQuery<'a, K, T, Src>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    Src: IndexScan<K>,
{
    pub fn new(src: &'a Src, index_id: u8, bucket: Vec<Vec<u8>>) -> Self {
        Self {
            src,
            index_id,
            bucket,
            descending: false,
            _key: PhantomData,
        }
    }
    pub fn len(&self) -> u64 {
        bucket(self.src, self.index_id, &self.bucket).bucket_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn rev(mut self) -> Self {
        self.descending = !self.descending;
        self
    }
    pub fn range(self, range: impl RangeBounds<T>) -> SortedRange<K, T, Src::Storage> {
        let mut scan = bucket(self.src, self.index_id, &self.bucket).sorted(range);
        scan.descending = self.descending;
        SortedRange { scan }
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.range(..).keys()
    }
    pub fn values(self) -> impl Iterator<Item = T> {
        self.range(..).values()
    }
    pub fn iter(self) -> impl Iterator<Item = (K, T)> {
        self.range(..).iter()
    }
}

impl<K, T, Src> IntoIterator for SortedIndexQuery<'_, K, T, Src>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    Src: IndexScan<K>,
{
    type Item = (K, T);
    type IntoIter = Box<dyn Iterator<Item = (K, T)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.range(..).iter())
    }
}

/// A key range with a covering projection. `.keys()` avoids reading projections.
pub struct CoveringRange<K, V, S> {
    scan: KeyRange<K, S>,
    build: fn(&[u8]) -> V,
}

impl<K, V, S> CoveringRange<K, V, S>
where
    K: KeyElement + Clone + 'static,
    V: 'static,
    S: ReadStorage + 'static,
{
    pub fn rev(mut self) -> Self {
        self.scan = self.scan.rev();
        self
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.scan.keys()
    }
    pub fn values(self) -> impl Iterator<Item = V> {
        self.scan
            .rows()
            .map(move |(_, value)| (self.build)(decode_storage(&value)))
    }
    pub fn iter(self) -> impl Iterator<Item = (K, V)> {
        self.scan
            .rows()
            .map(move |(key, value)| (key, (self.build)(decode_storage(&value))))
    }
}

impl<K, V, S> IntoIterator for CoveringRange<K, V, S>
where
    K: KeyElement + Clone + 'static,
    V: 'static,
    S: ReadStorage + 'static,
{
    type Item = (K, V);
    type IntoIter = Box<dyn Iterator<Item = (K, V)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

pub struct CoveringQuery<'a, K, V, Src> {
    src: &'a Src,
    index_id: u8,
    bucket: Vec<Vec<u8>>,
    descending: bool,
    build: fn(&[u8]) -> V,
    _key: PhantomData<K>,
}

impl<'a, K, V, Src> CoveringQuery<'a, K, V, Src>
where
    K: KeyElement + Clone + 'static,
    V: 'static,
    Src: IndexScan<K>,
{
    pub fn new(src: &'a Src, index_id: u8, bucket: Vec<Vec<u8>>, build: fn(&[u8]) -> V) -> Self {
        Self {
            src,
            index_id,
            bucket,
            descending: false,
            build,
            _key: PhantomData,
        }
    }
    pub fn len(&self) -> u64 {
        bucket(self.src, self.index_id, &self.bucket).bucket_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn rev(mut self) -> Self {
        self.descending = !self.descending;
        self
    }
    pub fn range(self, range: impl RangeBounds<K>) -> CoveringRange<K, V, Src::Storage> {
        let mut scan = bucket(self.src, self.index_id, &self.bucket).restrict(range);
        scan.descending = self.descending;
        CoveringRange {
            scan,
            build: self.build,
        }
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.range(..).keys()
    }
    pub fn values(self) -> impl Iterator<Item = V> {
        self.range(..).values()
    }
    pub fn iter(self) -> impl Iterator<Item = (K, V)> {
        self.range(..).iter()
    }
}

impl<K, V, Src> IntoIterator for CoveringQuery<'_, K, V, Src>
where
    K: KeyElement + Clone + 'static,
    V: 'static,
    Src: IndexScan<K>,
{
    type Item = (K, V);
    type IntoIter = Box<dyn Iterator<Item = (K, V)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.range(..).iter())
    }
}

pub struct SortedCoveringRange<K, T, V, S> {
    scan: KeyRange<(T, K), S>,
    build: fn(&T, &[u8]) -> V,
}

impl<K, T, V, S> SortedCoveringRange<K, T, V, S>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    V: 'static,
    S: ReadStorage + 'static,
{
    pub fn rev(mut self) -> Self {
        self.scan = self.scan.rev();
        self
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.scan.keys().map(|(_, key)| key)
    }
    pub fn with_scores(self) -> impl Iterator<Item = (K, T)> {
        self.scan.keys().map(|(sort, key)| (key, sort))
    }
    pub fn values(self) -> impl Iterator<Item = V> {
        self.scan
            .rows()
            .map(move |((sort, _), value)| (self.build)(&sort, decode_storage(&value)))
    }
    pub fn iter(self) -> impl Iterator<Item = (K, V)> {
        self.scan
            .rows()
            .map(move |((sort, key), value)| (key, (self.build)(&sort, decode_storage(&value))))
    }
}

impl<K, T, V, S> IntoIterator for SortedCoveringRange<K, T, V, S>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    V: 'static,
    S: ReadStorage + 'static,
{
    type Item = (K, V);
    type IntoIter = Box<dyn Iterator<Item = (K, V)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

pub struct SortedCoveringQuery<'a, K, T, V, Src> {
    src: &'a Src,
    index_id: u8,
    bucket: Vec<Vec<u8>>,
    descending: bool,
    build: fn(&T, &[u8]) -> V,
    _key: PhantomData<(K, T)>,
}

impl<'a, K, T, V, Src> SortedCoveringQuery<'a, K, T, V, Src>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    V: 'static,
    Src: IndexScan<K>,
{
    pub fn new(
        src: &'a Src,
        index_id: u8,
        bucket: Vec<Vec<u8>>,
        build: fn(&T, &[u8]) -> V,
    ) -> Self {
        Self {
            src,
            index_id,
            bucket,
            descending: false,
            build,
            _key: PhantomData,
        }
    }
    pub fn len(&self) -> u64 {
        bucket(self.src, self.index_id, &self.bucket).bucket_count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn rev(mut self) -> Self {
        self.descending = !self.descending;
        self
    }
    pub fn range(self, range: impl RangeBounds<T>) -> SortedCoveringRange<K, T, V, Src::Storage> {
        let mut scan = bucket(self.src, self.index_id, &self.bucket).sorted(range);
        scan.descending = self.descending;
        SortedCoveringRange {
            scan,
            build: self.build,
        }
    }
    pub fn keys(self) -> impl Iterator<Item = K> {
        self.range(..).keys()
    }
    pub fn with_scores(self) -> impl Iterator<Item = (K, T)> {
        self.range(..).with_scores()
    }
    pub fn values(self) -> impl Iterator<Item = V> {
        self.range(..).values()
    }
    pub fn iter(self) -> impl Iterator<Item = (K, V)> {
        self.range(..).iter()
    }
}

impl<K, T, V, Src> IntoIterator for SortedCoveringQuery<'_, K, T, V, Src>
where
    K: KeyElement + Clone + 'static,
    T: KeyElement + Clone + 'static,
    V: 'static,
    Src: IndexScan<K>,
{
    type Item = (K, V);
    type IntoIter = Box<dyn Iterator<Item = (K, V)>>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.range(..).iter())
    }
}
