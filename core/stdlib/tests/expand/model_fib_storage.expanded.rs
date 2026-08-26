use stdlib::Model;
struct FibValue {
    pub value: u64,
}
pub struct FibValueModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __FibValueModelFor<__S> = FibValueModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> FibValueModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
    }
    pub fn value(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn load(&self) -> FibValue {
        FibValue { value: self.value() }
    }
}
pub struct FibValueWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: FibValueModel<__S::View>,
}
#[doc(hidden)]
pub type __FibValueWriteModelFor<__S> = FibValueWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> FibValueWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: FibValueModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn with_index(
        mut self,
        index_root: stdlib::KeyPath,
        index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn value(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn set_value(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_value(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_value(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> FibValue {
        FibValue { value: self.value() }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for FibValueWriteModel<__S> {
    type Target = FibValueModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
pub struct FibStorageModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __FibStorageModelFor<__S> = FibStorageModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> FibStorageModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
    }
    pub fn cache(&self) -> FibStorageCacheModel<__S> {
        FibStorageCacheModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> FibStorage {
        FibStorage {
            cache: self.cache().load(),
        }
    }
}
pub struct FibStorageCacheModel<__S> {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for FibStorageCacheModel<__S> {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            index_path: self.index_path.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
impl<__S: stdlib::ReadStorage + 'static> FibStorageCacheModel<__S> {
    pub fn get(&self, key: &u64) -> Option<__FibValueModelFor<__S>> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| __FibValueModelFor::<__S>::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl<__S: stdlib::ReadStorage + 'static> stdlib::IndexScan<u64>
for FibStorageCacheModel<__S> {
    fn by_index(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<__S> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (S, u64)>> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_keys_range::<
                (S, u64),
            >(&self.ctx, &bucket, lo, hi, descending),
        )
    }
    fn by_index_rows(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> alloc::boxed::Box<
        dyn Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>,
    > {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_index_rows_range(
                &self.ctx,
                &bucket,
                lo,
                hi,
                descending,
            ),
        )
    }
    fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64 {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
impl<__S: stdlib::ReadStorage + 'static> FibValueIndex<u64>
for FibStorageCacheModel<__S> {}
pub struct FibStorageWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: FibStorageModel<__S::View>,
}
#[doc(hidden)]
pub type __FibStorageWriteModelFor<__S> = FibStorageWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> FibStorageWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: FibStorageModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn with_index(
        mut self,
        index_root: stdlib::KeyPath,
        index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn cache(&self) -> FibStorageCacheWriteModel<__S> {
        FibStorageCacheWriteModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> FibStorage {
        FibStorage {
            cache: self.cache().load(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for FibStorageWriteModel<__S> {
    type Target = FibStorageModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct FibStorageCacheWriteModel<__S> {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for FibStorageCacheWriteModel<__S> {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            index_path: self.index_path.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> FibStorageCacheWriteModel<__S> {
    pub fn get(&self, key: &u64) -> Option<__FibValueWriteModelFor<__S>> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                __FibValueWriteModelFor::<__S>::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), stdlib::KeyElement::encode(key))
            })
    }
    pub fn set(&self, key: &u64, value: FibValue) {
        if <FibValue as stdlib::Indexed>::HAS_INDEXES {
            let key_bytes = stdlib::KeyElement::encode(key);
            let new_entries = stdlib::Indexed::index_entries(&value);
            let old_entries = self
                .get(key)
                .map(|m| m.__index_entries())
                .unwrap_or_default();
            stdlib::apply_index_diff(
                &self.ctx,
                &self.index_path,
                &key_bytes,
                &old_entries,
                &new_entries,
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_element(key), value);
    }
    /// Remove the entry and its index rows. Returns true if a live value existed.
    pub fn remove(&self, key: &u64) -> bool {
        if <FibValue as stdlib::Indexed>::HAS_INDEXES {
            let key_bytes = stdlib::KeyElement::encode(key);
            let old_entries = self
                .get(key)
                .map(|m| m.__index_entries())
                .unwrap_or_default();
            stdlib::apply_index_diff(
                &self.ctx,
                &self.index_path,
                &key_bytes,
                &old_entries,
                &[],
            );
        }
        stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push_element(key))
    }
    pub fn load(&self) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> stdlib::IndexScan<u64> for FibStorageCacheWriteModel<__S> {
    fn by_index(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<__S> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (S, u64)>> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_keys_range::<
                (S, u64),
            >(&self.ctx, &bucket, lo, hi, descending),
        )
    }
    fn by_index_rows(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        descending: bool,
    ) -> alloc::boxed::Box<
        dyn Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>,
    > {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_index_rows_range(
                &self.ctx,
                &bucket,
                lo,
                hi,
                descending,
            ),
        )
    }
    fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64 {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> FibValueIndex<u64> for FibStorageCacheWriteModel<__S> {}
