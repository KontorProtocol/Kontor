use stdlib::Model;
struct FibValue {
    pub value: u64,
}
pub struct FibValueModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl FibValueModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
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
pub struct FibValueWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: FibValueModel,
}
impl FibValueWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
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
impl core::ops::Deref for FibValueWriteModel {
    type Target = FibValueModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
pub struct FibStorageModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl FibStorageModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
    }
    pub fn cache(&self) -> FibStorageCacheModel {
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
pub struct FibStorageCacheModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageCacheModel {
    #[inline]
    fn clone(&self) -> FibStorageCacheModel {
        FibStorageCacheModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl FibStorageCacheModel {
    pub fn get(&self, key: &u64) -> Option<FibValueModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| FibValueModel::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl stdlib::IndexScan<u64> for FibStorageCacheModel {
    fn by_index(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        from: Option<&[u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (S, u64)>> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_keys_from::<(S, u64)>(&self.ctx, &bucket, from),
        )
    }
    fn by_index_rows(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        from: Option<&[u8]>,
    ) -> alloc::boxed::Box<
        dyn Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>,
    > {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_index_rows(&self.ctx, &bucket, from),
        )
    }
    fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64 {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
impl FibValueIndex<u64> for FibStorageCacheModel {}
pub struct FibStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: FibStorageModel,
}
impl FibStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
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
    pub fn cache(&self) -> FibStorageCacheWriteModel {
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
impl core::ops::Deref for FibStorageWriteModel {
    type Target = FibStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct FibStorageCacheWriteModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageCacheWriteModel {
    #[inline]
    fn clone(&self) -> FibStorageCacheWriteModel {
        FibStorageCacheWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl FibStorageCacheWriteModel {
    pub fn get(&self, key: &u64) -> Option<FibValueWriteModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                FibValueWriteModel::new(self.ctx.clone(), base_path)
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
impl stdlib::IndexScan<u64> for FibStorageCacheWriteModel {
    fn by_index(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        from: Option<&[u8]>,
    ) -> alloc::boxed::Box<dyn Iterator<Item = (S, u64)>> {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_keys_from::<(S, u64)>(&self.ctx, &bucket, from),
        )
    }
    fn by_index_rows(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
        from: Option<&[u8]>,
    ) -> alloc::boxed::Box<
        dyn Iterator<Item = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>,
    > {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        alloc::boxed::Box::new(
            stdlib::ReadStorage::__get_index_rows(&self.ctx, &bucket, from),
        )
    }
    fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64 {
        let bucket = self.index_path.push_interned(index_id).push_raw_elements(bucket);
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
impl FibValueIndex<u64> for FibStorageCacheWriteModel {}
