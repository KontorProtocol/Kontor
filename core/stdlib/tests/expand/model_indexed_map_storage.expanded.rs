use stdlib::{Model, Storage};
#[index(due, by = status, sort = deadline)]
struct Challenge {
    pub prover: u64,
    #[index]
    pub status: u64,
    pub deadline: u64,
}
#[automatically_derived]
impl ::core::clone::Clone for Challenge {
    #[inline]
    fn clone(&self) -> Challenge {
        Challenge {
            prover: ::core::clone::Clone::clone(&self.prover),
            status: ::core::clone::Clone::clone(&self.status),
            deadline: ::core::clone::Clone::clone(&self.deadline),
        }
    }
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for Challenge {
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: Challenge) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.prover);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(1u8), value.status);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(2u8), value.deadline);
    }
}
pub struct ChallengeModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __ChallengeModelFor<__S> = ChallengeModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> ChallengeModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let __idx_status = self.status();
        let __idx_deadline = self.deadline();
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name_id: 0u8,
                bucket: (/*ERROR*/),
                sort: None,
                projection: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                projection: None,
            });
        entries
    }
    pub fn prover(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn deadline(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            prover: self.prover(),
            status: self.status(),
            deadline: self.deadline(),
        }
    }
}
pub struct ChallengeWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ChallengeModel<__S::View>,
}
#[doc(hidden)]
pub type __ChallengeWriteModelFor<__S> = ChallengeWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> ChallengeWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ChallengeModel::new(
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
    pub fn prover(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn deadline(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn set_prover(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_prover(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_prover(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_status(&self, value: u64) {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_deadline = self.deadline();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_status(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_deadline = self.deadline();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_status(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_deadline = self.deadline();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_deadline(&self, value: u64) {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_status = self.status();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_deadline(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_status = self.status();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_deadline(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_status = self.status();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            prover: self.prover(),
            status: self.status(),
            deadline: self.deadline(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for ChallengeWriteModel<__S> {
    type Target = ChallengeModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
#[automatically_derived]
impl stdlib::Indexed for Challenge {
    const HAS_INDEXES: bool = true;
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name_id: 0u8,
                bucket: (/*ERROR*/),
                sort: None,
                projection: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&self.deadline)),
                projection: None,
            });
        entries
    }
}
pub trait ChallengeIndex<K>: stdlib::IndexScan<K> + Sized
where
    K: stdlib::KeyElement + Clone + 'static,
{
    fn status(&self, status: u64) -> stdlib::IndexQuery<'_, K, Self> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        stdlib::IndexQuery::new(self, 0u8, alloc::vec::Vec::from([__b0]))
    }
    fn due(&self, status: u64) -> stdlib::SortedIndexQuery<'_, K, u64, Self> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        stdlib::SortedIndexQuery::new(self, 1u8, alloc::vec::Vec::from([__b0]))
    }
}
struct ChallengeStorage {
    pub challenges: Map<u64, Challenge>,
}
pub struct ChallengeStorageModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __ChallengeStorageModelFor<__S> = ChallengeStorageModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> ChallengeStorageModel<__S> {
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
    pub fn challenges(&self) -> ChallengeStorageChallengesModel<__S> {
        ChallengeStorageChallengesModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> ChallengeStorage {
        ChallengeStorage {
            challenges: self.challenges().load(),
        }
    }
}
pub struct ChallengeStorageChallengesModel<__S> {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for ChallengeStorageChallengesModel<__S> {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            index_path: self.index_path.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
impl<__S: stdlib::ReadStorage + 'static> ChallengeStorageChallengesModel<__S> {
    pub fn get(&self, key: &u64) -> Option<__ChallengeModelFor<__S>> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| __ChallengeModelFor::<__S>::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> Map<u64, Challenge> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl<__S: stdlib::ReadStorage + 'static> stdlib::IndexScan<u64>
for ChallengeStorageChallengesModel<__S> {
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
impl<__S: stdlib::ReadStorage + 'static> ChallengeIndex<u64>
for ChallengeStorageChallengesModel<__S> {}
pub struct ChallengeStorageWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ChallengeStorageModel<__S::View>,
}
#[doc(hidden)]
pub type __ChallengeStorageWriteModelFor<__S> = ChallengeStorageWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> ChallengeStorageWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ChallengeStorageModel::new(
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
    pub fn challenges(&self) -> ChallengeStorageChallengesWriteModel<__S> {
        ChallengeStorageChallengesWriteModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> ChallengeStorage {
        ChallengeStorage {
            challenges: self.challenges().load(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for ChallengeStorageWriteModel<__S> {
    type Target = ChallengeStorageModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct ChallengeStorageChallengesWriteModel<__S> {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for ChallengeStorageChallengesWriteModel<__S> {
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
> ChallengeStorageChallengesWriteModel<__S> {
    pub fn get(&self, key: &u64) -> Option<__ChallengeWriteModelFor<__S>> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                __ChallengeWriteModelFor::<__S>::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), stdlib::KeyElement::encode(key))
            })
    }
    pub fn set(&self, key: &u64, value: Challenge) {
        if <Challenge as stdlib::Indexed>::HAS_INDEXES {
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
        if <Challenge as stdlib::Indexed>::HAS_INDEXES {
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
    pub fn load(&self) -> Map<u64, Challenge> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> stdlib::IndexScan<u64> for ChallengeStorageChallengesWriteModel<__S> {
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
> ChallengeIndex<u64> for ChallengeStorageChallengesWriteModel<__S> {}
