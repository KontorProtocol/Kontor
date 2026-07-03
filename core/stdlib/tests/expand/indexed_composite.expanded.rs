use stdlib::{Model, Storage};
#[index(eligible, by = (active, challenge))]
struct Agreement {
    #[index]
    active: bool,
    challenge: Option<u64>,
}
#[automatically_derived]
impl ::core::clone::Clone for Agreement {
    #[inline]
    fn clone(&self) -> Agreement {
        Agreement {
            active: ::core::clone::Clone::clone(&self.active),
            challenge: ::core::clone::Clone::clone(&self.challenge),
        }
    }
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Agreement {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: Agreement,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.active);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(1u8), value.challenge);
    }
}
pub struct AgreementModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl AgreementModel {
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
        let __idx_active = self.active();
        let __idx_challenge = self.challenge();
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
                sort: None,
                projection: None,
            });
        entries
    }
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn challenge(&self) -> Option<u64> {
        let base_path = self.base_path.push_interned(1u8);
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &[stdlib::string_element("none")],
            )
            .is_some()
        {
            None
        } else {
            stdlib::ReadStorage::__get(&self.ctx, base_path.push("some"))
        }
    }
    pub fn load(&self) -> Agreement {
        Agreement {
            active: self.active(),
            challenge: self.challenge(),
        }
    }
}
pub struct AgreementWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: AgreementModel,
}
impl AgreementWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: AgreementModel::new(
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
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn challenge(&self) -> Option<u64> {
        let base_path = self.base_path.push_interned(1u8);
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &[stdlib::string_element("none")],
            )
            .is_some()
        {
            None
        } else {
            stdlib::ReadStorage::__get(&self.ctx, base_path.push("some"))
        }
    }
    pub fn set_active(&self, value: bool) {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_challenge = self.challenge();
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
                        sort: None,
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
                        sort: None,
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_active(&self, f: impl Fn(bool) -> bool) {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_challenge = self.challenge();
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
                        sort: None,
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
                        sort: None,
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_active(
        &self,
        f: impl Fn(bool) -> Result<bool, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: bool = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_challenge = self.challenge();
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
                        sort: None,
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
                        sort: None,
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_challenge(&self, value: Option<u64>) {
        let path = self.base_path.push_interned(1u8);
        let old = self.challenge();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            let __idx_active = self.active();
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                        projection: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn load(&self) -> Agreement {
        Agreement {
            active: self.active(),
            challenge: self.challenge(),
        }
    }
}
impl core::ops::Deref for AgreementWriteModel {
    type Target = AgreementModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
#[automatically_derived]
impl stdlib::Indexed for Agreement {
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
                sort: None,
                projection: None,
            });
        entries
    }
}
pub trait AgreementIndex<K>: stdlib::IndexScan<K> + Sized
where
    K: stdlib::KeyElement + Clone + 'static,
{
    fn active(&self, active: bool) -> stdlib::IndexQuery<'_, K, Self> {
        let __b0 = stdlib::IndexKey::index_key(&active);
        stdlib::IndexQuery::new(self, 0u8, alloc::vec::Vec::from([__b0]))
    }
    fn eligible(
        &self,
        active: bool,
        challenge: impl core::convert::Into<stdlib::Presence>,
    ) -> stdlib::IndexQuery<'_, K, Self> {
        let __b0 = stdlib::IndexKey::index_key(&active);
        let __b1 = {
            let __p: stdlib::Presence = challenge.into();
            stdlib::IndexKey::index_key(&__p)
        };
        stdlib::IndexQuery::new(self, 1u8, alloc::vec::Vec::from([__b0, __b1]))
    }
}
struct AgreementStorage {
    agreements: Map<u64, Agreement>,
}
pub struct AgreementStorageModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl AgreementStorageModel {
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
    pub fn agreements(&self) -> AgreementStorageAgreementsModel {
        AgreementStorageAgreementsModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> AgreementStorage {
        AgreementStorage {
            agreements: self.agreements().load(),
        }
    }
}
pub struct AgreementStorageAgreementsModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for AgreementStorageAgreementsModel {
    #[inline]
    fn clone(&self) -> AgreementStorageAgreementsModel {
        AgreementStorageAgreementsModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl AgreementStorageAgreementsModel {
    pub fn get(&self, key: &u64) -> Option<AgreementModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| AgreementModel::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> Map<u64, Agreement> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl stdlib::IndexScan<u64> for AgreementStorageAgreementsModel {
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
impl AgreementIndex<u64> for AgreementStorageAgreementsModel {}
pub struct AgreementStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: AgreementStorageModel,
}
impl AgreementStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: AgreementStorageModel::new(
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
    pub fn agreements(&self) -> AgreementStorageAgreementsWriteModel {
        AgreementStorageAgreementsWriteModel {
            base_path: self.base_path.push_interned(0u8),
            index_path: self.base_path.push_interned(128u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> AgreementStorage {
        AgreementStorage {
            agreements: self.agreements().load(),
        }
    }
}
impl core::ops::Deref for AgreementStorageWriteModel {
    type Target = AgreementStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct AgreementStorageAgreementsWriteModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for AgreementStorageAgreementsWriteModel {
    #[inline]
    fn clone(&self) -> AgreementStorageAgreementsWriteModel {
        AgreementStorageAgreementsWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl AgreementStorageAgreementsWriteModel {
    pub fn get(&self, key: &u64) -> Option<AgreementWriteModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                AgreementWriteModel::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), stdlib::KeyElement::encode(key))
            })
    }
    pub fn set(&self, key: &u64, value: Agreement) {
        if <Agreement as stdlib::Indexed>::HAS_INDEXES {
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
        if <Agreement as stdlib::Indexed>::HAS_INDEXES {
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
    pub fn load(&self) -> Map<u64, Agreement> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl stdlib::IndexScan<u64> for AgreementStorageAgreementsWriteModel {
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
impl AgreementIndex<u64> for AgreementStorageAgreementsWriteModel {}
