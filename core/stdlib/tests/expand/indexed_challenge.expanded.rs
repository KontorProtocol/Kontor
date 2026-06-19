use stdlib::Storage;
struct Challenge {
    id: String,
    #[index]
    status: u64,
    #[index]
    prover_id: u64,
    seed: u64,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Challenge {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: Challenge,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.id);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(1u8), value.status);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(2u8), value.prover_id);
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(3u8), value.seed);
    }
}
pub struct ChallengeModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ChallengeModel {
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
        let __idx_status = self.status();
        let __idx_prover_id = self.prover_id();
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name_id: 0u8,
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
    }
    pub fn id(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn prover_id(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn seed(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(3u8)).unwrap()
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            id: self.id(),
            status: self.status(),
            prover_id: self.prover_id(),
            seed: self.seed(),
        }
    }
}
pub struct ChallengeWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ChallengeModel,
}
impl ChallengeWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
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
    pub fn id(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn prover_id(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn seed(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(3u8)).unwrap()
    }
    pub fn set_id(&self, value: String) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_id(&self, f: impl Fn(String) -> String) {
        let path = self.base_path.push_interned(0u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_id(
        &self,
        f: impl Fn(String) -> Result<String, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_status(&self, value: u64) {
        let path = self.base_path.push_interned(1u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
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
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
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
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 0u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_prover_id(&self, value: u64) {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = value;
        if let Some((index_root, index_key)) = &self.index_binding {
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_prover_id(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_prover_id(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(2u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        if let Some((index_root, index_key)) = &self.index_binding {
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name_id: 1u8,
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_seed(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(3u8), value);
    }
    pub fn update_seed(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(3u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_seed(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(3u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            id: self.id(),
            status: self.status(),
            prover_id: self.prover_id(),
            seed: self.seed(),
        }
    }
}
impl core::ops::Deref for ChallengeWriteModel {
    type Target = ChallengeModel;
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
            });
        entries
            .push(stdlib::IndexEntry {
                name_id: 1u8,
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: stdlib::KeyElement + Clone,
{
    /// Raw bucket scan — yields the primary keys of an unsorted index
    /// bucket, identified by the index's interned id and its bucket segments
    /// `<bucket…>` (one per `by` field). The returned iterator owns its
    /// source (`use<Self, K>`, no lifetime capture), so the typed wrappers
    /// can hand it borrows of temporary key strings.
    fn by_index(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// Ordered bucket scan for a *sorted* index: the bucket's `(sort, pk)`
    /// tuple child members, wrapped in a `SortedScan` that yields `K` in sort
    /// order and bounds `up_to`/`range` on the decoded sort value. `S` is the
    /// index's sort field type, so the wrong bound type is a compile error.
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_id: u8,
        bucket: &[&[u8]],
    ) -> stdlib::SortedScan<K, S>;
    /// O(1) member count of an `(index_id, bucket…)` bucket, the
    /// framework-maintained size of what the scans would walk.
    fn bucket_count(&self, index_id: u8, bucket: &[&[u8]]) -> u64;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.by_index(0u8, &[__b0.as_slice()])
    }
    fn count_status(&self, status: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.bucket_count(0u8, &[__b0.as_slice()])
    }
    fn where_prover_id(&self, prover_id: u64) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&prover_id);
        self.by_index(1u8, &[__b0.as_slice()])
    }
    fn count_prover_id(&self, prover_id: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&prover_id);
        self.bucket_count(1u8, &[__b0.as_slice()])
    }
}
