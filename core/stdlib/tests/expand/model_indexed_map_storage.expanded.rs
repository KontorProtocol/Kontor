use stdlib::{Indexed, Model, Storage};
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
impl stdlib::Store<crate::context::ProcStorage> for Challenge {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: Challenge,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push("prover"), value.prover);
        stdlib::WriteStorage::__set(ctx, base_path.push("status"), value.status);
        stdlib::WriteStorage::__set(ctx, base_path.push("deadline"), value.deadline);
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
        let __idx_deadline = self.deadline();
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name: "status",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name: "due",
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
            });
        entries
    }
    pub fn prover(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("prover")).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("status")).unwrap()
    }
    pub fn deadline(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("deadline")).unwrap()
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            prover: self.prover(),
            status: self.status(),
            deadline: self.deadline(),
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
    pub fn prover(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("prover")).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("status")).unwrap()
    }
    pub fn deadline(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("deadline")).unwrap()
    }
    pub fn set_prover(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push("prover"), value);
    }
    pub fn update_prover(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("prover");
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_prover(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("prover");
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_status(&self, value: u64) {
        let path = self.base_path.push("status");
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
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_status(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("status");
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
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
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
        let path = self.base_path.push("status");
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
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "status",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&__idx_deadline)),
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_deadline(&self, value: u64) {
        let path = self.base_path.push("deadline");
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
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_deadline(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("deadline");
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
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
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
        let path = self.base_path.push("deadline");
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
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&old)),
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "due",
                        bucket: (/*ERROR*/),
                        sort: Some(stdlib::KeyElement::encode(&new)),
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
impl core::ops::Deref for ChallengeWriteModel {
    type Target = ChallengeModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
#[automatically_derived]
impl stdlib::Indexed for Challenge {
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name: "status",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name: "due",
                bucket: (/*ERROR*/),
                sort: Some(stdlib::KeyElement::encode(&self.deadline)),
            });
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: stdlib::KeyElement + Clone,
{
    /// Raw bucket scan — yields the primary keys of an unsorted index
    /// bucket, identified by its segments `<bucket…>` (one per `by` field).
    /// The returned iterator owns its source (`use<Self, K>`, no lifetime
    /// capture), so the typed wrappers can hand it borrows of temporary key
    /// strings.
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// Ordered bucket scan for a *sorted* index: the bucket's `(sort, pk)`
    /// tuple child members, wrapped in a `SortedScan` that yields `K` in sort
    /// order and bounds `up_to`/`range` on the decoded sort value. `S` is the
    /// index's sort field type, so the wrong bound type is a compile error.
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> stdlib::SortedScan<K, S>;
    /// O(1) member count of an `(index_name, bucket…)` bucket, the
    /// framework-maintained size of what the scans would walk.
    fn bucket_count(&self, index_name: &str, bucket: &[&[u8]]) -> u64;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.by_index("status", &[__b0.as_slice()])
    }
    fn count_status(&self, status: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.bucket_count("status", &[__b0.as_slice()])
    }
    fn where_due(&self, status: u64) -> stdlib::SortedScan<K, u64> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.by_index_sorted::<u64>("due", &[__b0.as_slice()])
    }
    fn count_due(&self, status: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.bucket_count("due", &[__b0.as_slice()])
    }
}
struct ChallengeStorage {
    pub challenges: IndexedMap<u64, Challenge>,
}
pub struct ChallengeStorageModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ChallengeStorageModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn challenges(&self) -> ChallengeStorageChallengesModel {
        ChallengeStorageChallengesModel {
            base_path: self.base_path.push("challenges"),
            index_path: self.base_path.push("challenges#idx"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> ChallengeStorage {
        ChallengeStorage {
            challenges: self.challenges().load(),
        }
    }
}
pub struct ChallengeStorageChallengesModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for ChallengeStorageChallengesModel {
    #[inline]
    fn clone(&self) -> ChallengeStorageChallengesModel {
        ChallengeStorageChallengesModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl ChallengeStorageChallengesModel {
    pub fn get(&self, key: &u64) -> Option<ChallengeModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| ChallengeModel::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> IndexedMap<u64, Challenge> {
        IndexedMap::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl ChallengeIndex<u64> for ChallengeStorageChallengesModel {
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> stdlib::SortedScan<u64, S> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        let members = stdlib::ReadStorage::__get_keys::<(S, u64)>(&self.ctx, &bucket);
        stdlib::SortedScan::new(alloc::boxed::Box::new(members))
    }
    fn bucket_count(&self, index_name: &str, bucket: &[&[u8]]) -> u64 {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
pub struct ChallengeStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    model: ChallengeStorageModel,
}
impl ChallengeStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: ChallengeStorageModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn challenges(&self) -> ChallengeStorageChallengesWriteModel {
        ChallengeStorageChallengesWriteModel {
            base_path: self.base_path.push("challenges"),
            index_path: self.base_path.push("challenges#idx"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> ChallengeStorage {
        ChallengeStorage {
            challenges: self.challenges().load(),
        }
    }
}
impl core::ops::Deref for ChallengeStorageWriteModel {
    type Target = ChallengeStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct ChallengeStorageChallengesWriteModel {
    pub base_path: stdlib::KeyPath,
    index_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for ChallengeStorageChallengesWriteModel {
    #[inline]
    fn clone(&self) -> ChallengeStorageChallengesWriteModel {
        ChallengeStorageChallengesWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            index_path: ::core::clone::Clone::clone(&self.index_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl ChallengeStorageChallengesWriteModel {
    pub fn get(&self, key: &u64) -> Option<ChallengeWriteModel> {
        let base_path = self.base_path.push_element(key);
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                ChallengeWriteModel::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), stdlib::KeyElement::encode(key))
            })
    }
    pub fn set(&self, key: &u64, value: Challenge) {
        let key_bytes = stdlib::KeyElement::encode(key);
        let new_entries = stdlib::Indexed::index_entries(&value);
        let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
        stdlib::apply_index_diff(
            &self.ctx,
            &self.index_path,
            &key_bytes,
            &old_entries,
            &new_entries,
        );
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_element(key), value);
    }
    /// Remove the entry and its index rows. Returns true if a live value existed.
    pub fn remove(&self, key: &u64) -> bool {
        let key_bytes = stdlib::KeyElement::encode(key);
        let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
        stdlib::apply_index_diff(
            &self.ctx,
            &self.index_path,
            &key_bytes,
            &old_entries,
            &[],
        );
        stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push_element(key))
    }
    pub fn load(&self) -> IndexedMap<u64, Challenge> {
        IndexedMap::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl ChallengeIndex<u64> for ChallengeStorageChallengesWriteModel {
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> stdlib::SortedScan<u64, S> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        let members = stdlib::ReadStorage::__get_keys::<(S, u64)>(&self.ctx, &bucket);
        stdlib::SortedScan::new(alloc::boxed::Box::new(members))
    }
    fn bucket_count(&self, index_name: &str, bucket: &[&[u8]]) -> u64 {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push_raw_element(seg));
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
