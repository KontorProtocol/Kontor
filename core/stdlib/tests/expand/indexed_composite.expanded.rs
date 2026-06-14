use stdlib::{Indexed, Model, Storage};
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
        stdlib::WriteStorage::__set(ctx, base_path.push("active"), value.active);
        stdlib::WriteStorage::__set(ctx, base_path.push("challenge"), value.challenge);
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
                name: "active",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name: "eligible",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
    }
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("active")).unwrap()
    }
    pub fn challenge(&self) -> Option<u64> {
        let base_path = self.base_path.push("challenge");
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &["none"],
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
    index_binding: Option<(stdlib::KeyPath, alloc::string::String)>,
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
        index_key: alloc::string::String,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn active(&self) -> bool {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("active")).unwrap()
    }
    pub fn challenge(&self) -> Option<u64> {
        let base_path = self.base_path.push("challenge");
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &["none"],
            )
            .is_some()
        {
            None
        } else {
            stdlib::ReadStorage::__get(&self.ctx, base_path.push("some"))
        }
    }
    pub fn set_active(&self, value: bool) {
        let path = self.base_path.push("active");
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
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_active(&self, f: impl Fn(bool) -> bool) {
        let path = self.base_path.push("active");
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
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
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
        let path = self.base_path.push("active");
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
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "active",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_challenge(&self, value: Option<u64>) {
        let path = self.base_path.push("challenge");
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
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
                    },
                ],
                &[
                    stdlib::IndexEntry {
                        name: "eligible",
                        bucket: (/*ERROR*/),
                        sort: None,
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
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name: "active",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name: "eligible",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
    }
}
pub trait AgreementIndex<K>
where
    K: alloc::string::ToString + core::str::FromStr + Clone,
    <K as core::str::FromStr>::Err: core::fmt::Debug,
{
    /// Raw bucket scan — yields the primary keys of an unsorted index
    /// bucket, identified by its segments `<bucket…>` (one per `by` field).
    /// The returned iterator owns its source (`use<Self, K>`, no lifetime
    /// capture), so the typed wrappers can hand it borrows of temporary key
    /// strings.
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// Ordered bucket scan for a *sorted* index: the bucket's `<sort‖pk>`
    /// child segments, wrapped in a `SortedScan` that strips the
    /// `S::WIDTH`-char prefix to yield `K` and bounds `up_to`/`range` on the
    /// encoded prefix. `S` is the index's sort field type, so the bound type
    /// and the stored prefix width can't disagree.
    fn by_index_sorted<S: stdlib::SortKey>(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> stdlib::SortedScan<K, S>;
    /// O(1) member count of an `(index_name, bucket…)` bucket, the
    /// framework-maintained size of what the scans would walk.
    fn bucket_count(&self, index_name: &str, bucket: &[&str]) -> u64;
    fn where_active(&self, active: bool) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&active);
        self.by_index("active", &[__b0.as_ref()])
    }
    fn count_active(&self, active: bool) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&active);
        self.bucket_count("active", &[__b0.as_ref()])
    }
    fn where_eligible(
        &self,
        active: bool,
        challenge: impl core::convert::Into<stdlib::Presence>,
    ) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&active);
        let __b1 = {
            let __p: stdlib::Presence = challenge.into();
            stdlib::IndexKey::index_key(&__p)
        };
        self.by_index("eligible", &[__b0.as_ref(), __b1.as_ref()])
    }
    fn count_eligible(
        &self,
        active: bool,
        challenge: impl core::convert::Into<stdlib::Presence>,
    ) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&active);
        let __b1 = {
            let __p: stdlib::Presence = challenge.into();
            stdlib::IndexKey::index_key(&__p)
        };
        self.bucket_count("eligible", &[__b0.as_ref(), __b1.as_ref()])
    }
}
struct AgreementStorage {
    agreements: IndexedMap<u64, Agreement>,
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
    pub fn agreements(&self) -> AgreementStorageAgreementsModel {
        AgreementStorageAgreementsModel {
            base_path: self.base_path.push("agreements"),
            index_path: self.base_path.push("agreements#idx"),
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
        let base_path = self.base_path.push(key.to_string());
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| AgreementModel::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> IndexedMap<u64, Agreement> {
        IndexedMap::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl AgreementIndex<u64> for AgreementStorageAgreementsModel {
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::SortKey>(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> stdlib::SortedScan<u64, S> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        let segments = stdlib::ReadStorage::__get_keys::<
            alloc::string::String,
        >(&self.ctx, &bucket);
        stdlib::SortedScan::new(alloc::boxed::Box::new(segments))
    }
    fn bucket_count(&self, index_name: &str, bucket: &[&str]) -> u64 {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
pub struct AgreementStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
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
            model: AgreementStorageModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn agreements(&self) -> AgreementStorageAgreementsWriteModel {
        AgreementStorageAgreementsWriteModel {
            base_path: self.base_path.push("agreements"),
            index_path: self.base_path.push("agreements#idx"),
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
        let base_path = self.base_path.push(key.to_string());
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                AgreementWriteModel::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), key.to_string())
            })
    }
    pub fn set(&self, key: &u64, value: Agreement) {
        let key_str = key.to_string();
        let new_entries = stdlib::Indexed::index_entries(&value);
        let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
        stdlib::apply_index_diff(
            &self.ctx,
            &self.index_path,
            &key_str,
            &old_entries,
            &new_entries,
        );
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push(key_str), value);
    }
    /// Remove the entry and its index rows. Returns true if a live value existed.
    pub fn remove(&self, key: &u64) -> bool {
        let key_str = key.to_string();
        let old_entries = self.get(key).map(|m| m.__index_entries()).unwrap_or_default();
        stdlib::apply_index_diff(
            &self.ctx,
            &self.index_path,
            &key_str,
            &old_entries,
            &[],
        );
        stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push(key_str))
    }
    pub fn load(&self) -> IndexedMap<u64, Agreement> {
        IndexedMap::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = u64> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
impl AgreementIndex<u64> for AgreementStorageAgreementsWriteModel {
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
    fn by_index_sorted<S: stdlib::SortKey>(
        &self,
        index_name: &str,
        bucket: &[&str],
    ) -> stdlib::SortedScan<u64, S> {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        let segments = stdlib::ReadStorage::__get_keys::<
            alloc::string::String,
        >(&self.ctx, &bucket);
        stdlib::SortedScan::new(alloc::boxed::Box::new(segments))
    }
    fn bucket_count(&self, index_name: &str, bucket: &[&str]) -> u64 {
        let bucket = bucket
            .iter()
            .fold(self.index_path.push(index_name), |p, seg| p.push(*seg));
        stdlib::ReadStorage::__get_u64(&self.ctx, &bucket).unwrap_or(0)
    }
}
