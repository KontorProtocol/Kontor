use stdlib::{Indexed, Model, Storage};
struct Challenge {
    pub prover: u64,
    #[index]
    pub status: u64,
}
#[automatically_derived]
impl ::core::clone::Clone for Challenge {
    #[inline]
    fn clone(&self) -> Challenge {
        Challenge {
            prover: ::core::clone::Clone::clone(&self.prover),
            status: ::core::clone::Clone::clone(&self.status),
        }
    }
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Challenge {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
        value: Challenge,
    ) {
        stdlib::WriteStorage::__set(ctx, base_path.push("prover"), value.prover);
        stdlib::WriteStorage::__set(ctx, base_path.push("status"), value.status);
    }
}
pub struct ChallengeModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ChallengeModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(
        &self,
    ) -> alloc::vec::Vec<(&'static str, alloc::string::String)> {
        let mut entries = alloc::vec::Vec::new();
        entries.push(("status", stdlib::IndexKey::index_key(&self.status())));
        entries
    }
    pub fn prover(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("prover")).unwrap()
    }
    pub fn status(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("status")).unwrap()
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            prover: self.prover(),
            status: self.status(),
        }
    }
}
pub struct ChallengeWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::DotPathBuf, alloc::string::String)>,
    model: ChallengeModel,
}
impl ChallengeWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
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
        index_root: stdlib::DotPathBuf,
        index_key: alloc::string::String,
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
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[("status", stdlib::IndexKey::index_key(&old))],
                &[("status", stdlib::IndexKey::index_key(&new))],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn update_status(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("status");
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        if let Some((index_root, index_key)) = &self.index_binding {
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[("status", stdlib::IndexKey::index_key(&old))],
                &[("status", stdlib::IndexKey::index_key(&new))],
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
            stdlib::apply_index_diff(
                &self.ctx,
                index_root,
                index_key,
                &[("status", stdlib::IndexKey::index_key(&old))],
                &[("status", stdlib::IndexKey::index_key(&new))],
            );
        }
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Challenge {
        Challenge {
            prover: self.prover(),
            status: self.status(),
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
    fn index_entries(&self) -> alloc::vec::Vec<(&'static str, alloc::string::String)> {
        let mut entries = alloc::vec::Vec::new();
        entries.push(("status", stdlib::IndexKey::index_key(&self.status)));
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: alloc::string::ToString + core::str::FromStr + Clone,
    <K as core::str::FromStr>::Err: core::fmt::Debug,
{
    /// Raw bucket scan — the single primitive the field model supplies;
    /// the typed `where_*` methods wrap it. Kept public as an escape
    /// hatch for index keys built at runtime. The returned iterator owns
    /// its source (`use<Self, K>`, no lifetime capture), so the typed
    /// wrappers can hand it a borrow of a temporary key string.
    fn by_index(
        &self,
        index_name: &str,
        index_key: &str,
    ) -> impl Iterator<Item = K> + use<Self, K>;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        self.by_index("status", &stdlib::IndexKey::index_key(&status))
    }
}
struct ChallengeStorage {
    pub challenges: IndexedMap<u64, Challenge>,
}
pub struct ChallengeStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ChallengeStorageModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
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
    pub base_path: stdlib::DotPathBuf,
    index_path: stdlib::DotPathBuf,
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
        let base_path = self.base_path.push(key.to_string());
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
        index_key: &str,
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = self.index_path.push(index_name).push(index_key);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
}
pub struct ChallengeStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    model: ChallengeStorageModel,
}
impl ChallengeStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
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
    pub base_path: stdlib::DotPathBuf,
    index_path: stdlib::DotPathBuf,
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
        let base_path = self.base_path.push(key.to_string());
        stdlib::ReadStorage::__exists(&self.ctx, &base_path)
            .then(|| {
                ChallengeWriteModel::new(self.ctx.clone(), base_path)
                    .with_index(self.index_path.clone(), key.to_string())
            })
    }
    pub fn set(&self, key: &u64, value: Challenge) {
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
        index_key: &str,
    ) -> impl Iterator<Item = u64> + use<> {
        let bucket = self.index_path.push(index_name).push(index_key);
        stdlib::ReadStorage::__get_keys(&self.ctx, &bucket)
    }
}
