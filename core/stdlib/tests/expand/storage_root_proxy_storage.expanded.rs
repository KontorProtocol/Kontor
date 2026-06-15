use stdlib::StorageRoot;
struct ProxyStorage {
    contract_address: ContractAddress,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ProxyStorage {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
        value: ProxyStorage,
    ) {
        stdlib::WriteStorage::__set(
            ctx,
            base_path.push_interned(0u8),
            value.contract_address,
        );
    }
}
pub struct ProxyStorageModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ProxyStorageModel {
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
    pub fn contract_address(&self) -> ContractAddress {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
pub struct ProxyStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ProxyStorageModel,
}
impl ProxyStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ProxyStorageModel::new(
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
    pub fn contract_address(&self) -> ContractAddress {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn set_contract_address(&self, value: ContractAddress) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_contract_address(
        &self,
        f: impl Fn(ContractAddress) -> ContractAddress,
    ) {
        let path = self.base_path.push_interned(0u8);
        let old: ContractAddress = stdlib::ReadStorage::__get(&self.ctx, path.clone())
            .unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_contract_address(
        &self,
        f: impl Fn(ContractAddress) -> Result<ContractAddress, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: ContractAddress = stdlib::ReadStorage::__get(&self.ctx, path.clone())
            .unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
impl core::ops::Deref for ProxyStorageWriteModel {
    type Target = ProxyStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
#[automatically_derived]
impl stdlib::Indexed for ProxyStorage {
    const HAS_INDEXES: bool = false;
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
    }
}
pub trait ProxyStorageIndex<K>
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
}
impl ProxyStorage {
    pub fn init(self, ctx: &crate::ProcContext) {
        stdlib::WriteStorage::__set(
            &alloc::rc::Rc::new(ctx.storage()),
            stdlib::KeyPath::new(),
            self,
        )
    }
}
impl crate::ProcContext {
    pub fn model(&self) -> ProxyStorageWriteModel {
        ProxyStorageWriteModel::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
    }
}
impl crate::ViewContext {
    pub fn model(&self) -> ProxyStorageModel {
        ProxyStorageModel::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
    }
}
