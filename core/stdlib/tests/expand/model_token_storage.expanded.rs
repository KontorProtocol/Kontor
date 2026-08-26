use stdlib::Model;
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
pub struct TokenStorageModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __TokenStorageModelFor<__S> = TokenStorageModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> TokenStorageModel<__S> {
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
    pub fn ledger(&self) -> TokenStorageLedgerModel<__S> {
        TokenStorageLedgerModel {
            base_path: self.base_path.push_interned(0u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> TokenStorage {
        TokenStorage {
            ledger: self.ledger().load(),
        }
    }
}
pub struct TokenStorageLedgerModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for TokenStorageLedgerModel<__S> {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
impl<__S: stdlib::ReadStorage + 'static> TokenStorageLedgerModel<__S> {
    pub fn get(&self, key: &String) -> Option<u64> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_element(key))
    }
    pub fn load(&self) -> Map<String, u64> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = String> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
pub struct TokenStorageWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: TokenStorageModel<__S::View>,
}
#[doc(hidden)]
pub type __TokenStorageWriteModelFor<__S> = TokenStorageWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> TokenStorageWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: TokenStorageModel::new(
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
    pub fn ledger(&self) -> TokenStorageLedgerWriteModel<__S> {
        TokenStorageLedgerWriteModel {
            base_path: self.base_path.push_interned(0u8),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> TokenStorage {
        TokenStorage {
            ledger: self.ledger().load(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for TokenStorageWriteModel<__S> {
    type Target = TokenStorageModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct TokenStorageLedgerWriteModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
impl<__S> Clone for TokenStorageLedgerWriteModel<__S> {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> TokenStorageLedgerWriteModel<__S> {
    pub fn get(&self, key: &String) -> Option<u64> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_element(key))
    }
    pub fn set(&self, key: &String, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_element(key), value)
    }
    /// Remove a single entry (tombstone). Returns true if a live value existed.
    pub fn remove(&self, key: &String) -> bool {
        stdlib::WriteStorage::__delete(&self.ctx, &self.base_path.push_element(key))
    }
    pub fn load(&self) -> Map<String, u64> {
        Map::new(&[])
    }
    pub fn keys(&self) -> impl Iterator<Item = String> {
        stdlib::ReadStorage::__get_keys(&self.ctx, &self.base_path)
    }
}
