use stdlib::Model;
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
pub struct TokenStorageModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl TokenStorageModel {
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
    pub fn ledger(&self) -> TokenStorageLedgerModel {
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
pub struct TokenStorageLedgerModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageLedgerModel {
    #[inline]
    fn clone(&self) -> TokenStorageLedgerModel {
        TokenStorageLedgerModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl TokenStorageLedgerModel {
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
pub struct TokenStorageWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: TokenStorageModel,
}
impl TokenStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
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
    pub fn ledger(&self) -> TokenStorageLedgerWriteModel {
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
impl core::ops::Deref for TokenStorageWriteModel {
    type Target = TokenStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct TokenStorageLedgerWriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageLedgerWriteModel {
    #[inline]
    fn clone(&self) -> TokenStorageLedgerWriteModel {
        TokenStorageLedgerWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl TokenStorageLedgerWriteModel {
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
