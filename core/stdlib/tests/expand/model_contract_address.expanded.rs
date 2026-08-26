use stdlib::Model;
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
pub struct ContractAddressModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __ContractAddressModelFor<__S> = ContractAddressModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> ContractAddressModel<__S> {
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
    pub fn name(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn height(&self) -> i64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn tx_index(&self) -> i64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn load(&self) -> ContractAddress {
        ContractAddress {
            name: self.name(),
            height: self.height(),
            tx_index: self.tx_index(),
        }
    }
}
pub struct ContractAddressWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ContractAddressModel<__S::View>,
}
#[doc(hidden)]
pub type __ContractAddressWriteModelFor<__S> = ContractAddressWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> ContractAddressWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ContractAddressModel::new(
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
    pub fn name(&self) -> String {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn height(&self) -> i64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn tx_index(&self) -> i64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(2u8)).unwrap()
    }
    pub fn set_name(&self, value: String) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_name(&self, f: impl Fn(String) -> String) {
        let path = self.base_path.push_interned(0u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_name(
        &self,
        f: impl Fn(String) -> Result<String, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: String = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_height(&self, value: i64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(1u8), value);
    }
    pub fn update_height(&self, f: impl Fn(i64) -> i64) {
        let path = self.base_path.push_interned(1u8);
        let old: i64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_height(
        &self,
        f: impl Fn(i64) -> Result<i64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(1u8);
        let old: i64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_tx_index(&self, value: i64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(2u8), value);
    }
    pub fn update_tx_index(&self, f: impl Fn(i64) -> i64) {
        let path = self.base_path.push_interned(2u8);
        let old: i64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_tx_index(
        &self,
        f: impl Fn(i64) -> Result<i64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(2u8);
        let old: i64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> ContractAddress {
        ContractAddress {
            name: self.name(),
            height: self.height(),
            tx_index: self.tx_index(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for ContractAddressWriteModel<__S> {
    type Target = ContractAddressModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
