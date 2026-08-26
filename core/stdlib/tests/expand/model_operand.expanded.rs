use stdlib::Model;
pub struct Operand {
    pub y: u64,
}
pub struct OperandModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __OperandModelFor<__S> = OperandModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> OperandModel<__S> {
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
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
pub struct OperandWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: OperandModel<__S::View>,
}
#[doc(hidden)]
pub type __OperandWriteModelFor<__S> = OperandWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> OperandWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: OperandModel::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
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
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn set_y(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_y(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_y(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for OperandWriteModel<__S> {
    type Target = OperandModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
