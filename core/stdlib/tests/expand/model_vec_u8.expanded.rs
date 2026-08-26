use stdlib::Model;
struct VecU8 {
    pub bytes: Vec<u8>,
    pub bytes_other: Vec<u8>,
}
pub struct VecU8Model<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __VecU8ModelFor<__S> = VecU8Model<__S>;
impl<__S: stdlib::ReadStorage + 'static> VecU8Model<__S> {
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
    pub fn bytes(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn bytes_other(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn load(&self) -> VecU8 {
        VecU8 {
            bytes: self.bytes(),
            bytes_other: self.bytes_other(),
        }
    }
}
pub struct VecU8WriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: VecU8Model<__S::View>,
}
#[doc(hidden)]
pub type __VecU8WriteModelFor<__S> = VecU8WriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> VecU8WriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: VecU8Model::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
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
    pub fn bytes(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn bytes_other(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(1u8)).unwrap()
    }
    pub fn set_bytes(&self, value: Vec<u8>) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_bytes(&self, f: impl Fn(Vec<u8>) -> Vec<u8>) {
        let path = self.base_path.push_interned(0u8);
        let old: Vec<u8> = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_bytes(
        &self,
        f: impl Fn(Vec<u8>) -> Result<Vec<u8>, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: Vec<u8> = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn set_bytes_other(&self, value: Vec<u8>) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(1u8), value);
    }
    pub fn update_bytes_other(&self, f: impl Fn(Vec<u8>) -> Vec<u8>) {
        let path = self.base_path.push_interned(1u8);
        let old: Vec<u8> = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_bytes_other(
        &self,
        f: impl Fn(Vec<u8>) -> Result<Vec<u8>, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(1u8);
        let old: Vec<u8> = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> VecU8 {
        VecU8 {
            bytes: self.bytes(),
            bytes_other: self.bytes_other(),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for VecU8WriteModel<__S> {
    type Target = VecU8Model<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
