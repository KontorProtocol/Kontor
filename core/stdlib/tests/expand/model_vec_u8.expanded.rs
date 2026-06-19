use stdlib::Model;
struct VecU8 {
    pub bytes: Vec<u8>,
    pub bytes_other: Vec<u8>,
}
pub struct VecU8Model {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl VecU8Model {
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
pub struct VecU8WriteModel {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: VecU8Model,
}
impl VecU8WriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        let view_storage = ctx.view_storage();
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
impl core::ops::Deref for VecU8WriteModel {
    type Target = VecU8Model;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
