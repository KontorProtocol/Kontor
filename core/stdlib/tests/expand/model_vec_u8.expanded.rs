use stdlib::Model;
struct VecU8 {
    pub bytes: Vec<u8>,
    pub bytes_other: Vec<u8>,
}
pub struct VecU8Model {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl VecU8Model {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("bytes")).unwrap()
    }
    pub fn bytes_other(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("bytes_other"))
            .unwrap()
    }
    pub fn load(&self) -> VecU8 {
        VecU8 {
            bytes: self.bytes(),
            bytes_other: self.bytes_other(),
        }
    }
}
pub struct VecU8WriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    model: VecU8Model,
}
impl VecU8WriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: VecU8Model::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("bytes")).unwrap()
    }
    pub fn bytes_other(&self) -> Vec<u8> {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("bytes_other"))
            .unwrap()
    }
    pub fn set_bytes(&self, value: Vec<u8>) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push("bytes"), value);
    }
    pub fn update_bytes(&self, f: impl Fn(Vec<u8>) -> Vec<u8>) {
        let path = self.base_path.push("bytes");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap()),
        );
    }
    pub fn try_update_bytes(
        &self,
        f: impl Fn(Vec<u8>) -> Result<Vec<u8>, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("bytes");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap())?,
        );
        Ok(())
    }
    pub fn set_bytes_other(&self, value: Vec<u8>) {
        stdlib::WriteStorage::__set(
            &self.ctx,
            self.base_path.push("bytes_other"),
            value,
        );
    }
    pub fn update_bytes_other(&self, f: impl Fn(Vec<u8>) -> Vec<u8>) {
        let path = self.base_path.push("bytes_other");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap()),
        );
    }
    pub fn try_update_bytes_other(
        &self,
        f: impl Fn(Vec<u8>) -> Result<Vec<u8>, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("bytes_other");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap())?,
        );
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
