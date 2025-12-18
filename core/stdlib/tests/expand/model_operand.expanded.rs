use stdlib::Model;
pub struct Operand {
    pub y: u64,
}
pub struct OperandModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl OperandModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("y")).unwrap()
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
pub struct OperandWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    model: OperandModel,
}
impl OperandWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: OperandModel::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("y")).unwrap()
    }
    pub fn set_y(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push("y"), value);
    }
    pub fn update_y(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("y");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap()),
        );
    }
    pub fn try_update_y(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("y");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap())?,
        );
        Ok(())
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
impl core::ops::Deref for OperandWriteModel {
    type Target = OperandModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
