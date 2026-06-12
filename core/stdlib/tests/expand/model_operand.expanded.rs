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
    #[allow(dead_code)]
    index_binding: Option<(stdlib::DotPathBuf, alloc::string::String)>,
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
            index_binding: None,
            model: OperandModel::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    #[allow(dead_code)]
    pub fn with_index(
        mut self,
        index_root: stdlib::DotPathBuf,
        index_key: alloc::string::String,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("y")).unwrap()
    }
    pub fn set_y(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push("y"), value);
    }
    pub fn update_y(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push("y");
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_y(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("y");
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
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
