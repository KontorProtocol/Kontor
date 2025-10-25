use stdlib::Model;
pub struct Operand {
    pub y: u64,
}
pub struct OperandModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl OperandModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn y(&self) -> u64 {
        self.ctx.__get(self.base_path.push("y")).unwrap()
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
pub struct OperandWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: OperandModel,
}
impl OperandWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: OperandModel::new(std::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn y(&self) -> u64 {
        self.ctx.__get(self.base_path.push("y")).unwrap()
    }
    pub fn set_y(&self, value: u64) {
        self.ctx.__set(self.base_path.push("y"), value);
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
impl std::ops::Deref for OperandWriteModel {
    type Target = OperandModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
