use stdlib::Model;
struct ArithStorage {
    pub last_op: Option<Op>,
}
pub struct ArithStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl ArithStorageModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn last_op(&self) -> Option<OpModel> {
        let base_path = self.base_path.push("last_op");
        if self.ctx.__extend_path_with_match(&base_path, &["none"]).is_some() {
            None
        } else {
            Some(OpModel::new(self.ctx.clone(), base_path.push("some")))
        }
    }
    pub fn load(&self) -> ArithStorage {
        ArithStorage {
            last_op: self.last_op().map(|p| p.load()),
        }
    }
}
pub struct ArithStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: ArithStorageModel,
}
impl ArithStorageWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: ArithStorageModel::new(
                std::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn last_op(&self) -> Option<OpWriteModel> {
        let base_path = self.base_path.push("last_op");
        if self.ctx.__extend_path_with_match(&base_path, &["none"]).is_some() {
            None
        } else {
            Some(OpWriteModel::new(self.ctx.clone(), base_path.push("some")))
        }
    }
    pub fn set_last_op(&self, value: Option<Op>) {
        self.ctx.__set(self.base_path.push("last_op"), value);
    }
    pub fn load(&self) -> ArithStorage {
        ArithStorage {
            last_op: self.last_op().map(|p| p.load()),
        }
    }
}
impl std::ops::Deref for ArithStorageWriteModel {
    type Target = ArithStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
