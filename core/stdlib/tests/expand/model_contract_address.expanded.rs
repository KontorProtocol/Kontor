use stdlib::Model;
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
pub struct ContractAddressModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl ContractAddressModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn name(&self) -> String {
        self.ctx.__get(self.base_path.push("name")).unwrap()
    }
    pub fn height(&self) -> i64 {
        self.ctx.__get(self.base_path.push("height")).unwrap()
    }
    pub fn tx_index(&self) -> i64 {
        self.ctx.__get(self.base_path.push("tx_index")).unwrap()
    }
    pub fn load(&self) -> ContractAddress {
        ContractAddress {
            name: self.name(),
            height: self.height(),
            tx_index: self.tx_index(),
        }
    }
}
pub struct ContractAddressWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: ContractAddressModel,
}
impl ContractAddressWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: ContractAddressModel::new(
                std::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn name(&self) -> String {
        self.ctx.__get(self.base_path.push("name")).unwrap()
    }
    pub fn height(&self) -> i64 {
        self.ctx.__get(self.base_path.push("height")).unwrap()
    }
    pub fn tx_index(&self) -> i64 {
        self.ctx.__get(self.base_path.push("tx_index")).unwrap()
    }
    pub fn set_name(&self, value: String) {
        self.ctx.__set(self.base_path.push("name"), value);
    }
    pub fn update_name(&self, f: impl Fn(String) -> String) {
        let path = self.base_path.push("name");
        self.ctx.__set(path.clone(), f(self.ctx.__get(path).unwrap()));
    }
    pub fn set_height(&self, value: i64) {
        self.ctx.__set(self.base_path.push("height"), value);
    }
    pub fn update_height(&self, f: impl Fn(i64) -> i64) {
        let path = self.base_path.push("height");
        self.ctx.__set(path.clone(), f(self.ctx.__get(path).unwrap()));
    }
    pub fn set_tx_index(&self, value: i64) {
        self.ctx.__set(self.base_path.push("tx_index"), value);
    }
    pub fn update_tx_index(&self, f: impl Fn(i64) -> i64) {
        let path = self.base_path.push("tx_index");
        self.ctx.__set(path.clone(), f(self.ctx.__get(path).unwrap()));
    }
    pub fn load(&self) -> ContractAddress {
        ContractAddress {
            name: self.name(),
            height: self.height(),
            tx_index: self.tx_index(),
        }
    }
}
impl std::ops::Deref for ContractAddressWriteModel {
    type Target = ContractAddressModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
