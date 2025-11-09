use stdlib::Storage;
struct ProxyStorage {
    contract_address: ContractAddress,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for ProxyStorage {
    fn __set(
        ctx: &std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
        value: ProxyStorage,
    ) {
        ctx.__set(base_path.push("contract_address"), value.contract_address);
    }
}
pub struct ProxyStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl ProxyStorageModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn contract_address(&self) -> ContractAddress {
        self.ctx.__get(self.base_path.push("contract_address")).unwrap()
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
pub struct ProxyStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: ProxyStorageModel,
}
impl ProxyStorageWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: ProxyStorageModel::new(
                std::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn contract_address(&self) -> ContractAddress {
        self.ctx.__get(self.base_path.push("contract_address")).unwrap()
    }
    pub fn set_contract_address(&self, value: ContractAddress) {
        self.ctx.__set(self.base_path.push("contract_address"), value);
    }
    pub fn update_contract_address(
        &self,
        f: impl Fn(ContractAddress) -> ContractAddress,
    ) {
        let path = self.base_path.push("contract_address");
        self.ctx.__set(path.clone(), f(self.ctx.__get(path).unwrap()));
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
impl std::ops::Deref for ProxyStorageWriteModel {
    type Target = ProxyStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
