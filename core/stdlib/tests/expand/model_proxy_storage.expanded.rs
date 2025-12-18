use stdlib::Model;
struct ProxyStorage {
    contract_address: ContractAddress,
}
pub struct ProxyStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ViewStorage>,
}
impl ProxyStorageModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn contract_address(&self) -> ContractAddress {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("contract_address"))
            .unwrap()
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
pub struct ProxyStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: alloc::rc::Rc<crate::context::ProcStorage>,
    model: ProxyStorageModel,
}
impl ProxyStorageWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: ProxyStorageModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn contract_address(&self) -> ContractAddress {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push("contract_address"))
            .unwrap()
    }
    pub fn set_contract_address(&self, value: ContractAddress) {
        stdlib::WriteStorage::__set(
            &self.ctx,
            self.base_path.push("contract_address"),
            value,
        );
    }
    pub fn update_contract_address(
        &self,
        f: impl Fn(ContractAddress) -> ContractAddress,
    ) {
        let path = self.base_path.push("contract_address");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap()),
        );
    }
    pub fn try_update_contract_address(
        &self,
        f: impl Fn(ContractAddress) -> Result<ContractAddress, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push("contract_address");
        stdlib::WriteStorage::__set(
            &self.ctx,
            path.clone(),
            f(stdlib::ReadStorage::__get(&self.ctx, path).unwrap())?,
        );
        Ok(())
    }
    pub fn load(&self) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(),
        }
    }
}
impl core::ops::Deref for ProxyStorageWriteModel {
    type Target = ProxyStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
