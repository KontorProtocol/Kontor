use stdlib::Root;
struct ProxyStorage {
    contract_address: ContractAddress,
}
impl ProxyStorage {
    pub fn init(self, ctx: &crate::ProcContext) {
        ctx.storage().__set(stdlib::DotPathBuf::new(), self)
    }
}
impl crate::ProcContext {
    pub fn model(&self) -> ProxyStorageWriteModel {
        ProxyStorageWriteModel::new(std::rc::Rc::new(self.storage()), DotPathBuf::new())
    }
}
impl crate::ViewContext {
    pub fn model(&self) -> ProxyStorageModel {
        ProxyStorageModel::new(std::rc::Rc::new(self.storage()), DotPathBuf::new())
    }
}
