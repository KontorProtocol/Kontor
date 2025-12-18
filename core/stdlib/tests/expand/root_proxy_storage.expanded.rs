use stdlib::Root;
struct ProxyStorage {
    contract_address: ContractAddress,
}
impl ProxyStorage {
    pub fn init(self, ctx: &crate::ProcContext) {
        stdlib::WriteStorage::__set(
            &alloc::rc::Rc::new(ctx.storage()),
            stdlib::DotPathBuf::new(),
            self,
        )
    }
}
impl crate::ProcContext {
    pub fn model(&self) -> ProxyStorageWriteModel {
        ProxyStorageWriteModel::new(
            alloc::rc::Rc::new(self.storage()),
            DotPathBuf::new(),
        )
    }
}
impl crate::ViewContext {
    pub fn model(&self) -> ProxyStorageModel {
        ProxyStorageModel::new(alloc::rc::Rc::new(self.storage()), DotPathBuf::new())
    }
}
