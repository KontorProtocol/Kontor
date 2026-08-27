use stdlib::Root;
struct ProxyStorage {
    contract_address: ContractAddress,
}
impl ProxyStorage {
    pub fn init(self, ctx: &crate::ProcContext) {
        stdlib::WriteStorage::__set(
            &alloc::rc::Rc::new(ctx.storage()),
            stdlib::KeyPath::new(),
            self,
        )
    }
}
impl stdlib::HasRootModel<ProxyStorage> for crate::ProcContext {
    type Model = ProxyStorageWriteModel<crate::context::ProcStorage>;
    fn model(&self) -> Self::Model {
        ProxyStorageWriteModel::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
    }
}
impl stdlib::HasRootModel<ProxyStorage> for crate::ViewContext {
    type Model = ProxyStorageModel<crate::context::ViewStorage>;
    fn model(&self) -> Self::Model {
        ProxyStorageModel::new(alloc::rc::Rc::new(self.storage()), KeyPath::new())
    }
}
