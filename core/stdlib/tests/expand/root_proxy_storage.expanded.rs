use stdlib::Root;
struct ProxyStorage {
    contract_address: ContractAddress,
}
impl ProxyStorage {
    pub fn init(self, ctx: &impl stdlib::WriteContext) {
        ctx.__set(stdlib::DotPathBuf::new(), self)
    }
}
pub fn storage(ctx: &impl stdlib::ReadContext) -> ProxyStorageWrapper {
    ProxyStorageWrapper::new(ctx, stdlib::DotPathBuf::new())
}
