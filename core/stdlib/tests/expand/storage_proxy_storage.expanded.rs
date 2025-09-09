use stdlib::Storage;
struct ProxyStorage {
    contract_address: ContractAddress,
}
#[automatically_derived]
impl stdlib::Store for ProxyStorage {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: ProxyStorage,
    ) {
        ctx.__set(base_path.push("contract_address"), value.contract_address);
    }
}
pub struct ProxyStorageWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for ProxyStorageWrapper {
    #[inline]
    fn clone(&self) -> ProxyStorageWrapper {
        ProxyStorageWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl ProxyStorageWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn contract_address(&self, ctx: &impl stdlib::ReadContext) -> ContractAddress {
        ContractAddressWrapper::new(ctx, self.base_path.push("contract_address"))
            .load(ctx)
    }
    pub fn set_contract_address(
        &self,
        ctx: &impl stdlib::WriteContext,
        value: ContractAddress,
    ) {
        ctx.__set(self.base_path.push("contract_address"), value);
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> ProxyStorage {
        ProxyStorage {
            contract_address: self.contract_address(ctx),
        }
    }
}
