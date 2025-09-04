use stdlib::Wrapper;
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
pub struct TokenStorageWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageWrapper {
    #[inline]
    fn clone(&self) -> TokenStorageWrapper {
        TokenStorageWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl TokenStorageWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn ledger(&self) -> TokenStorageLedgerWrapper {
        TokenStorageLedgerWrapper {
            base_path: self.base_path.push("ledger"),
        }
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> TokenStorage {
        TokenStorage {
            ledger: self.ledger().load(ctx),
        }
    }
}
pub struct TokenStorageLedgerWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageLedgerWrapper {
    #[inline]
    fn clone(&self) -> TokenStorageLedgerWrapper {
        TokenStorageLedgerWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl TokenStorageLedgerWrapper {
    pub fn get(
        &self,
        ctx: &impl stdlib::ReadContext,
        key: impl ToString,
    ) -> Option<u64> {
        let base_path = self.base_path.push(key.to_string());
        ctx.__get(base_path)
    }
    pub fn set(&self, ctx: &impl stdlib::WriteContext, key: String, value: u64) {
        ctx.__set(self.base_path.push(key.to_string()), value)
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Map<String, u64> {
        Map::new(&[])
    }
}
