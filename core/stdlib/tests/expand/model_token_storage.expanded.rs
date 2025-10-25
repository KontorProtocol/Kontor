use stdlib::Model;
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
pub struct TokenStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl TokenStorageModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn ledger(&self) -> TokenStorageLedgerModel {
        TokenStorageLedgerModel {
            base_path: self.base_path.push("ledger"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> TokenStorage {
        TokenStorage {
            ledger: self.ledger().load(),
        }
    }
}
pub struct TokenStorageLedgerModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageLedgerModel {
    #[inline]
    fn clone(&self) -> TokenStorageLedgerModel {
        TokenStorageLedgerModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl TokenStorageLedgerModel {
    pub fn get(&self, key: impl ToString) -> Option<u64> {
        let base_path = self.base_path.push(key.to_string());
        self.ctx.__get(base_path)
    }
    pub fn load(&self) -> Map<String, u64> {
        Map::new(&[])
    }
    pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
        &'a self,
    ) -> impl Iterator<Item = T> + 'a {
        self.ctx.__get_keys(&self.base_path)
    }
}
pub struct TokenStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: TokenStorageModel,
}
impl TokenStorageWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: TokenStorageModel::new(
                std::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn ledger(&self) -> TokenStorageLedgerWriteModel {
        TokenStorageLedgerWriteModel {
            base_path: self.base_path.push("ledger"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> TokenStorage {
        TokenStorage {
            ledger: self.ledger().load(),
        }
    }
}
impl std::ops::Deref for TokenStorageWriteModel {
    type Target = TokenStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct TokenStorageLedgerWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for TokenStorageLedgerWriteModel {
    #[inline]
    fn clone(&self) -> TokenStorageLedgerWriteModel {
        TokenStorageLedgerWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl TokenStorageLedgerWriteModel {
    pub fn get(&self, key: impl ToString) -> Option<u64> {
        let base_path = self.base_path.push(key.to_string());
        self.ctx.__get(base_path)
    }
    pub fn set(&self, key: String, value: u64) {
        self.ctx.__set(self.base_path.push(key.to_string()), value)
    }
    pub fn load(&self) -> Map<String, u64> {
        Map::new(&[])
    }
    pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
        &'a self,
    ) -> impl Iterator<Item = T> + 'a {
        self.ctx.__get_keys(&self.base_path)
    }
}
