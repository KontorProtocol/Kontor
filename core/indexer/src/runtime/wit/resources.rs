use std::{ops::Deref, pin::Pin};

use futures_util::Stream;

pub trait HasContractId: 'static {
    fn get_contract_id(&self) -> i64;
}

pub struct ViewContext {
    pub contract_id: i64,
}

impl HasContractId for ViewContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    XOnlyPubKey(String),
    ContractId { id: i64, id_str: String },
}

impl Signer {
    pub fn new_contract_id(id: i64) -> Self {
        Self::ContractId {
            id,
            id_str: format!("__cid__{}", id),
        }
    }
}

impl Deref for Signer {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::XOnlyPubKey(s) => s,
            Self::ContractId { id_str, .. } => id_str,
        }
    }
}

pub struct ProcContext {
    pub contract_id: i64,
    pub signer: Signer,
}

impl HasContractId for ProcContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct FallContext {
    pub contract_id: i64,
    pub signer: Option<Signer>,
}

impl HasContractId for FallContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct Keys {
    pub stream: Pin<Box<dyn Stream<Item = Result<String, libsql::Error>> + Send>>,
}
