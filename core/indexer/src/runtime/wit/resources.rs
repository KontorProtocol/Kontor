use std::{fmt, pin::Pin};

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

#[derive(Clone)]
pub enum Signer {
    XOnlyPubKey(String),
    ContractId(i64),
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XOnlyPubKey(s) => write!(f, "{}", s),
            Self::ContractId(id) => write!(f, "__cid__{}", id),
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

pub struct ResourceData {
    pub resource_id: String,
    pub payload: String,
}
