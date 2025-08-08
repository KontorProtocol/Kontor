pub trait HasContractId: 'static {
    fn get_contract_id(&self) -> i64;
}

pub struct ViewStorage {
    pub contract_id: i64,
}

impl HasContractId for ViewStorage {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct ProcStorage {
    pub contract_id: i64,
}

impl HasContractId for ProcStorage {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct ViewContext {
    pub contract_id: i64,
}

impl HasContractId for ViewContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct Signer {
    pub signer: String,
}

pub struct ProcContext {
    pub contract_id: i64,
    pub signer: String,
}

impl HasContractId for ProcContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}

pub struct FallContext {
    pub contract_id: i64,
    pub signer: Option<String>,
}

impl HasContractId for FallContext {
    fn get_contract_id(&self) -> i64 {
        self.contract_id
    }
}
