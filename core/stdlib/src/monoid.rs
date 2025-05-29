use anyhow::{Result, anyhow};

type MzeroFn = fn() -> u64;
type MappendFn = fn(u64, u64) -> u64;

fn mzero_for_add() -> u64 {
    0
}

fn mappend_for_add(a: u64, b: u64) -> u64 {
    a + b
}

fn mzero_for_mul() -> u64 {
    1
}

fn mappend_for_mul(a: u64, b: u64) -> u64 {
    a * b
}

pub struct MyMonoidHostRep {
    pub mzero_operation: MzeroFn,
    pub mappend_operation: MappendFn,
}

impl MyMonoidHostRep {
    pub fn new(address: u64) -> Result<Self> {
        match address {
            0 => Ok(MyMonoidHostRep {
                mzero_operation: mzero_for_add,
                mappend_operation: mappend_for_add,
            }),
            1 => Ok(MyMonoidHostRep {
                mzero_operation: mzero_for_mul,
                mappend_operation: mappend_for_mul,
            }),
            _ => Err(anyhow!(
                "Invalid address: {} provided to monoid constructor. Expected 0 (add) or 1 (mul).",
                address
            )),
        }
    }
}
