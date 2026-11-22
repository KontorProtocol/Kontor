use indexer_types::{
    AggregateInfo, AggregateSigner, ContractAddress, Inst, InstKind, Insts, SignerRef,
};

pub(super) fn aggregate_call(gas_limit: u64, contract: ContractAddress, expr: String) -> Inst {
    Inst {
        gas_limit,
        kind: InstKind::Call { contract, expr },
    }
}

pub(super) fn signer_by_id(id: u64, nonce: u64, sponsored: bool) -> AggregateSigner {
    AggregateSigner {
        identity: SignerRef::SignerId(id),
        nonce,
        sponsored,
    }
}

pub(super) fn aggregate_insts(
    ops: Vec<Inst>,
    signers: Vec<AggregateSigner>,
    signature: Vec<u8>,
) -> Insts {
    Insts {
        ops,
        aggregate: Some(AggregateInfo { signers, signature }),
    }
}
