use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;

use super::Value;
use crate::protocol::coordinator::certified_input::{EraContext, ExactInput};
use crate::protocol::identity::{ChainId, ProtocolId};

// Isolated codec/stream fixtures only. Reactor fixtures must use their persisted era.
pub(crate) fn context() -> EraContext {
    EraContext {
        chain: ChainId([1; 32]),
        era: [2; 32],
        protocol: ProtocolId([3; 32]),
        codec: 1,
    }
}

pub(crate) fn block() -> Value {
    let input = ExactInput::block(context(), 0, serialize(&genesis_block(Network::Regtest)))
        .expect("valid Bitcoin genesis body");
    Value::from_input(input).expect("valid block value")
}
