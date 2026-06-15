#![no_std]
contract!(name = "crypto");

#[derive(Clone, StorageRoot)]
struct VecU8 {
    pub bytes: Option<Vec<u8>>,
}

use stdlib::*;

fn _generate_id(ctx: &ProcContext) -> String {
    ctx.generate_id()
}

impl Guest for Crypto {
    fn init(ctx: &ProcContext) -> Contract {
        VecU8 { bytes: None }.init(ctx);
        ctx.contract()
    }

    fn sha256(_ctx: &ViewContext, input: Vec<u8>) -> Vec<u8> {
        crypto::sha256(&input)
    }

    fn block_entropy(_ctx: &ViewContext, height: u64) -> Option<Vec<u8>> {
        crypto::block_entropy(height)
    }

    fn generate_id(ctx: &ProcContext) -> String {
        ctx.generate_id()
    }

    fn set_hash(ctx: &ProcContext, input: Vec<u8>) -> Vec<u8> {
        let hash = crypto::sha256(&input);
        ctx.model().set_bytes(Some(hash.clone()));
        hash
    }

    fn get_hash(ctx: &ViewContext) -> Option<Vec<u8>> {
        ctx.model().bytes()
    }
}
