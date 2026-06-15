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

    // `input` is a string for test-ergonomics (callers invoke `set-hash("foo")`
    // via string exprs); the crypto built-in itself is bytes-native.
    fn set_hash(ctx: &ProcContext, input: String) -> Vec<u8> {
        let hash = crypto::sha256(input.as_bytes());
        ctx.model().set_bytes(Some(hash.clone()));
        hash
    }

    fn get_hash(ctx: &ViewContext) -> Option<Vec<u8>> {
        ctx.model().bytes()
    }
}
