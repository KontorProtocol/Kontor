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
    fn init(ctx: &ProcContext) {
        VecU8 { bytes: None }.init(ctx);
    }

    fn hash(_ctx: &ViewContext, input: String) -> String {
        crypto::hash(&input).0
    }

    fn hash_with_salt(_ctx: &ViewContext, input: String, salt: String) -> String {
        crypto::hash_with_salt(&input, &salt).0
    }

    fn generate_id(ctx: &ProcContext) -> String {
        ctx.generate_id()
    }

    fn set_hash(ctx: &ProcContext, input: String) -> Vec<u8> {
        let hash = crypto::hash(&input).1;
        ctx.model().set_bytes(Some(hash.clone()));
        hash
    }

    fn get_hash(ctx: &ViewContext) -> Option<Vec<u8>> {
        ctx.model().bytes()
    }
}
