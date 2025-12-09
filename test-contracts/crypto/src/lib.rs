#![no_std]
contract!(name = "crypto");

use stdlib::*;

fn _generate_id(ctx: &ProcContext) -> String {
    ctx.generate_id()
}

impl Guest for Crypto {
    fn init(_ctx: &ProcContext) {}

    fn hash(_ctx: &ViewContext, input: String) -> String {
        crypto::hash(&input).0
    }

    fn hash_with_salt(_ctx: &ViewContext, input: String, salt: String) -> String {
        crypto::hash_with_salt(&input, &salt).0
    }

    fn generate_id(ctx: &ProcContext) -> String {
        ctx.generate_id()
    }
}
