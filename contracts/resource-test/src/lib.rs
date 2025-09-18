use stdlib::*;

contract!(name = "resource_test");

impl Guest for ResourceTest {
    fn init(_ctx: &ProcContext) {}

    fn hash(_ctx: &ViewContext, input: String) -> String {
        kontor::built_in::crypto::hash(&input).0
    }

    fn hash_with_salt(_ctx: &ViewContext, input: String, salt: String) -> String {
        kontor::built_in::crypto::hash_with_salt(&input, &salt).0
    }

    fn generate_id(_ctx: &ViewContext) -> String {
        kontor::built_in::crypto::generate_id()
    }
}