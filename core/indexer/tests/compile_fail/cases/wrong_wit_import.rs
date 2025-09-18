// This test MUST fail to compile - demonstrates WIT resource import validation

// Attempt to import wrong resource types in contract
contract!(name = "test_contract");

// Import a Balance resource with wrong signature
use kontor::built_in::assets::Balance;

impl Guest for TestContract {
    fn init(_ctx: &ProcContext) {}

    // This MUST fail: wrong resource type signature
    fn wrong_balance_function(_ctx: &ProcContext, _bal: SomeOtherResource) -> Balance {
        //                                              ^^^^^^^^^^^^^^^^^
        // ERROR: SomeOtherResource is not defined or wrong type
        unimplemented!()
    }

    // This MUST fail: trying to accept LP balance where Balance expected
    fn deposit(_ctx: &ProcContext, _recipient: String, _bal: LpBalance) -> Result<(), Error> {
        //                                                   ^^^^^^^^^
        // ERROR: Contract signature expects Balance, not LpBalance
        unimplemented!()
    }
}

struct SomeOtherResource; // Not a valid WIT resource