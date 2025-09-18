use stdlib::*;

// Test contract to validate compilation
contract!(name = "resource_test");

// wit-bindgen generates a struct based on the contract name
impl Guest for ResourceTest {
    fn init(_ctx: &ProcContext) {
        // Initialize the contract
    }
    
    fn consume_balance(_ctx: &ProcContext, _bal: Balance) -> Result<(), Error> {
        Ok(())
    }
    
    fn create_balance(_ctx: &ProcContext, amount: Integer) -> Result<Balance, Error> {
        // Create a test balance using the factory function
        // Use a dummy token address for testing
        let test_token = ContractAddress {
            name: "test_token".to_string(),
            height: 0,
            tx_index: 0,
        };
        // Use the assets module's create_balance function
        Ok(kontor::built_in::assets::create_balance(amount, test_token))
    }
    
    fn maybe_balance(_ctx: &ViewContext, _check: bool) -> Option<Balance> {
        None
    }
}