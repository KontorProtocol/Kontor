use stdlib::*;

contract!(name = "simple_token");

// Simple token storage
#[derive(Default, StorageRoot)]
struct TokenStorage {
    pub balances: Map<String, String>,  // Integer is actually a String alias
    pub total_supply: String,
}

impl Guest for SimpleToken {
    fn init(_ctx: &ProcContext) {
        // Initialize storage
        TokenStorage::default().init(_ctx);
    }
    
    fn mint(ctx: &ProcContext, to: String, amount: Integer) {
        let storage = storage(ctx);
        let balances = storage.balances();
        
        // Get current balance (as string)
        let current = balances.get(ctx, &to).unwrap_or_else(|| "0".to_string());
        
        // For now, just store the raw amount (no arithmetic yet)
        // In production, we'd parse and do proper arithmetic
        balances.set(ctx, to, amount.clone());
        
        // Update total supply
        storage.set_total_supply(ctx, amount);
    }
    
    fn transfer(ctx: &ProcContext, to: String, amount: Integer) -> Result<(), Error> {
        // For now, just move the amount without arithmetic
        let storage = storage(ctx);
        let balances = storage.balances();
        
        // Get sender (would need proper signer handling)
        let from = "sender".to_string(); // Placeholder
        
        // Get balances
        let from_balance = balances.get(ctx, &from).unwrap_or_else(|| "0".to_string());
        
        // For simplicity, just set the balance
        balances.set(ctx, from, "0".to_string());
        balances.set(ctx, to, amount);
        
        Ok(())
    }
    
    fn balance(ctx: &ViewContext, account: String) -> Integer {
        let storage = storage(ctx);
        let balances = storage.balances();
        balances.get(ctx, account).unwrap_or_else(|| "0".to_string())
    }
    
    fn total_supply(ctx: &ViewContext) -> Integer {
        storage(ctx).total_supply(ctx)
    }
}