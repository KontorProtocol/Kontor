use stdlib::*;

contract!(name = "token");

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, numbers::Integer>,
    pub allowances: Map<String, numbers::Integer>, // "owner:spender" -> amount (flattened)
    pub total_supply: numbers::Integer,
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn mint(ctx: &ProcContext, n: numbers::Integer) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let total_supply = storage(ctx).total_supply();

        let balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, to, numbers::add_integer(balance, n));
        
        let current_supply = total_supply.get(ctx).unwrap_or_default();
        total_supply.set(ctx, numbers::add_integer(current_supply, n));
    }

    fn transfer(ctx: &ProcContext, to: String, n: numbers::Integer) -> Result<(), error::Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();

        if from_balance < n {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, numbers::sub_integer(from_balance, n));
        ledger.set(ctx, to, numbers::add_integer(to_balance, n));
        Ok(())
    }

    fn approve(ctx: &ProcContext, spender: String, amount: numbers::Integer) -> Result<(), error::Error> {
        let owner = ctx.signer().to_string();
        let allowances = storage(ctx).allowances();
        
        let owner_allowances = allowances.get(ctx, &owner).unwrap_or_default();
        owner_allowances.set(ctx, spender, amount);
        allowances.set(ctx, owner, owner_allowances);
        
        Ok(())
    }

    fn transfer_from(ctx: &ProcContext, owner: String, to: String, amount: numbers::Integer) -> Result<(), error::Error> {
        let spender = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let allowances = storage(ctx).allowances();
        
        // Check allowance
        let owner_allowances = allowances.get(ctx, &owner).unwrap_or_default();
        let allowed = owner_allowances.get(ctx, &spender).unwrap_or_default();
        
        if allowed < amount {
            return Err(error::Error::Message("insufficient allowance".to_string()));
        }
        
        // Check balance
        let owner_balance = ledger.get(ctx, &owner).unwrap_or_default();
        if owner_balance < amount {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }
        
        // Update balances
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, owner.clone(), numbers::sub_integer(owner_balance, amount));
        ledger.set(ctx, to, numbers::add_integer(to_balance, amount));
        
        // Update allowance
        owner_allowances.set(ctx, spender, numbers::sub_integer(allowed, amount));
        allowances.set(ctx, owner, owner_allowances);
        
        Ok(())
    }

    fn allowance(ctx: &ViewContext, owner: String, spender: String) -> Option<numbers::Integer> {
        let allowances = storage(ctx).allowances();
        allowances.get(ctx, owner)
            .and_then(|owner_allowances| owner_allowances.get(ctx, spender))
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<numbers::Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }
    
    fn balance_or_zero(ctx: &ViewContext, acc: String) -> numbers::Integer {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).unwrap_or_default()
    }
    
    fn total_supply(ctx: &ViewContext) -> numbers::Integer {
        storage(ctx).total_supply().get(ctx).unwrap_or_default()
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<numbers::Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|i| numbers::log10(numbers::integer_to_decimal(i)))
    }
}