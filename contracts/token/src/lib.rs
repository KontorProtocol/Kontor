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
        let current_supply = storage(ctx).total_supply(ctx);

        let balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, to, numbers::add_integer(balance, n));

        storage(ctx).set_total_supply(ctx, numbers::add_integer(current_supply, n));
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

        let key = format!("{}:{}", owner, spender);
        allowances.set(ctx, key, amount);

        Ok(())
    }

    fn transfer_from(ctx: &ProcContext, owner: String, to: String, amount: numbers::Integer) -> Result<(), error::Error> {
        let spender = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let allowances = storage(ctx).allowances();
        
        // Check allowance
        let allow_key = format!("{}:{}", owner, spender);
        let allowed = allowances.get(ctx, &allow_key).unwrap_or_default();
        
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
        allowances.set(ctx, allow_key, numbers::sub_integer(allowed, amount));
        
        Ok(())
    }

    fn allowance(ctx: &ViewContext, owner: String, spender: String) -> Option<numbers::Integer> {
        let allowances = storage(ctx).allowances();
        allowances.get(ctx, format!("{}:{}", owner, spender))
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
        storage(ctx).total_supply(ctx)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<numbers::Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|i| numbers::log10(numbers::integer_to_decimal(i)))
    }
}