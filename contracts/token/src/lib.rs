use stdlib::*;

contract!(name = "token");

// Thread-local storage for balance resources using the generic ResourceTable
resource_table!(BALANCE_TABLE, BalanceData);

// Data backing a Balance resource
#[derive(Clone)]
struct BalanceData {
    token_addr: foreign::ContractAddress,
    amount: numbers::Integer,
    handle: String,  // Unique ID for linearity tracking
}

// Helper to create a unique handle for a balance
fn create_handle(id: numbers::Integer) -> String {
    format!("balance_{}", numbers::integer_to_string(id))
}

// Resource management is now handled by the generic ResourceTable

// Helper function to get the token's contract address
fn get_contract_address(ctx: &impl ReadContext) -> foreign::ContractAddress {
    storage(ctx).contract_addr(ctx).expect(
        "Contract address must be properly set during initialization. \
         This indicates a deployment configuration error."
    )
}

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, numbers::Integer>,
    pub total_supply: numbers::Integer,
    pub contract_addr: Option<foreign::ContractAddress>, // Store our own address
    pub next_balance_id: numbers::Integer,  // Counter for unique balance IDs
}

// Helper to allocate a new balance
fn allocate_balance(ctx: &ProcContext, amount: numbers::Integer) -> Balance {
    let token_addr = get_contract_address(ctx);
    
    // Get next ID and increment counter
    let id = storage(ctx).next_balance_id(ctx);
    let one = numbers::u64_to_integer(1);
    storage(ctx).set_next_balance_id(ctx, numbers::add_integer(id, one));
    
    let handle = create_handle(id);
    
    // Create the resource data
    let data = BalanceData {
        token_addr,
        amount,
        handle,
    };
    
    // Allocate a resource handle using the generic ResourceTable
    let index = BALANCE_TABLE.with(|table| table.allocate(data));
    
    // The macro should provide a way to create Balance from index
    // For now, we'll use unsafe from_handle which the macro generates
    unsafe { Balance::from_handle(index) }
}

// Helper to consume a balance
fn consume_balance(balance: Balance) -> Result<numbers::Integer, error::Error> {
    // Get the handle from the Balance resource
    let index = balance.take_handle();
    
    // Take the balance data from the resource table (this consumes it)
    let balance_data = BALANCE_TABLE.with(|table| table.take(index))
        .map_err(|msg| error::Error::Message(msg))?;
    
    Ok(balance_data.amount)
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        // Store the contract's address on initialization
        // In a real deployment, this would be set from deployment parameters
        let contract_addr = foreign::ContractAddress {
            name: "token".to_string(),
            height: 0,  // Should be set from deployment context
            tx_index: 1, // Should be set from deployment context
        };
        
        let mut storage = TokenStorage::default();
        storage.contract_addr = Some(contract_addr);
        storage.init(ctx);
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
    
    // Resource-based asset management
    fn withdraw(ctx: &ProcContext, amount: numbers::Integer) -> Result<Balance, error::Error> {
        let owner = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let balance = ledger.get(ctx, &owner).unwrap_or_default();

        if balance < amount {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        // Decrease ledger balance
        ledger.set(ctx, owner.clone(), numbers::sub_integer(balance, amount));
        
        // Create and return a balance resource
        Ok(allocate_balance(ctx, amount))
    }
    
    fn deposit(ctx: &ProcContext, recipient: String, bal: Balance) -> Result<(), error::Error> {
        // Consume the balance (this moves it, enforcing linearity)
        let amount = consume_balance(bal)?;
        
        // Credit the recipient
        let ledger = storage(ctx).ledger();
        let recipient_balance = ledger.get(ctx, &recipient).unwrap_or_default();
        ledger.set(ctx, recipient, numbers::add_integer(recipient_balance, amount));
        
        Ok(())
    }
    
    fn split(ctx: &ProcContext, bal: Balance, split_amount: numbers::Integer) -> Result<SplitResult, error::Error> {
        // Consume the original balance
        let total_amount = consume_balance(bal)?;
        
        if split_amount > total_amount {
            return Err(error::Error::Message("Split amount exceeds balance".to_string()));
        }
        
        // Create split balance
        let split_balance = allocate_balance(ctx, split_amount);
        
        // Create remainder balance if any
        let remainder_amount = numbers::sub_integer(total_amount, split_amount);
        let zero = numbers::u64_to_integer(0);
        let remainder_balance = if remainder_amount > zero {
            Some(allocate_balance(ctx, remainder_amount))
        } else {
            None
        };
        
        Ok(SplitResult {
            split: split_balance,
            remainder: remainder_balance,
        })
    }
    
    fn merge(ctx: &ProcContext, a: Balance, b: Balance) -> Result<Balance, error::Error> {
        // Consume both balances (they move, cannot be reused)
        let amount_a = consume_balance(a)?;
        let amount_b = consume_balance(b)?;
        
        // Create merged balance
        let merged_amount = numbers::add_integer(amount_a, amount_b);
        Ok(allocate_balance(ctx, merged_amount))
    }
}