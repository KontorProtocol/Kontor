use stdlib::*;
use std::cell::RefCell;

contract!(name = "token");

// Thread-local storage for balance resources
// The WIT resource system needs us to manage resource instances
thread_local! {
    static BALANCE_TABLE: RefCell<Vec<Option<BalanceData>>> = RefCell::new(Vec::new());
}

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

// The macro generates the Balance type but we need to implement the resource methods
// Since WIT resources require host-side implementation, we'll provide the methods
// through the Guest implementation
fn allocate_balance_resource(data: BalanceData) -> u32 {
    BALANCE_TABLE.with(|table| {
        let mut table = table.borrow_mut();
        // Find a free slot or add a new one
        let index = table.iter().position(|slot| slot.is_none())
            .unwrap_or_else(|| {
                table.push(None);
                table.len() - 1
            });
        table[index] = Some(data);
        index as u32
    })
}

fn take_balance_data(index: u32) -> Result<BalanceData, error::Error> {
    BALANCE_TABLE.with(|table| {
        let mut table = table.borrow_mut();
        let idx = index as usize;
        
        if idx >= table.len() {
            return Err(error::Error::Message("Invalid balance resource".to_string()));
        }
        
        table[idx].take()
            .ok_or_else(|| error::Error::Message("Balance already consumed or invalid".to_string()))
    })
}

fn get_balance_data(index: u32) -> Result<BalanceData, error::Error> {
    BALANCE_TABLE.with(|table| {
        let table = table.borrow();
        let idx = index as usize;
        
        if idx >= table.len() {
            return Err(error::Error::Message("Invalid balance resource".to_string()));
        }
        
        table[idx].clone()
            .ok_or_else(|| error::Error::Message("Balance not found".to_string()))
    })
}

// Helper function to get the token's contract address
fn get_contract_address(ctx: &impl ReadContext) -> foreign::ContractAddress {
    storage(ctx).contract_addr(ctx).unwrap_or_else(|| {
        // Fallback: This should be set during init
        foreign::ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 1,
        }
    })
}

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, numbers::Integer>,
    pub total_supply: numbers::Integer,
    pub contract_addr: Option<foreign::ContractAddress>, // Store our own address
    pub next_balance_id: numbers::Integer,  // Counter for unique balance IDs
    pub inflight: Map<String, InFlightEntry>, // Track in-flight balances using string ID
}

// Track in-flight balance data
#[derive(Clone, Storage)]
struct InFlightEntry {
    pub owner: String,      // Original withdrawer for refund on drop
    pub amount: numbers::Integer,
    pub token_addr: foreign::ContractAddress,
}

impl Default for InFlightEntry {
    fn default() -> Self {
        Self {
            owner: String::new(),
            amount: 0.into(),
            token_addr: foreign::ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
        }
    }
}


// Helper to allocate a new balance and register it as in-flight
fn allocate_balance(ctx: &ProcContext, amount: numbers::Integer, owner: String) -> Balance {
    let token_addr = get_contract_address(ctx);
    
    // Get next ID and increment counter
    let id = storage(ctx).next_balance_id(ctx);
    let one = numbers::u64_to_integer(1);
    storage(ctx).set_next_balance_id(ctx, numbers::add_integer(id, one));
    
    // Register the in-flight balance
    let entry = InFlightEntry {
        owner: owner.clone(),
        amount,
        token_addr: token_addr.clone(),
    };
    let handle = create_handle(id);
    storage(ctx).inflight().set(ctx, handle.clone(), entry);
    
    // Create the resource data
    let data = BalanceData {
        token_addr,
        amount,
        handle,
    };
    
    // Allocate a resource handle
    let index = allocate_balance_resource(data);
    
    // The macro should provide a way to create Balance from index
    // For now, we'll use unsafe from_handle which the macro generates
    unsafe { Balance::from_handle(index) }
}

// Helper to consume a balance
fn consume_balance(ctx: &ProcContext, balance: Balance) -> Result<(numbers::Integer, String), error::Error> {
    // Get the handle from the Balance resource
    let index = balance.take_handle();
    
    // Take the balance data from the resource table (this consumes it)
    let balance_data = take_balance_data(index)?;
    
    let inflight = storage(ctx).inflight();
    
    // Check if balance is still valid in storage
    let entry = inflight.get(ctx, &balance_data.handle)
        .ok_or_else(|| error::Error::Message("Invalid or already consumed balance".to_string()))?;
    let entry_data = entry.load(ctx);
    
    // Check if it's already been consumed (amount would be 0)
    let zero = numbers::u64_to_integer(0);
    if entry_data.amount == zero {
        return Err(error::Error::Message("Balance already consumed".to_string()));
    }
    
    // Verify amount and token matches (defensive check)
    if entry_data.amount != balance_data.amount || entry_data.token_addr != balance_data.token_addr {
        return Err(error::Error::Message("Balance data mismatch - possible tampering".to_string()));
    }
    
    // Mark as consumed by setting amount to 0 (keep entry for audit trail)
    let consumed_entry = InFlightEntry {
        owner: entry_data.owner.clone(),
        amount: zero,
        token_addr: entry_data.token_addr,
    };
    inflight.set(ctx, balance_data.handle, consumed_entry);
    
    Ok((entry_data.amount, entry_data.owner))
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
        Ok(allocate_balance(ctx, amount, owner))
    }
    
    fn deposit(ctx: &ProcContext, recipient: String, bal: Balance) -> Result<(), error::Error> {
        // Consume the balance (this moves it, enforcing linearity)
        let (amount, _original_owner) = consume_balance(ctx, bal)?;
        
        // Credit the recipient
        let ledger = storage(ctx).ledger();
        let recipient_balance = ledger.get(ctx, &recipient).unwrap_or_default();
        ledger.set(ctx, recipient, numbers::add_integer(recipient_balance, amount));
        
        Ok(())
    }
    
    fn split(ctx: &ProcContext, bal: Balance, split_amount: numbers::Integer) -> Result<SplitResult, error::Error> {
        // Consume the original balance
        let (total_amount, original_owner) = consume_balance(ctx, bal)?;
        
        if split_amount > total_amount {
            return Err(error::Error::Message("Split amount exceeds balance".to_string()));
        }
        
        // Create split balance
        let split_balance = allocate_balance(ctx, split_amount, original_owner.clone());
        
        // Create remainder balance if any
        let remainder_amount = numbers::sub_integer(total_amount, split_amount);
        let zero = numbers::u64_to_integer(0);
        let remainder_balance = if remainder_amount > zero {
            Some(allocate_balance(ctx, remainder_amount, original_owner))
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
        let (amount_a, owner_a) = consume_balance(ctx, a)?;
        let (amount_b, _owner_b) = consume_balance(ctx, b)?;
        
        // Create merged balance
        let merged_amount = numbers::add_integer(amount_a, amount_b);
        Ok(allocate_balance(ctx, merged_amount, owner_a))
    }
}