use stdlib::*;

contract!(name = "token");

// The contract macro generates these types at the crate root:
// - Integer, Balance, SplitResult
// Import ContractAddress and the functions we need:
use kontor::built_in::foreign::ContractAddress;
use kontor::built_in::assets::{balance_amount, balance_token};
// NOTE: create_balance has been removed to prevent forgery
// Balances are created internally by the withdraw operation

// Helper function to get the token's contract address
fn get_contract_address(ctx: &impl ReadContext) -> ContractAddress {
    storage(ctx).contract_addr(ctx).expect(
        "Contract address must be properly set during initialization. \
         This indicates a deployment configuration error."
    )
}

fn same_address(a: &ContractAddress, b: &ContractAddress) -> bool {
    a.name == b.name && a.height == b.height && a.tx_index == b.tx_index
}

// Manual storage implementation since we can't derive with resource types
#[derive(Clone, Default)]
struct TokenStorage {
    pub ledger: Map<String, Integer>,
    pub total_supply: Integer,
    pub contract_addr: Option<ContractAddress>, // Store our own address
}

// Storage initialization
impl TokenStorage {
    fn init(&self, ctx: &impl WriteContext) {
        use stdlib::Store;
        // Initialize with default values
        // Use Store trait to properly handle Integer type
        <Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), self.total_supply.clone());
        if let Some(ref addr) = self.contract_addr {
            <ContractAddress as Store>::__set(ctx, "contract_addr".parse().unwrap(), addr.clone());
        }
    }
}

// Helper function for storage access
fn storage<C>(_ctx: &C) -> TokenStorage {
    TokenStorage::default()
}

// Manual storage accessors
impl TokenStorage {
    fn ledger(&self) -> MapAccessor<String, Integer> {
        MapAccessor::new("ledger")
    }
    
    fn total_supply(&self, ctx: &impl ReadContext) -> Integer {
        use stdlib::Retrieve;
        <Integer as Retrieve>::__get(ctx, "total_supply".parse().unwrap()).unwrap_or_default()
    }
    
    fn set_total_supply(&self, ctx: &impl WriteContext, value: Integer) {
        use stdlib::Store;
        <Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), value);
    }
    
    fn contract_addr(&self, ctx: &impl ReadContext) -> Option<ContractAddress> {
        use stdlib::Retrieve;
        <ContractAddress as Retrieve>::__get(ctx, "contract_addr".parse().unwrap())
    }
}

// MapAccessor helper for ledger
struct MapAccessor<K, V> {
    base_path: String,
    _phantom: std::marker::PhantomData<(K, V)>,
}

impl<K: ToString + FromString, V: Store + Retrieve + Default> MapAccessor<K, V> {
    fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            _phantom: std::marker::PhantomData,
        }
    }
    
    fn get(&self, ctx: &impl ReadContext, key: &K) -> Option<V> {
        let mut path: DotPathBuf = self.base_path.parse().unwrap();
        path = path.push(key.to_string());
        V::__get(ctx, path)
    }
    
    fn set(&self, ctx: &impl WriteContext, key: K, value: V) {
        let mut path: DotPathBuf = self.base_path.parse().unwrap();
        path = path.push(key.to_string());
        V::__set(ctx, path, value);
    }
}

// Helper to allocate a new balance
impl Guest for Token {
    fn init(ctx: &ProcContext) {
        // Store the contract's address on initialization
        // In a real deployment, this would be set from deployment parameters
        let contract_addr = ContractAddress {
            name: "token".to_string(),
            height: 0,  // Should be set from deployment context
            tx_index: 1, // Should be set from deployment context
        };
        
        let mut storage = TokenStorage::default();
        storage.contract_addr = Some(contract_addr);
        storage.init(ctx);
    }

    fn mint(ctx: &ProcContext, n: kontor::built_in::numbers::Integer) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let current_supply = storage(ctx).total_supply(ctx);

        let balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, to, kontor::built_in::numbers::add_integer(balance, n));

        storage(ctx).set_total_supply(ctx, kontor::built_in::numbers::add_integer(current_supply, n));
    }

    fn transfer(ctx: &ProcContext, to: String, n: kontor::built_in::numbers::Integer) -> Result<(), kontor::built_in::error::Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();

        // Use the numbers module comparison function
        if kontor::built_in::numbers::cmp_integer(from_balance.clone(), n.clone()) == kontor::built_in::numbers::Ordering::Less {
            return Err(kontor::built_in::error::Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, kontor::built_in::numbers::sub_integer(from_balance, n));
        ledger.set(ctx, to, kontor::built_in::numbers::add_integer(to_balance, n));
        Ok(())
    }


    fn balance(ctx: &ViewContext, acc: String) -> Option<kontor::built_in::numbers::Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc)
    }
    
    fn balance_or_zero(ctx: &ViewContext, acc: String) -> kontor::built_in::numbers::Integer {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc).unwrap_or_default()
    }
    
    fn total_supply(ctx: &ViewContext) -> kontor::built_in::numbers::Integer {
        storage(ctx).total_supply(ctx)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<kontor::built_in::numbers::Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc).map(|i| kontor::built_in::numbers::log10(kontor::built_in::numbers::integer_to_decimal(i)))
    }
    
    // Resource-based asset management
    fn withdraw(ctx: &ProcContext, amount: kontor::built_in::numbers::Integer) -> Result<Balance, kontor::built_in::error::Error> {
        let owner = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let balance = ledger.get(ctx, &owner).unwrap_or_default();

        // Use the numbers module comparison function
        if kontor::built_in::numbers::cmp_integer(balance.clone(), amount.clone()) == kontor::built_in::numbers::Ordering::Less {
            return Err(kontor::built_in::error::Error::Message("insufficient funds".to_string()));
        }

        // Decrease ledger balance
        ledger.set(ctx, owner.clone(), kontor::built_in::numbers::sub_integer(balance, amount));

        // Create a Balance resource for the withdrawal
        let contract_addr = get_contract_address(ctx);
        let balance = Balance::new(amount, &contract_addr);

        // Register the Balance resource for cross-contract transfer
        let handle = kontor::built_in::resource_manager::register_balance(balance);

        // Transfer ownership to the calling contract
        let token_contract_id = 1; // TODO: Get actual token contract ID
        let caller_contract_id = 2; // TODO: Get actual caller contract ID

        kontor::built_in::resource_manager::transfer(
            token_contract_id,
            caller_contract_id,
            handle
        )?;

        // Retrieve the Balance resource to return to the caller
        // Since we just transferred ownership, the caller can take it
        match kontor::built_in::resource_manager::take_balance(handle) {
            Ok(transferred_balance) => Ok(transferred_balance),
            Err(e) => Err(kontor::built_in::error::Error::Message(format!("Transfer failed: {:?}", e))),
        }
    }
    
    fn deposit(ctx: &ProcContext, recipient: String, bal: Balance) -> Result<(), kontor::built_in::error::Error> {
        // Use accessor functions to get resource data BEFORE consuming
        let amount = balance_amount(&bal);
        let token = balance_token(&bal);

        // Verify the balance is for this token contract
        let contract_addr = get_contract_address(ctx);
        if !same_address(&token, &contract_addr) {
            return Err(kontor::built_in::error::Error::Message("Balance is for different token".to_string()));
        }

        // CRITICAL: Explicitly consume the balance to enforce linearity
        // This validates ownership and prevents double-spending
        bal.consume();

        // Credit the recipient's account AFTER consuming the balance
        let ledger = storage(ctx).ledger();
        let current_balance = ledger.get(ctx, &recipient).unwrap_or_default();
        ledger.set(ctx, recipient, kontor::built_in::numbers::add_integer(current_balance, amount));

        Ok(())
    }
    
    fn split(_ctx: &ProcContext, bal: Balance, split_amount: kontor::built_in::numbers::Integer) -> Result<SplitResult, kontor::built_in::error::Error> {
        // SECURITY: Use host-backed split operation to enforce ownership and atomicity
        // This consumes the original balance and creates new ones with proper validation

        // Check if split amount is valid before calling host operation
        let total_amount = balance_amount(&bal);
        if kontor::built_in::numbers::cmp_integer(split_amount.clone(), total_amount) == kontor::built_in::numbers::Ordering::Greater {
            return Err(kontor::built_in::error::Error::Message("Split amount exceeds balance".to_string()));
        }

        // Use the host-backed split operation which:
        // 1. Validates ownership (only owner can split)
        // 2. Atomically consumes original and creates new balances
        // 3. Enforces linear type safety
        let split_result = bal.split(split_amount);

        Ok(SplitResult {
            split: split_result.split,
            remainder: split_result.remainder,
        })
    }
    
    fn merge(_ctx: &ProcContext, a: Balance, b: Balance) -> Result<Balance, kontor::built_in::error::Error> {
        // SECURITY: Use host-backed merge operation to enforce ownership and atomicity
        // This validates that both balances are owned by the current contract
        // and atomically consumes both to create a new merged balance

        // Verify both balances are for the same token before merging
        let token_a = balance_token(&a);
        let token_b = balance_token(&b);

        if !same_address(&token_a, &token_b) {
            return Err(kontor::built_in::error::Error::Message("Cannot merge balances from different tokens".to_string()));
        }

        // Use the host-backed merge operation which:
        // 1. Validates ownership (only owner can merge)
        // 2. Atomically consumes both input balances
        // 3. Creates new merged balance with proper validation
        // 4. Enforces linear type safety
        match Balance::merge(a, b) {
            Ok(merged_balance) => Ok(merged_balance),
            Err(error_msg) => Err(kontor::built_in::error::Error::Message(error_msg)),
        }
    }
}
