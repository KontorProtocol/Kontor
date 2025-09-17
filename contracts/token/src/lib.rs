use stdlib::*;

contract!(name = "token");

// Helper function to get the token's contract address
fn get_contract_address(ctx: &impl ReadContext) -> foreign::ContractAddress {
    storage(ctx).contract_addr(ctx).expect(
        "Contract address must be properly set during initialization. \
         This indicates a deployment configuration error."
    )
}

fn same_address(a: &foreign::ContractAddress, b: &foreign::ContractAddress) -> bool {
    a.name == b.name && a.height == b.height && a.tx_index == b.tx_index
}

// Manual storage implementation since we can't derive with resource types
#[derive(Clone, Default)]
struct TokenStorage {
    pub ledger: Map<String, numbers::Integer>,
    pub total_supply: numbers::Integer,
    pub contract_addr: Option<foreign::ContractAddress>, // Store our own address
}

// Storage initialization
impl TokenStorage {
    fn init(&self, ctx: &impl WriteContext) {
        use stdlib::{Store, Retrieve};
        // Initialize with default values
        // Use Store trait to properly handle Integer type
        <numbers::Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), self.total_supply.clone());
        if let Some(ref addr) = self.contract_addr {
            <foreign::ContractAddress as Store>::__set(ctx, "contract_addr".parse().unwrap(), addr.clone());
        }
    }
}

// Helper function for storage access
fn storage<C>(_ctx: &C) -> TokenStorage {
    TokenStorage::default()
}

// Manual storage accessors
impl TokenStorage {
    fn ledger(&self) -> MapAccessor<String, numbers::Integer> {
        MapAccessor::new("ledger")
    }
    
    fn total_supply(&self, ctx: &impl ReadContext) -> numbers::Integer {
        use stdlib::Retrieve;
        <numbers::Integer as Retrieve>::__get(ctx, "total_supply".parse().unwrap()).unwrap_or_default()
    }
    
    fn set_total_supply(&self, ctx: &impl WriteContext, value: numbers::Integer) {
        use stdlib::Store;
        <numbers::Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), value);
    }
    
    fn contract_addr(&self, ctx: &impl ReadContext) -> Option<foreign::ContractAddress> {
        use stdlib::Retrieve;
        <foreign::ContractAddress as Retrieve>::__get(ctx, "contract_addr".parse().unwrap())
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

        // Use the numbers module comparison function
        if numbers::cmp_integer(from_balance.clone(), n.clone()) == numbers::Ordering::Less {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, numbers::sub_integer(from_balance, n));
        ledger.set(ctx, to, numbers::add_integer(to_balance, n));
        Ok(())
    }


    fn balance(ctx: &ViewContext, acc: String) -> Option<numbers::Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc)
    }
    
    fn balance_or_zero(ctx: &ViewContext, acc: String) -> numbers::Integer {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc).unwrap_or_default()
    }
    
    fn total_supply(ctx: &ViewContext) -> numbers::Integer {
        storage(ctx).total_supply(ctx)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<numbers::Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, &acc).map(|i| numbers::log10(numbers::integer_to_decimal(i)))
    }
    
    // Resource-based asset management
    fn withdraw(ctx: &ProcContext, amount: numbers::Integer) -> Result<Balance, error::Error> {
        let owner = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();
        let balance = ledger.get(ctx, &owner).unwrap_or_default();

        // Use the numbers module comparison function
        if numbers::cmp_integer(balance.clone(), amount.clone()) == numbers::Ordering::Less {
            return Err(error::Error::Message("insufficient funds".to_string()));
        }

        // Decrease ledger balance
        ledger.set(ctx, owner.clone(), numbers::sub_integer(balance, amount));

        // For now, return a placeholder - Balance resource creation needs host support
        // This would be handled by the resource manager in a real implementation
        Err(error::Error::Message("Balance resources not yet implemented".to_string()))
    }
    
    fn deposit(ctx: &ProcContext, recipient: String, bal: Balance) -> Result<(), error::Error> {
        // For now, deposit is not fully implemented due to resource limitations
        // In a real implementation, we would:
        // 1. Validate the balance belongs to this token contract
        // 2. Extract the amount from the Balance resource
        // 3. Credit the recipient's account
        // 4. Consume the Balance resource
        Err(error::Error::Message("Balance resources not yet implemented".to_string()))
    }
    
    fn split(ctx: &ProcContext, bal: Balance, split_amount: numbers::Integer) -> Result<SplitResult, error::Error> {
        // Balance split not yet implemented - requires resource support
        Err(error::Error::Message("Balance resources not yet implemented".to_string()))
    }
    
    fn merge(ctx: &ProcContext, a: Balance, b: Balance) -> Result<Balance, error::Error> {
        // Balance merge not yet implemented - requires resource support  
        Err(error::Error::Message("Balance resources not yet implemented".to_string()))
    }
}
