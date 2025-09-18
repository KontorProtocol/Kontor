use stdlib::*;

contract!(name = "simple_token");

// Simple token storage - manual implementation since Integer is a WIT type
#[derive(Clone, Default)]
struct TokenStorage {
    pub balances: Map<String, Integer>,
    pub total_supply: Integer,
}

// Storage helper function
fn storage<C>(_ctx: &C) -> TokenStorage {
    TokenStorage::default()
}

// Manual storage accessors
impl TokenStorage {
    fn init(&self, ctx: &impl WriteContext) {
        // Initialize with default values
        use stdlib::{Store, Retrieve};
        <Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), self.total_supply.clone());
    }

    fn balances(&self) -> MapAccessor<String, Integer> {
        MapAccessor::new("balances")
    }

    fn total_supply(&self, ctx: &impl ReadContext) -> Integer {
        use stdlib::Retrieve;
        <Integer as Retrieve>::__get(ctx, "total_supply".parse().unwrap()).unwrap_or_default()
    }

    fn set_total_supply(&self, ctx: &impl WriteContext, value: Integer) {
        use stdlib::Store;
        <Integer as Store>::__set(ctx, "total_supply".parse().unwrap(), value);
    }
}

// MapAccessor helper for map storage
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

impl Guest for SimpleToken {
    fn init(_ctx: &ProcContext) {
        // Initialize storage
        TokenStorage::default().init(_ctx);
    }
    
    fn mint(ctx: &ProcContext, to: String, amount: Integer) {
        let storage = storage(ctx);
        let balances = storage.balances();

        // Get current balance, default to 0
        let current = balances.get(ctx, &to).unwrap_or_default();

        // Add the new amount to current balance
        let new_balance = kontor::built_in::numbers::add_integer(current, amount);
        balances.set(ctx, to, new_balance);

        // Update total supply
        let current_supply = storage.total_supply(ctx);
        let new_supply = kontor::built_in::numbers::add_integer(current_supply, amount);
        storage.set_total_supply(ctx, new_supply);
    }
    
    fn transfer(ctx: &ProcContext, to: String, amount: Integer) -> Result<(), Error> {
        let storage = storage(ctx);
        let balances = storage.balances();

        // Get sender (would need proper signer handling)
        let from = "sender".to_string(); // Placeholder

        // Get current balances
        let from_balance = balances.get(ctx, &from).unwrap_or_default();
        let to_balance = balances.get(ctx, &to).unwrap_or_default();

        // Check sufficient funds (compare with zero)
        let zero = Integer::default();
        if kontor::built_in::numbers::cmp_integer(from_balance, amount) == kontor::built_in::numbers::Ordering::Less {
            return Err(Error::Message("Insufficient balance".to_string()));
        }

        // Perform transfer
        let new_from_balance = kontor::built_in::numbers::sub_integer(from_balance, amount);
        let new_to_balance = kontor::built_in::numbers::add_integer(to_balance, amount);

        balances.set(ctx, from, new_from_balance);
        balances.set(ctx, to, new_to_balance);

        Ok(())
    }

    fn balance(ctx: &ViewContext, account: String) -> Integer {
        let storage = storage(ctx);
        let balances = storage.balances();
        balances.get(ctx, &account).unwrap_or_default()
    }

    fn total_supply(ctx: &ViewContext) -> Integer {
        storage(ctx).total_supply(ctx)
    }
}