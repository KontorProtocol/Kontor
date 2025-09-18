use stdlib::*;

contract!(name = "amm");

// Use interface macro for real cross-contract calls  
// TODO: Fix interface! macro for cross-contract calls
// interface!(name = "token_dyn", path = "token/wit");

// Temporary stubs until interface! macro is fixed
mod token_dyn {
    use super::*;
    
    pub fn balance_or_zero(_token: &ContractAddress, _account: String) -> Integer {
        Integer::default()
    }
    
    pub fn deposit(_token: &ContractAddress, _signer: &String, _recipient: &str, _balance: Balance) -> Result<(), Error> {
        Ok(())
    }
    
    pub fn withdraw(_token: &ContractAddress, _signer: &String, _amount: Integer) -> Result<Balance, Error> {
        // Create a dummy balance - can't use default since Balance is a resource
        Ok(create_balance(Integer::default(), &ContractAddress::default()))
    }
    
    pub struct SplitResult {
        pub split: Balance,
        pub remainder: Option<Balance>,
    }
    
    pub fn split(_token: &ContractAddress, _signer: &String, _balance: Balance, _amount: Integer) -> Result<SplitResult, Error> {
        Ok(SplitResult {
            split: create_balance(Integer::default(), &ContractAddress::default()),
            remainder: None,
        })
    }
}

// # Pure Resource AMM Contract
// 
// This Automated Market Maker (AMM) contract implements a constant product formula
// similar to Uniswap V2 with admin fees.
//
// ## Core Design Principle
// 
// This AMM operates on a **pure resource model**. Ownership of liquidity is represented 
// *solely* by holding an `LpBalance` resource, not by an internal ledger. This eliminates
// complexity, ensures perfect linearity, and makes the contract much more secure and
// composable.
// 
// The contract transforms resources: `(Balance, Balance) -> LpBalance` for deposits,
// `LpBalance -> (Balance, Balance)` for withdrawals, and `Balance -> Balance` for swaps.

// Typed canonical pair wrapper that sorts by tuple comparison
#[derive(Clone, Debug)]
pub struct CanonicalTokenPair {
    token_a: foreign::ContractAddress,
    token_b: foreign::ContractAddress,
    id: String,
}

// Manual PartialEq implementation for ContractAddress comparison
impl PartialEq for CanonicalTokenPair {
    fn eq(&self, other: &Self) -> bool {
        self.token_a.name == other.token_a.name &&
        self.token_a.height == other.token_a.height &&
        self.token_a.tx_index == other.token_a.tx_index &&
        self.token_b.name == other.token_b.name &&
        self.token_b.height == other.token_b.height &&
        self.token_b.tx_index == other.token_b.tx_index
    }
}

impl Eq for CanonicalTokenPair {}

// Default implementation for ContractAddress
impl Default for foreign::ContractAddress {
    fn default() -> Self {
        Self {
            name: String::new(),
            height: 0,
            tx_index: 0,
        }
    }
}

// Helper function to compare ContractAddress instances
fn addr_eq(a: &foreign::ContractAddress, b: &foreign::ContractAddress) -> bool {
    a.name == b.name && a.height == b.height && a.tx_index == b.tx_index
}

impl CanonicalTokenPair {
    /// Creates a new canonical pair, automatically sorting A < B by (name, height, tx_index) tuple
    pub fn new(
        a: foreign::ContractAddress, 
        b: foreign::ContractAddress
    ) -> Result<Self, AmmError> {
        // Validate that both tokens are properly specified
        if a.name.is_empty() || b.name.is_empty() {
            return Err(AmmError::InvalidPair);
        }
        
        // Create tuples for proper sorting (lexicographic comparison)
        let a_tuple = (&a.name, a.height, a.tx_index);
        let b_tuple = (&b.name, b.height, b.tx_index);
        
        // Ensure tokens are different
        if a_tuple == b_tuple {
            return Err(AmmError::InvalidPair);
        }
        
        // Sort to ensure canonical ordering
        let (token_a, token_b) = if a_tuple < b_tuple {
            (a, b)
        } else {
            (b, a)
        };
        
        // Generate the internal pair ID
        let id = format!("{}_{}_{}::{}_{}_{}",
            token_a.name, token_a.height, token_a.tx_index,
            token_b.name, token_b.height, token_b.tx_index
        );
        
        Ok(Self { token_a, token_b, id })
    }
    
    /// Returns the canonical tuple representation by value (clones)
    pub fn as_tuple(&self) -> (foreign::ContractAddress, foreign::ContractAddress) {
        (self.token_a.clone(), self.token_b.clone())
    }
    
    /// Returns references to the token addresses to avoid cloning
    pub fn as_refs(&self) -> (&foreign::ContractAddress, &foreign::ContractAddress) {
        (&self.token_a, &self.token_b)
    }
    
    /// Returns the internal pair ID (for storage keys)
    pub fn id(&self) -> &str {
        &self.id
    }
    
}

// Typed error enum for better error handling
#[derive(Debug, Clone)]
pub enum AmmError {
    PoolNotFound,
    NotAdmin,
    ExcessiveSlippage,
    NoLiquidity,
    InvalidPair,
    InvalidFees,
    InsufficientLpTokens,
    InsufficientAdminFees,
    InputBalanceZero,
    InitialLiquidityTooSmall,
    PoolAlreadyExists,
    InvalidTokenIn,
}

impl From<AmmError> for Error {
    fn from(err: AmmError) -> Self {
        let message = match err {
            AmmError::PoolNotFound => "Pool not found",
            AmmError::NotAdmin => "Not authorized: admin only",
            AmmError::ExcessiveSlippage => "Excessive slippage",
            AmmError::NoLiquidity => "Pool has no liquidity",
            AmmError::InvalidPair => "Invalid token pair",
            AmmError::InvalidFees => "Invalid fee parameters",
            AmmError::InsufficientLpTokens => "Insufficient LP tokens",
            AmmError::InsufficientAdminFees => "Insufficient admin fees",
            AmmError::InputBalanceZero => "Input balances cannot be zero",
            AmmError::InitialLiquidityTooSmall => "Initial liquidity too small",
            AmmError::PoolAlreadyExists => "Pool already exists",
            AmmError::InvalidTokenIn => "Invalid token_in: must match pool's token_a or token_b",
        };
        Error::Message(message.to_string())
    }
}

#[derive(Clone)]
struct Pool {
    pub token_a: foreign::ContractAddress,
    pub token_b: foreign::ContractAddress,
    pub lp_fee_bps: numbers::Integer,
    pub admin_fee_pct: numbers::Integer,
    pub admin_fee_lp: numbers::Integer,
    pub lp_total_supply: numbers::Integer,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            token_a: foreign::ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            token_b: foreign::ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            lp_fee_bps: numbers::u64_to_integer(0),
            admin_fee_pct: numbers::u64_to_integer(0),
            admin_fee_lp: numbers::u64_to_integer(0),
            lp_total_supply: numbers::u64_to_integer(0),
        }
    }
}

// Manual Store implementation for Pool
impl stdlib::Store for Pool {
    fn __set(ctx: &impl stdlib::WriteContext, path: stdlib::DotPathBuf, value: Self) {
        use stdlib::Store;
        <foreign::ContractAddress as Store>::__set(ctx, path.clone().push("token_a".to_string()), value.token_a);
        <foreign::ContractAddress as Store>::__set(ctx, path.clone().push("token_b".to_string()), value.token_b);
        <numbers::Integer as Store>::__set(ctx, path.clone().push("lp_fee_bps".to_string()), value.lp_fee_bps);
        <numbers::Integer as Store>::__set(ctx, path.clone().push("admin_fee_pct".to_string()), value.admin_fee_pct);
        <numbers::Integer as Store>::__set(ctx, path.clone().push("admin_fee_lp".to_string()), value.admin_fee_lp);
        <numbers::Integer as Store>::__set(ctx, path.clone().push("lp_total_supply".to_string()), value.lp_total_supply);
    }
}

impl stdlib::Retrieve for Pool {
    fn __get(ctx: &impl stdlib::ReadContext, path: stdlib::DotPathBuf) -> Option<Self> {
        use stdlib::Retrieve;
        Some(Pool {
            token_a: <foreign::ContractAddress as Retrieve>::__get(ctx, path.clone().push("token_a".to_string()))?,
            token_b: <foreign::ContractAddress as Retrieve>::__get(ctx, path.clone().push("token_b".to_string()))?,
            lp_fee_bps: <numbers::Integer as Retrieve>::__get(ctx, path.clone().push("lp_fee_bps".to_string()))?,
            admin_fee_pct: <numbers::Integer as Retrieve>::__get(ctx, path.clone().push("admin_fee_pct".to_string()))?,
            admin_fee_lp: <numbers::Integer as Retrieve>::__get(ctx, path.clone().push("admin_fee_lp".to_string()))?,
            lp_total_supply: <numbers::Integer as Retrieve>::__get(ctx, path.clone().push("lp_total_supply".to_string()))?,
        })
    }
}

#[derive(Clone, Default)]
struct AmmStorage {
    pub pools: Map<String, Pool>,
    pub admin: String,  // Admin address (signer-based auth)
    pub self_address: String,
}

// Manual storage implementation
impl AmmStorage {
    fn init(&self, ctx: &impl WriteContext) {
        // Initialize admin and self_address
        ctx.__set_str("admin", &self.admin);
        ctx.__set_str("self_address", &self.self_address);
    }
    
    fn pools(&self) -> PoolMapAccessor {
        PoolMapAccessor::new("pools")
    }
    
    fn admin(&self, ctx: &impl ReadContext) -> String {
        ctx.__get_str("admin").unwrap_or_default()
    }
    
    fn set_admin(&self, ctx: &impl WriteContext, value: String) {
        ctx.__set_str("admin", &value);
    }
    
    fn self_address(&self, ctx: &impl ReadContext) -> String {
        ctx.__get_str("self_address").unwrap_or_default()
    }
    
    fn set_self_address(&self, ctx: &impl WriteContext, value: String) {
        ctx.__set_str("self_address", &value);
    }
}

// Pool map accessor
struct PoolMapAccessor {
    base_path: String,
}

impl PoolMapAccessor {
    fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
        }
    }
    
    fn get(&self, ctx: &impl ReadContext, key: &str) -> Option<PoolAccessor> {
        let path: DotPathBuf = self.base_path.parse().unwrap();
        let path = path.push(key.to_string());
        if ctx.__exists(&path.to_string()) {
            Some(PoolAccessor::new(path.to_string()))
        } else {
            None
        }
    }
    
    fn set(&self, ctx: &impl WriteContext, key: String, value: Pool) {
        let path: DotPathBuf = self.base_path.parse().unwrap();
        let path = path.push(key);
        // Store each field of the pool
        use stdlib::Store;
        <foreign::ContractAddress as Store>::__set(ctx, path.push("token_a".to_string()), value.token_a);
        <foreign::ContractAddress as Store>::__set(ctx, path.push("token_b".to_string()), value.token_b);
        <numbers::Integer as Store>::__set(ctx, path.push("lp_fee_bps".to_string()), value.lp_fee_bps);
        <numbers::Integer as Store>::__set(ctx, path.push("admin_fee_pct".to_string()), value.admin_fee_pct);
        <numbers::Integer as Store>::__set(ctx, path.push("admin_fee_lp".to_string()), value.admin_fee_lp);
        <numbers::Integer as Store>::__set(ctx, path.push("lp_total_supply".to_string()), value.lp_total_supply);
    }
}

// Pool accessor for reading pool data
struct PoolAccessor {
    path: String,
}

impl PoolAccessor {
    fn new(path: String) -> Self {
        Self { path }
    }
    
    fn load(&self, ctx: &impl ReadContext) -> Pool {
        use stdlib::Retrieve;
        let base_path: DotPathBuf = self.path.parse().unwrap();
        Pool {
            token_a: <foreign::ContractAddress as Retrieve>::__get(ctx, base_path.push("token_a".to_string())).unwrap_or_default(),
            token_b: <foreign::ContractAddress as Retrieve>::__get(ctx, base_path.push("token_b".to_string())).unwrap_or_default(),
            lp_fee_bps: <numbers::Integer as Retrieve>::__get(ctx, base_path.push("lp_fee_bps".to_string())).unwrap_or_default(),
            admin_fee_pct: <numbers::Integer as Retrieve>::__get(ctx, base_path.push("admin_fee_pct".to_string())).unwrap_or_default(),
            admin_fee_lp: <numbers::Integer as Retrieve>::__get(ctx, base_path.push("admin_fee_lp".to_string())).unwrap_or_default(),
            lp_total_supply: <numbers::Integer as Retrieve>::__get(ctx, base_path.push("lp_total_supply".to_string())).unwrap_or_default(),
        }
    }
}

// Helper function for storage access
fn storage<C>(_ctx: &C) -> AmmStorage {
    AmmStorage::default()
}

fn get_token_balance(_signer: Option<context::Signer>, token: &foreign::ContractAddress, account: &str) -> Result<numbers::Integer, Error> {
    Ok(token_dyn::balance_or_zero(token, account.to_string()))
}

// Since we're using the same Balance type from built-in assets everywhere,
// these conversion functions are now identity functions.
// They're kept for API compatibility but could be removed in a refactor.
fn balance_to_interface(balance: Balance) -> Balance {
    balance
}

fn balance_from_interface(balance: Balance) -> Balance {
    balance
}

fn balance_option_from_interface(balance: Option<Balance>) -> Option<Balance> {
    balance
}

// Helper function to consume a token Balance and deposit it to the pool
fn consume_token_balance_to_pool(
    ctx: &ProcContext,
    balance: Balance,
    pool_address: &str,
    token: &foreign::ContractAddress,
) -> Result<numbers::Integer, Error> {
    // Get the actual amount from the Balance resource
    let amount = balance_amount(&balance);
    
    // Convert and deposit the balance to the pool
    let iface_balance = balance_to_interface(balance);
    token_dyn::deposit(token, &ctx.contract_signer().to_string(), pool_address, iface_balance)?;
    
    Ok(amount)
}

// Helper function to create and return a token Balance from the pool
fn create_token_balance_from_pool(
    ctx: &ProcContext,
    token: &foreign::ContractAddress,
    amount: numbers::Integer,
) -> Result<Balance, Error> {
    let iface_balance = token_dyn::withdraw(token, &ctx.contract_signer().to_string(), amount)?;
    Ok(balance_from_interface(iface_balance))
}

// Helper function to load a pool using canonical pair or return error
fn load_pool(ctx: &impl ReadContext, pair: &TokenPair) -> Result<(String, PoolAccessor, Pool), AmmError> {
    let canonical_pair = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?;
    let id = canonical_pair.id().to_string();
    let pools = storage(ctx).pools();
    let pool_accessor = pools.get(ctx, &id)
        .ok_or(AmmError::PoolNotFound)?;
    let pool = pool_accessor.load(ctx);
    Ok((id, pool_accessor, pool))
}

// Dedicated function for minting admin fees - the only place that touches admin_fee_lp and lp_total_supply for fees
fn mint_admin_fee_lp(
    pool: &mut Pool,
    admin_fee_in_lp: numbers::Integer,
) {
    pool.admin_fee_lp = numbers::add_integer(pool.admin_fee_lp, admin_fee_in_lp);
    pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, admin_fee_in_lp);
}

// Helper function to get both token balances for a pool
fn get_pool_token_balances(
    pool: &Pool,
    pool_address: &str,
) -> Result<(numbers::Integer, numbers::Integer), Error> {
    let balance_a = get_token_balance(None, &pool.token_a, pool_address)?;
    let balance_b = get_token_balance(None, &pool.token_b, pool_address)?;
    Ok((balance_a, balance_b))
}

// update_lp_balance removed - LP ownership is now tracked solely via LpBalance resources!

// Helper function to check admin authorization
fn ensure_admin_auth(ctx: &ProcContext) -> Result<(), AmmError> {
    if ctx.signer().to_string() != storage(ctx).admin(ctx) {
        return Err(AmmError::NotAdmin);
    }
    Ok(())
}

// Helper function for slippage validation
fn validate_min_output(actual: numbers::Integer, minimum: numbers::Integer) -> Result<(), AmmError> {
    if numbers::cmp_integer(actual, minimum) == numbers::Ordering::Less {
        return Err(AmmError::ExcessiveSlippage);
    }
    Ok(())
}

// Helper function for common swap logic
// Helper functions for constants (since we can't call functions in const)
fn bps_in_100_pct() -> numbers::Integer {
    numbers::u64_to_integer(10000) // 100% = 10000 basis points
}

fn pct_100() -> numbers::Integer {
    numbers::u64_to_integer(100)
}

fn minimum_liquidity() -> numbers::Integer {
    numbers::u64_to_integer(1000) // Permanently locked LP tokens to prevent edge cases
}

/// Public constant function for minimum liquidity (to be exposed via WIT)
pub fn min_liquidity() -> numbers::Integer {
    minimum_liquidity()
}

fn calc_swap_result(
    i_value: numbers::Integer,
    i_pool_value: numbers::Integer,
    o_pool_value: numbers::Integer,
    pool_lp_value: numbers::Integer,
    lp_fee_bps: numbers::Integer,
    admin_fee_pct: numbers::Integer,
) -> Result<(numbers::Integer, numbers::Integer), Error> {
    // Calculate LP fee (round up to ensure protocol always collects fee)
    let lp_fee_value = numbers::mul_div_up_integer(i_value, lp_fee_bps, bps_in_100_pct());
    let in_after_lp_fee = numbers::sub_integer(i_value, lp_fee_value);
    
    // Calculate output amount using constant product formula
    // out = (in_after_fee * out_pool) / (in_pool + in_after_fee)
    let out_value = numbers::mul_div_down_integer(
        in_after_lp_fee,
        o_pool_value,
        numbers::add_integer(i_pool_value, in_after_lp_fee)
    );
    
    // Calculate admin fee value (as portion of LP fee)
    let admin_fee_value = numbers::mul_div_down_integer(lp_fee_value, admin_fee_pct, pct_100());
    
    // Convert admin fee to LP tokens proportionally
    // Note: This is an approximation similar to Uniswap V2's approach
    // admin_fee_in_lp ≈ (admin_fee_value * pool_lp) / (i_pool + i_value - admin_fee_value)
    let admin_fee_in_lp = if numbers::cmp_integer(pool_lp_value.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
        numbers::u64_to_integer(0)
    } else {
        let adjusted_pool = numbers::sub_integer(
            numbers::add_integer(i_pool_value, i_value),
            admin_fee_value
        );
        numbers::mul_div_down_integer(admin_fee_value, pool_lp_value, adjusted_pool)
    };
    
    Ok((out_value, admin_fee_in_lp))
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        let admin = ctx.signer().to_string();
        let self_address = ctx.contract_signer().to_string();
        
        AmmStorage {
            pools: Map::default(),
            admin,
            self_address,
        }
        .init(ctx)
    }

    fn create(
        ctx: &ProcContext,
        pair: TokenPair,
        balance_a: Balance,
        balance_b: Balance,
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<LpBalance, Error> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?;

        // Get actual amounts from the Balance resources
        let init_a = balance_amount(&balance_a);
        let init_b = balance_amount(&balance_b);
        // Can't validate tokens since we can't access resource fields

        if numbers::cmp_integer(init_a.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
           numbers::cmp_integer(init_b.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            return Err(AmmError::InputBalanceZero.into());
        }

        let (token_a, token_b) = canonical_pair.as_tuple();
        
        // Skip token validation since we can't access resource fields in guest code

        // Validate fee parameters
        if numbers::cmp_integer(lp_fee_bps.clone(), bps_in_100_pct()) != numbers::Ordering::Less || 
           numbers::cmp_integer(admin_fee_pct.clone(), pct_100()) == numbers::Ordering::Greater {
            return Err(AmmError::InvalidFees.into());
        }

        let id = canonical_pair.id().to_string();
        let pools = storage(ctx).pools();
        
        // Check if pool already exists
        if pools.get(ctx, &id).is_some() {
            return Err(AmmError::PoolAlreadyExists.into());
        }

        let pool_address = ctx.contract_signer().to_string();
        
        // Consume the Balance resources and deposit them to the pool
        // This is much cleaner than the old approve/transfer pattern!
        consume_token_balance_to_pool(ctx, balance_a, &pool_address, &token_a)?;
        consume_token_balance_to_pool(ctx, balance_b, &pool_address, &token_b)?;

        // Calculate initial LP tokens: sqrt(init_a * init_b)
        let total_lp = numbers::mul_sqrt_integer(init_a, init_b);
        
        // Lock MINIMUM_LIQUIDITY permanently on first pool creation
        let min_liq = minimum_liquidity();
        if numbers::cmp_integer(total_lp.clone(), min_liq.clone()) != numbers::Ordering::Greater {
            return Err(AmmError::InitialLiquidityTooSmall.into());
        }
        let lp_to_issue = numbers::sub_integer(total_lp, min_liq);
        
        // Create pool - no ledger needed, LP ownership is tracked via resources!
        let lp_pair = TokenPair {
            token_a: token_a.clone(),
            token_b: token_b.clone(),
        };

        pools.set(
            ctx,
            id,
            Pool {
                token_a,
                token_b,
                lp_fee_bps,
                admin_fee_pct,
                admin_fee_lp: numbers::u64_to_integer(0),
                lp_total_supply: total_lp,
            },
        );

        // EVENT: PoolCreated { pool_id: id, initial_lp: lp_to_issue }
        
        // Create LpBalance resource using factory function
        Ok(create_lp_balance(lp_to_issue, &pair.token_a, &pair.token_b))
    }

    fn values(ctx: &ViewContext, pair: TokenPair) -> Option<PoolValues> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = storage(ctx).self_address(ctx);
            
            // Get current balances from token contracts
            let balance_a = get_token_balance(None, &pool.token_a, &pool_address).ok()?;
            let balance_b = get_token_balance(None, &pool.token_b, &pool_address).ok()?;
            
            Some(PoolValues {
                a: balance_a,
                b: balance_b,
                lp: pool.lp_total_supply,
            })
        })
    }

    fn fees(ctx: &ViewContext, pair: TokenPair) -> Option<FeeInfo> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).map(|p| {
            let pool = p.load(ctx);
            FeeInfo {
                lp_fee_bps: pool.lp_fee_bps,
                admin_fee_pct: pool.admin_fee_pct,
            }
        })
    }

    fn admin_fee_value(ctx: &ViewContext, pair: TokenPair) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).map(|p| p.load(ctx).admin_fee_lp)
    }

    fn deposit(
        ctx: &ProcContext,
        pair: TokenPair,
        balance_a: Balance,
        balance_b: Balance,
        min_lp_out: numbers::Integer,
    ) -> Result<LpBalance, Error> {
        let (id, _pool_accessor, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        // Get actual amounts from the Balance resources
        let input_a = balance_amount(&balance_a);
        let input_b = balance_amount(&balance_b);
        let (token_a, token_b) = (pool.token_a.clone(), pool.token_b.clone());
        
        // Skip token validation since we can't access resource fields in guest code

        if numbers::cmp_integer(input_a.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
           numbers::cmp_integer(input_b.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            validate_min_output(numbers::u64_to_integer(0), min_lp_out)?;
            let pool_address = ctx.contract_signer().to_string();
            consume_token_balance_to_pool(ctx, balance_a, &pool_address, &token_a)?;
            consume_token_balance_to_pool(ctx, balance_b, &pool_address, &token_b)?;
            // Return zero LP balance
            return Ok(create_lp_balance(numbers::u64_to_integer(0), &token_a, &token_b));
        }

        let pool_address = ctx.contract_signer().to_string();
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let (pool_balance_a, pool_balance_b) = get_pool_token_balances(&pool, &pool_address)?;
        
        let lp_supply = pool.lp_total_supply;
        
        // Calculate LP to issue and actual deposit amounts
        let (lp_to_issue, deposit_a, deposit_b) = if numbers::cmp_integer(lp_supply.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            // First deposit - use sqrt(a * b) for LP tokens
            let lp = numbers::mul_sqrt_integer(input_a, input_b);
            (lp, input_a, input_b)
        } else if numbers::cmp_integer(pool_balance_a.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
                  numbers::cmp_integer(pool_balance_b.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            // Edge case: pool has no liquidity
            return Err(AmmError::NoLiquidity.into());
        } else {
            // Calculate potential LP shares from each input
            let lp_from_a = numbers::mul_div_down_integer(input_a, lp_supply, pool_balance_a);
            let lp_from_b = numbers::mul_div_down_integer(input_b, lp_supply, pool_balance_b);
            
            // The actual LP to issue is the minimum - this ensures proportional deposits
            let lp_to_issue = if numbers::cmp_integer(lp_from_a.clone(), lp_from_b.clone()) == numbers::Ordering::Less { 
                lp_from_a 
            } else { 
                lp_from_b 
            };
            
            // Calculate the exact deposit amounts needed for this LP amount
            let deposit_a = numbers::mul_div_up_integer(lp_to_issue, pool_balance_a, lp_supply);
            let deposit_b = numbers::mul_div_up_integer(lp_to_issue, pool_balance_b, lp_supply);
            
            (lp_to_issue, deposit_a, deposit_b)
        };

        validate_min_output(lp_to_issue, min_lp_out)?;

        // For proportional deposits, we may need to split the balances to get exact amounts
        // If user provided more than needed, we split and refund the excess
        let (balance_a_exact, excess_a) = if numbers::cmp_integer(input_a.clone(), deposit_a.clone()) == numbers::Ordering::Greater {
            let split = token_dyn::split(
                &token_a,
                &ctx.signer().to_string(),
                balance_to_interface(balance_a),
                deposit_a,
            )?;
            (
                balance_from_interface(split.split),
                balance_option_from_interface(split.remainder),
            )
        } else {
            (balance_a, None)
        };
        
        let (balance_b_exact, excess_b) = if numbers::cmp_integer(input_b.clone(), deposit_b.clone()) == numbers::Ordering::Greater {
            let split = token_dyn::split(
                &token_b,
                &ctx.signer().to_string(),
                balance_to_interface(balance_b),
                deposit_b,
            )?;
            (
                balance_from_interface(split.split),
                balance_option_from_interface(split.remainder),
            )
        } else {
            (balance_b, None)
        };

        // Consume the exact amounts needed for the pool
        consume_token_balance_to_pool(ctx, balance_a_exact, &pool_address, &token_a)?;
        consume_token_balance_to_pool(ctx, balance_b_exact, &pool_address, &token_b)?;

        // Return any excess balances to the user
        if let Some(excess) = excess_a {
            let iface = balance_to_interface(excess);
            // TODO: Re-enable when interface! is fixed
            // token_dyn::deposit(&token_a, &ctx.contract_signer().to_string(), user_address.as_str(), iface)?;
        }
        if let Some(excess) = excess_b {
            let iface = balance_to_interface(excess);
            // TODO: Re-enable when interface! is fixed
            // token_dyn::deposit(&token_b, &ctx.contract_signer().to_string(), user_address.as_str(), iface)?;
        }

        // Update total supply - no ledger manipulation needed!
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, lp_to_issue);
        pools.set(ctx, id, pool);

        // EVENT: Deposit { user: user_address, token_a_amount: deposit_a, token_b_amount: deposit_b, lp_minted: lp_to_issue }
        
        // Create LpBalance resource using factory function
        Ok(create_lp_balance(lp_to_issue, &token_a, &token_b))
    }

    fn withdraw(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_balance: LpBalance,
        min_a_out: numbers::Integer,
        min_b_out: numbers::Integer,
    ) -> Result<WithdrawResult, Error> {
        let (id, _pool_accessor, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        // In guest code, resources are opaque handles - we can't access their fields
        // For now, we'll trust that the LP balance matches the pair
        // In a real implementation, the host would validate this
        
        // Get actual LP amount from the resource
        let lp_in = lp_balance_amount(&lp_balance);
        
        // We can't validate the pair since we can't access resource fields
        let lp_pair_id = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?.id().to_string();
        let pair_id = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?.id().to_string();
        if lp_pair_id != pair_id {
            return Err(AmmError::InvalidPair.into());
        }

        if numbers::cmp_integer(lp_in.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            // Create zero-amount token balances for the result
            let balance_a = create_token_balance_from_pool(ctx, &pool.token_a, numbers::u64_to_integer(0))?;
            let balance_b = create_token_balance_from_pool(ctx, &pool.token_b, numbers::u64_to_integer(0))?;
            return Ok(WithdrawResult { balance_a, balance_b });
        }

        let pool_address = ctx.contract_signer().to_string();
        
        // No ledger check needed - the LpBalance resource itself is the proof of ownership!
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;

        let lp_supply = pool.lp_total_supply;

        // Calculate proportional withdrawal amounts (round down to be conservative)
        let a_out = numbers::mul_div_down_integer(lp_in, balance_a, lp_supply);
        let b_out = numbers::mul_div_down_integer(lp_in, balance_b, lp_supply);
        
        validate_min_output(a_out, min_a_out)?;
        validate_min_output(b_out, min_b_out)?;

        // Create token Balance resources from the pool
        let balance_a_out = create_token_balance_from_pool(ctx, &pool.token_a, a_out)?;
        let balance_b_out = create_token_balance_from_pool(ctx, &pool.token_b, b_out)?;

        // Burn LP tokens from total supply - resource consumption handles the rest!
        pool.lp_total_supply = numbers::sub_integer(pool.lp_total_supply, lp_in);
        pools.set(ctx, id, pool);
        
        // EVENT: Withdraw { user: user_address, lp_burned: lp_in, token_a_amount: a_out, token_b_amount: b_out }
        
        // Return Balance resources instead of raw amounts
        Ok(WithdrawResult { 
            balance_a: balance_a_out, 
            balance_b: balance_b_out 
        })
    }

    fn swap(
        ctx: &ProcContext,
        pair: TokenPair,
        balance_in: Balance,
        min_out: numbers::Integer,
    ) -> Result<Balance, Error> {
        let (id, _pool_accessor, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
        
        // Get actual amount and token from the Balance resource
        let amount_in = balance_amount(&balance_in);
        let token_in = balance_token(&balance_in);
            
        if numbers::cmp_integer(amount_in.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            validate_min_output(numbers::u64_to_integer(0), min_out)?;
            // Consume the zero balance and return a zero balance of the output token
            let pool_address = ctx.contract_signer().to_string();
            consume_token_balance_to_pool(ctx, balance_in, &pool_address, &token_in)?;
            
            // Determine output token
            let token_out = if addr_eq(&token_in, &pool.token_a) {
                pool.token_b.clone()
            } else if addr_eq(&token_in, &pool.token_b) {
                pool.token_a.clone()
            } else {
                return Err(AmmError::InvalidTokenIn.into());
            };
            
            return Ok(create_token_balance_from_pool(ctx, &token_out, numbers::u64_to_integer(0))?);
        }
        
        let pool_address = ctx.contract_signer().to_string();
        
        // Validate that token_in matches either token_a or token_b
        let token_a = pool.token_a.clone();
        let token_b = pool.token_b.clone();
        
        let (actual_token_out, pool_balance_in, pool_balance_out) = if addr_eq(&token_in, &token_a) {
            // Swapping A for B
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
            (token_b, balance_a, balance_b)
        } else if addr_eq(&token_in, &token_b) {
            // Swapping B for A
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
            (token_a, balance_b, balance_a)
        } else {
            return Err(AmmError::InvalidTokenIn.into());
        };
        
        // Calculate swap output using the same math as before
        let (out_value, admin_fee_in_lp) = calc_swap_result(
            amount_in,
            pool_balance_in,
            pool_balance_out,
            pool.lp_total_supply,
            pool.lp_fee_bps,
            pool.admin_fee_pct,
        )?;
        
        validate_min_output(out_value, min_out)?;
        
        // Consume the input balance and deposit to pool
        consume_token_balance_to_pool(ctx, balance_in, &pool_address, &token_in)?;
        
        // Create output balance resource from pool
        let balance_out = create_token_balance_from_pool(ctx, &actual_token_out, out_value)?;
        
        // Update admin fees
        pool.admin_fee_lp = numbers::add_integer(pool.admin_fee_lp, admin_fee_in_lp);
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, admin_fee_in_lp);
        pools.set(ctx, id, pool);
        
        // EVENT: Swap { token_in, amount_in, token_out: actual_token_out, amount_out: out_value }
        
        // Return the output Balance resource
        Ok(balance_out)
    }

    fn admin_withdraw_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        amount: numbers::Integer,
    ) -> Result<LpBalance, Error> {
        let (id, _pool_accessor, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        let amount_int = if numbers::cmp_integer(amount.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
            pool.admin_fee_lp
        } else {
            if numbers::cmp_integer(amount.clone(), pool.admin_fee_lp.clone()) == numbers::Ordering::Greater {
                return Err(AmmError::InsufficientAdminFees.into());
            }
            amount
        };
        
        // Simply mint new LP tokens and return them to admin - much cleaner!
        pool.admin_fee_lp = numbers::sub_integer(pool.admin_fee_lp, amount_int);
        // Note: We don't reduce lp_total_supply here as the LP tokens already exist as admin fees
        let _lp_pair = TokenPair {
            token_a: pool.token_a.clone(),
            token_b: pool.token_b.clone(),
        };
        
        // Store token addresses before moving pool
        let token_a = pool.token_a.clone();
        let token_b = pool.token_b.clone();
        
        pools.set(ctx, id, pool);
        
        // EVENT: AdminWithdrawFees { admin: admin_address, amount: amount_int }
        
        // Create LpBalance resource for admin fees
        Ok(create_lp_balance(amount_int, &token_a, &token_b))
    }

    fn admin_set_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<(), Error> {
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        // Validate fee parameters first using Integer comparison
        if numbers::cmp_integer(lp_fee_bps.clone(), bps_in_100_pct()) != numbers::Ordering::Less {
            return Err(AmmError::InvalidFees.into());
        }
        if numbers::cmp_integer(admin_fee_pct.clone(), pct_100()) == numbers::Ordering::Greater {
            return Err(AmmError::InvalidFees.into());
        }
        
        // Store the provided fees directly as Integer
        let lp_fee_bps_val = lp_fee_bps;
        let admin_fee_pct_val = admin_fee_pct;
        
        let (id, _pool_accessor, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        pool.lp_fee_bps = lp_fee_bps_val;
        pool.admin_fee_pct = admin_fee_pct_val;
        pools.set(ctx, id, pool);
        
        // EVENT: FeesUpdated { pool_id: id, lp_fee_bps, admin_fee_pct }
        
        Ok(())
    }
    
    fn lp_total_supply(ctx: &ViewContext, pair: TokenPair) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id)
            .map(|pool| pool.load(ctx).lp_total_supply)
    }
    
    fn admin(ctx: &ViewContext) -> String {
        storage(ctx).admin(ctx)
    }
    
    // Quoter views - preview operations without state changes
    
    fn quote_swap(ctx: &ViewContext, pair: TokenPair, token_in: foreign::ContractAddress, amount_in: numbers::Integer) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = storage(ctx).self_address(ctx);
            
            if numbers::cmp_integer(amount_in.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return Some(numbers::u64_to_integer(0));
            }
            
            // Determine which token is being swapped
            let (balance_in, balance_out) = if addr_eq(&token_in, &pool.token_a) {
                get_pool_token_balances(&pool, &pool_address).ok()?
            } else if addr_eq(&token_in, &pool.token_b) {
                let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
                (balance_b, balance_a)
            } else {
                return None; // Invalid token_in
            };
            
            if numbers::cmp_integer(balance_in.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
               numbers::cmp_integer(balance_out.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return None; // No liquidity
            }
            
            // Calculate swap output
            let (out_value, _) = calc_swap_result(
                amount_in,
                balance_in,
                balance_out,
                pool.lp_total_supply,
                pool.lp_fee_bps,
                pool.admin_fee_pct,
            ).ok()?;
            
            Some(out_value)
        })
    }
    
    fn quote_deposit(ctx: &ViewContext, pair: TokenPair, input_a: numbers::Integer, input_b: numbers::Integer) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = storage(ctx).self_address(ctx);
            
            if numbers::cmp_integer(input_a.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
               numbers::cmp_integer(input_b.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return Some(numbers::u64_to_integer(0));
            }
            
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
            let lp_supply = pool.lp_total_supply;
            
            // Calculate LP tokens that would be issued
            let lp_to_issue = if numbers::cmp_integer(lp_supply.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                // This shouldn't happen after pool creation, but handle it
                numbers::mul_sqrt_integer(input_a, input_b)
            } else if numbers::cmp_integer(balance_a.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal || 
                      numbers::cmp_integer(balance_b.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return None; // No liquidity
            } else {
                // Calculate potential LP shares from each input
                let lp_from_a = numbers::mul_div_down_integer(input_a, lp_supply, balance_a);
                let lp_from_b = numbers::mul_div_down_integer(input_b, lp_supply, balance_b);
                
                // The actual LP to issue is the minimum
                if numbers::cmp_integer(lp_from_a.clone(), lp_from_b.clone()) == numbers::Ordering::Less { 
                    lp_from_a 
                } else { 
                    lp_from_b 
                }
            };
            
            Some(lp_to_issue)
        })
    }
    
    fn quote_withdraw(ctx: &ViewContext, pair: TokenPair, lp_in: numbers::Integer) -> Option<QuoteWithdrawResult> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = storage(ctx).self_address(ctx);
            
            if numbers::cmp_integer(lp_in.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return Some(QuoteWithdrawResult { a_out: numbers::u64_to_integer(0), b_out: numbers::u64_to_integer(0) });
            }
            
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
            let lp_supply = pool.lp_total_supply;
            
            if numbers::cmp_integer(lp_supply.clone(), numbers::u64_to_integer(0)) == numbers::Ordering::Equal {
                return None; // No LP supply
            }
            
            // Calculate proportional withdrawal amounts
            let a_out = numbers::mul_div_down_integer(lp_in, balance_a, lp_supply);
            let b_out = numbers::mul_div_down_integer(lp_in, balance_b, lp_supply);
            
            Some(QuoteWithdrawResult { a_out, b_out })
        })
    }

    // Constants view
    fn min_liquidity(_ctx: &ViewContext) -> numbers::Integer {
        min_liquidity()
    }
}
