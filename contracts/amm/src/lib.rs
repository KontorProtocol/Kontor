use stdlib::*;
use std::cell::RefCell;

contract!(name = "amm");

interface!(name = "token_dyn", path = "token/wit");

// Thread-local storage for LP balance resources
// Similar to the token contract's balance table
thread_local! {
    static LP_BALANCE_TABLE: RefCell<Vec<Option<LpBalanceData>>> = RefCell::new(Vec::new());
}

// Data backing an LP Balance resource
#[derive(Clone)]
struct LpBalanceData {
    pair: TokenPair,
    amount: numbers::Integer,
    handle: String,  // Unique ID for linearity tracking
}

// Helper to allocate an LP Balance resource handle
fn allocate_lp_balance_resource(data: LpBalanceData) -> u32 {
    LP_BALANCE_TABLE.with(|table| {
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

// Helper to consume an LP Balance resource and get its data
fn take_lp_balance_data(index: u32) -> Result<LpBalanceData, error::Error> {
    LP_BALANCE_TABLE.with(|table| {
        let mut table = table.borrow_mut();
        let idx = index as usize;
        
        if idx >= table.len() {
            return Err(error::Error::Message("Invalid LP balance resource".to_string()));
        }
        
        table[idx].take()
            .ok_or_else(|| error::Error::Message("LP balance already consumed or invalid".to_string()))
    })
}

// Helper to get LP Balance data without consuming it
fn get_lp_balance_data(index: u32) -> Result<LpBalanceData, error::Error> {
    LP_BALANCE_TABLE.with(|table| {
        let table = table.borrow();
        let idx = index as usize;
        
        if idx >= table.len() {
            return Err(error::Error::Message("Invalid LP balance resource".to_string()));
        }
        
        table[idx].clone()
            .ok_or_else(|| error::Error::Message("LP balance not found".to_string()))
    })
}

// # AMM Contract
// 
// This Automated Market Maker (AMM) contract implements a constant product formula
// similar to Uniswap V2 with admin fees.

// Typed canonical pair wrapper that sorts by tuple comparison
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTokenPair {
    token_a: foreign::ContractAddress,
    token_b: foreign::ContractAddress,
    id: String,
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

impl From<AmmError> for error::Error {
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
        error::Error::Message(message.to_string())
    }
}

#[derive(Clone, Storage)]
struct Pool {
    pub token_a: foreign::ContractAddress,
    pub token_b: foreign::ContractAddress,
    pub lp_fee_bps: numbers::Integer,
    pub admin_fee_pct: numbers::Integer,
    pub admin_fee_lp: numbers::Integer,
    pub lp_total_supply: numbers::Integer,
    pub lp_ledger: Map<String, numbers::Integer>, // owner -> lp balance
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
            lp_fee_bps: 0.into(),
            admin_fee_pct: 0.into(),
            admin_fee_lp: 0.into(),
            lp_total_supply: 0.into(),
            lp_ledger: Map::default(),
        }
    }
}

#[derive(Clone, Default, StorageRoot)]
struct AmmStorage {
    pub pools: Map<String, Pool>,
    pub admin: String,  // Admin address (signer-based auth)
    pub self_address: String,
}

fn get_token_balance(_signer: Option<context::Signer>, token: &foreign::ContractAddress, account: &str) -> Result<numbers::Integer, error::Error> {
    Ok(token_dyn::balance_or_zero(token, account))
}

// Helper function to consume a token Balance and deposit it to the pool
fn consume_token_balance_to_pool(
    ctx: &ProcContext,
    balance: TokenBalance,
    pool_address: &str,
) -> Result<numbers::Integer, error::Error> {
    // Get the amount from the balance before consuming it
    let amount = balance.amount;
    
    // Deposit the balance into the pool's account using the token contract
    token_dyn::deposit(&balance.token_addr, ctx.contract_signer(), pool_address.to_string(), balance)?;
    
    Ok(amount)
}

// Helper function to create and return a token Balance from the pool
fn create_token_balance_from_pool(
    ctx: &ProcContext,
    token: &foreign::ContractAddress,
    amount: numbers::Integer,
    recipient: &str,
) -> Result<TokenBalance, error::Error> {
    // Withdraw from the pool (using contract signer) and return the Balance
    token_dyn::withdraw(token, ctx.contract_signer(), amount)
}

// Helper function to create an LP Balance resource
fn create_lp_balance(
    ctx: &ProcContext,
    pair: TokenPair,
    amount: numbers::Integer,
) -> LpBalance {
    // Get next ID from storage and create handle
    let pools = storage(ctx).pools();
    let canonical_pair = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone()).unwrap();
    let id = canonical_pair.id();
    
    // Create a unique handle for this LP balance
    let handle = format!("lp_{}_{}", id, amount.r0); // Simple handle for now
    
    let data = LpBalanceData {
        pair,
        amount,
        handle,
    };
    
    let index = allocate_lp_balance_resource(data);
    unsafe { LpBalance::from_handle(index) }
}

// Helper function to consume an LP Balance resource
fn consume_lp_balance(
    ctx: &ProcContext,
    lp_balance: LpBalance,
) -> Result<(TokenPair, numbers::Integer), error::Error> {
    let index = lp_balance.take_handle();
    let data = take_lp_balance_data(index)?;
    Ok((data.pair, data.amount))
}

// Helper function to load a pool using canonical pair or return error
fn load_pool(ctx: &impl ReadContext, pair: &TokenPair) -> Result<(String, PoolWrapper, Pool), AmmError> {
    let canonical_pair = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?;
    let id = canonical_pair.id().to_string();
    let pools = storage(ctx).pools();
    let pool_wrapper = pools.get(ctx, &id)
        .ok_or(AmmError::PoolNotFound)?;
    let pool = pool_wrapper.load(ctx);
    Ok((id, pool_wrapper, pool))
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
) -> Result<(numbers::Integer, numbers::Integer), error::Error> {
    let balance_a = get_token_balance(None, &pool.token_a, pool_address)?;
    let balance_b = get_token_balance(None, &pool.token_b, pool_address)?;
    Ok((balance_a, balance_b))
}

// Helper function to update LP ledger balance
fn update_lp_balance(
    ctx: &ProcContext,
    pool_wrapper: &PoolWrapper,
    user_address: &str,
    amount_change: numbers::Integer,
    is_addition: bool,
) {
    let current_lp = pool_wrapper.lp_ledger().get(ctx, user_address)
        .unwrap_or_else(|| 0.into());
    let new_balance = if is_addition {
        numbers::add_integer(current_lp, amount_change)
    } else {
        numbers::sub_integer(current_lp, amount_change)
    };
    pool_wrapper.lp_ledger().set(ctx, user_address.to_string(), new_balance);
}

// Helper function to check admin authorization
fn ensure_admin_auth(ctx: &ProcContext) -> Result<(), AmmError> {
    if ctx.signer().to_string() != storage(ctx).admin(ctx) {
        return Err(AmmError::NotAdmin);
    }
    Ok(())
}

// Helper function for slippage validation
fn validate_min_output(actual: numbers::Integer, minimum: numbers::Integer) -> Result<(), AmmError> {
    if actual < minimum {
        return Err(AmmError::ExcessiveSlippage);
    }
    Ok(())
}

// Helper function for common swap logic
fn execute_swap(
    ctx: &ProcContext,
    pool: &mut Pool,
    token_in: &foreign::ContractAddress,
    token_out: &foreign::ContractAddress,
    amount_in: numbers::Integer,
    balance_in: numbers::Integer,
    balance_out: numbers::Integer,
    min_out: numbers::Integer,
) -> Result<numbers::Integer, AmmError> {
            let pool_address = ctx.contract_signer().to_string();
    let user_address = ctx.signer().to_string();
    
    if balance_in == 0.into() || balance_out == 0.into() {
        return Err(AmmError::NoLiquidity);
    }

    let (out_value, admin_fee_in_lp) = calc_swap_result(
        amount_in,
        balance_in,
        balance_out,
        pool.lp_total_supply,
        pool.lp_fee_bps,
        pool.admin_fee_pct,
    ).map_err(|_| AmmError::NoLiquidity)?;
    
    validate_min_output(out_value, min_out)?;
    
    // Transfer token in from user to pool using asset-based transfer
    transfer_token_from_user_to_pool(ctx, token_in, amount_in, &pool_address)
        .map_err(|_| AmmError::NoLiquidity)?;
    
    // Transfer token out from pool to user
    token_dyn::transfer(token_out, ctx.contract_signer(), &user_address, out_value)
        .map_err(|_| AmmError::NoLiquidity)?;
    
    // Update admin fees using dedicated function
    mint_admin_fee_lp(pool, admin_fee_in_lp);
    
    Ok(out_value)
}

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
) -> Result<(numbers::Integer, numbers::Integer), error::Error> {
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
    let admin_fee_in_lp = if pool_lp_value == 0.into() {
        0.into()
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
        balance_a: TokenBalance,
        balance_b: TokenBalance,
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<LpBalance, error::Error> {
        // Create canonical pair and validate
        let canonical_pair = CanonicalTokenPair::new(pair.token_a.clone(), pair.token_b.clone())?;
        
        // Get amounts from the balance records
        let init_a = balance_a.amount;
        let init_b = balance_b.amount;
        
        if init_a == 0.into() || init_b == 0.into() {
            return Err(AmmError::InputBalanceZero.into());
        }
        
        // Validate that the balance records match the pair tokens
        let (token_a, token_b) = canonical_pair.as_tuple();
        if balance_a.token_addr != token_a || balance_b.token_addr != token_b {
            return Err(AmmError::InvalidPair.into());
        }
        
        // Validate fee parameters
        if lp_fee_bps >= bps_in_100_pct() || admin_fee_pct > pct_100() {
            return Err(AmmError::InvalidFees.into());
        }

        let id = canonical_pair.id().to_string();
        let pools = storage(ctx).pools();
        
        // Check if pool already exists
        if pools.get(ctx, &id).is_some() {
            return Err(AmmError::PoolAlreadyExists.into());
        }

        let pool_address = ctx.contract_signer().to_string();
        let user_address = ctx.signer().to_string();
        
        // Consume the Balance resources and deposit them to the pool
        // This is much cleaner than the old approve/transfer pattern!
        consume_token_balance_to_pool(ctx, balance_a, &pool_address)?;
        consume_token_balance_to_pool(ctx, balance_b, &pool_address)?;

        // Calculate initial LP tokens: sqrt(init_a * init_b)
        let total_lp = numbers::mul_sqrt_integer(init_a, init_b);
        
        // Lock MINIMUM_LIQUIDITY permanently on first pool creation
        let min_liq = minimum_liquidity();
        if total_lp <= min_liq {
            return Err(AmmError::InitialLiquidityTooSmall.into());
        }
        let lp_to_issue = numbers::sub_integer(total_lp, min_liq);
        
        // Create pool with LP ledger
        let mut lp_ledger = Map::default();
        lp_ledger.entries.push((user_address, lp_to_issue));
        
        pools.set(
            ctx,
            id,
            Pool {
                token_a,
                token_b,
                lp_fee_bps,
                admin_fee_pct,
                admin_fee_lp: 0.into(),
                lp_total_supply: total_lp,
                lp_ledger,
            },
        );

        // EVENT: PoolCreated { pool_id: id, initial_lp: lp_to_issue }
        
        // Return an LP Balance resource instead of a raw integer
        Ok(create_lp_balance(ctx, pair, lp_to_issue))
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
        balance_a: TokenBalance,
        balance_b: TokenBalance,
        min_lp_out: numbers::Integer,
    ) -> Result<LpBalance, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        // Get amounts from balance records
        let input_a = balance_a.amount;
        let input_b = balance_b.amount;

        if input_a == 0.into() || input_b == 0.into() {
            validate_min_output(0.into(), min_lp_out)?;
            // Need to consume the zero balances to maintain linearity
            let pool_address = ctx.contract_signer().to_string();
            consume_token_balance_to_pool(ctx, balance_a, &pool_address)?;
            consume_token_balance_to_pool(ctx, balance_b, &pool_address)?;
            return Ok(create_lp_balance(ctx, pair, 0.into()));
        }

        // Validate that balance records match the pair tokens
        let (token_a, token_b) = (pool.token_a.clone(), pool.token_b.clone());
        if balance_a.token_addr != token_a || balance_b.token_addr != token_b {
            return Err(AmmError::InvalidPair.into());
        }

        let pool_address = ctx.contract_signer().to_string();
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let (pool_balance_a, pool_balance_b) = get_pool_token_balances(&pool, &pool_address)?;
        
        let lp_supply = pool.lp_total_supply;
        
        // Calculate LP to issue and actual deposit amounts
        let (lp_to_issue, deposit_a, deposit_b) = if lp_supply == 0.into() {
            // First deposit - use sqrt(a * b) for LP tokens
            let lp = numbers::mul_sqrt_integer(input_a, input_b);
            (lp, input_a, input_b)
        } else if pool_balance_a == 0.into() || pool_balance_b == 0.into() {
            // Edge case: pool has no liquidity
            return Err(AmmError::NoLiquidity.into());
        } else {
            // Calculate potential LP shares from each input
            let lp_from_a = numbers::mul_div_down_integer(input_a, lp_supply, pool_balance_a);
            let lp_from_b = numbers::mul_div_down_integer(input_b, lp_supply, pool_balance_b);
            
            // The actual LP to issue is the minimum - this ensures proportional deposits
            let lp_to_issue = if lp_from_a < lp_from_b { lp_from_a } else { lp_from_b };
            
            // Calculate the exact deposit amounts needed for this LP amount
            let deposit_a = numbers::mul_div_up_integer(lp_to_issue, pool_balance_a, lp_supply);
            let deposit_b = numbers::mul_div_up_integer(lp_to_issue, pool_balance_b, lp_supply);
            
            (lp_to_issue, deposit_a, deposit_b)
        };

        validate_min_output(lp_to_issue, min_lp_out)?;

        // For proportional deposits, we may need to split the balances to get exact amounts
        // If user provided more than needed, we split and refund the excess
        let (balance_a_exact, excess_a) = if input_a > deposit_a {
            let (exact, excess_opt) = token_dyn::split(&balance_a.token(), ctx.signer(), balance_a, deposit_a)?;
            (exact, excess_opt)
        } else {
            (balance_a, None)
        };
        
        let (balance_b_exact, excess_b) = if input_b > deposit_b {
            let (exact, excess_opt) = token_dyn::split(&balance_b.token(), ctx.signer(), balance_b, deposit_b)?;
            (exact, excess_opt)
        } else {
            (balance_b, None)
        };

        // Consume the exact amounts needed for the pool
        consume_token_balance_to_pool(ctx, balance_a_exact, &pool_address)?;
        consume_token_balance_to_pool(ctx, balance_b_exact, &pool_address)?;

        // Return any excess balances to the user
        if let Some(excess) = excess_a {
            token_dyn::deposit(&token_a, ctx.contract_signer(), &user_address, excess)?;
        }
        if let Some(excess) = excess_b {
            token_dyn::deposit(&token_b, ctx.contract_signer(), &user_address, excess)?;
        }

        // Update LP tokens (use wrapper for map mutations)
        update_lp_balance(ctx, &pool_wrapper, &user_address, lp_to_issue, true);
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, lp_to_issue);
        pools.set(ctx, id, pool);

        // EVENT: Deposit { user: user_address, token_a_amount: deposit_a, token_b_amount: deposit_b, lp_minted: lp_to_issue }
        
        // Return an LP Balance resource
        Ok(create_lp_balance(ctx, pair, lp_to_issue))
    }

    fn withdraw(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_balance: LpBalance,
        min_a_out: numbers::Integer,
        min_b_out: numbers::Integer,
    ) -> Result<WithdrawResult, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        // Consume the LP Balance resource to get the amount
        let (lp_pair, lp_in) = consume_lp_balance(ctx, lp_balance)?;
        
        // Validate that the LP balance is for the correct pair
        if lp_pair != pair {
            return Err(AmmError::InvalidPair.into());
        }

        if lp_in == 0.into() {
            // Create zero-amount token balances for the result
            let balance_a = create_token_balance_from_pool(ctx, &pool.token_a, 0.into(), "")?;
            let balance_b = create_token_balance_from_pool(ctx, &pool.token_b, 0.into(), "")?;
            return Ok(WithdrawResult { balance_a, balance_b });
        }

        let user_address = ctx.signer().to_string();
        let pool_address = ctx.contract_signer().to_string();
        
        // Check LP balance in ledger (defensive check - should match the resource)
        let user_lp = pool_wrapper.lp_ledger().get(ctx, &user_address)
            .unwrap_or_else(|| 0.into());
        if user_lp < lp_in {
            return Err(AmmError::InsufficientLpTokens.into());
        }
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;

        let lp_supply = pool.lp_total_supply;

        // Calculate proportional withdrawal amounts (round down to be conservative)
        let a_out = numbers::mul_div_down_integer(lp_in, balance_a, lp_supply);
        let b_out = numbers::mul_div_down_integer(lp_in, balance_b, lp_supply);
        
        validate_min_output(a_out, min_a_out)?;
        validate_min_output(b_out, min_b_out)?;

        // Create token Balance resources from the pool
        let balance_a_out = create_token_balance_from_pool(ctx, &pool.token_a, a_out, &user_address)?;
        let balance_b_out = create_token_balance_from_pool(ctx, &pool.token_b, b_out, &user_address)?;

        // Burn LP tokens from ledger
        update_lp_balance(ctx, &pool_wrapper, &user_address, lp_in, false);
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
        balance_in: TokenBalance,
        min_out: numbers::Integer,
    ) -> Result<TokenBalance, error::Error> {
        let (id, _pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
        
        // Get amount and token from the balance record
        let amount_in = balance_in.amount;
        let token_in = balance_in.token_addr;
            
        if amount_in == 0.into() {
            validate_min_output(0.into(), min_out)?;
            // Consume the zero balance and return a zero balance of the output token
            let pool_address = ctx.contract_signer().to_string();
            consume_token_balance_to_pool(ctx, balance_in, &pool_address)?;
            
            // Determine output token
            let token_out = if token_in == pool.token_a {
                pool.token_b.clone()
            } else if token_in == pool.token_b {
                pool.token_a.clone()
            } else {
                return Err(AmmError::InvalidTokenIn.into());
            };
            
            return Ok(create_token_balance_from_pool(ctx, &token_out, 0.into(), "")?);
        }
        
        let pool_address = ctx.contract_signer().to_string();
        
        // Validate that token_in matches either token_a or token_b
        let token_a = pool.token_a.clone();
        let token_b = pool.token_b.clone();
        
        let (actual_token_out, pool_balance_in, pool_balance_out) = if token_in == token_a {
            // Swapping A for B
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
            (token_b, balance_a, balance_b)
        } else if token_in == token_b {
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
        consume_token_balance_to_pool(ctx, balance_in, &pool_address)?;
        
        // Create output balance resource from pool
        let balance_out = create_token_balance_from_pool(ctx, &actual_token_out, out_value, "")?;
        
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
    ) -> Result<LpBalance, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        let amount_int = if amount == 0.into() {
            pool.admin_fee_lp
        } else {
            if amount > pool.admin_fee_lp {
                return Err(AmmError::InsufficientAdminFees.into());
            }
            amount
        };
        
        // Credit admin with LP tokens
        let admin_address = ctx.signer().to_string();
        update_lp_balance(ctx, &pool_wrapper, &admin_address, amount_int, true);
        
        pool.admin_fee_lp = numbers::sub_integer(pool.admin_fee_lp, amount_int);
        // Note: We don't reduce lp_total_supply here as the LP tokens already exist, just moving ownership
        pools.set(ctx, id, pool);
        
        // EVENT: AdminWithdrawFees { admin: admin_address, amount: amount_int }
        
        // Return LP Balance resource instead of raw amount
        Ok(create_lp_balance(ctx, pair, amount_int))
    }

    fn admin_set_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<(), error::Error> {
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        // Validate fee parameters first using Integer comparison
        if lp_fee_bps >= bps_in_100_pct() {
            return Err(AmmError::InvalidFees.into());
        }
        if admin_fee_pct > pct_100() {
            return Err(AmmError::InvalidFees.into());
        }
        
        // Store the provided fees directly as Integer
        let lp_fee_bps_val = lp_fee_bps;
        let admin_fee_pct_val = admin_fee_pct;
        
        let (id, _pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        pool.lp_fee_bps = lp_fee_bps_val;
        pool.admin_fee_pct = admin_fee_pct_val;
        pools.set(ctx, id, pool);
        
        // EVENT: FeesUpdated { pool_id: id, lp_fee_bps, admin_fee_pct }
        
        Ok(())
    }
    
    // LP Token management functions
    fn lp_balance(ctx: &ViewContext, pair: TokenPair, owner: String) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id)
            .and_then(|pool| pool.lp_ledger().get(ctx, owner))
    }
    
    fn lp_total_supply(ctx: &ViewContext, pair: TokenPair) -> Option<numbers::Integer> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id)
            .map(|pool| pool.lp_total_supply(ctx))
    }
    
    // LP Token operations using Balance resources
    fn withdraw_lp(
        ctx: &ProcContext,
        pair: TokenPair,
        amount: numbers::Integer,
    ) -> Result<LpBalance, error::Error> {
        let (id, pool_wrapper, pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
        
        let user_address = ctx.signer().to_string();
        let user_lp = pool_wrapper.lp_ledger().get(ctx, &user_address)
            .unwrap_or_else(|| 0.into());
        
        if user_lp < amount {
            return Err(AmmError::InsufficientLpTokens.into());
        }
        
        // Debit user's LP balance
        update_lp_balance(ctx, &pool_wrapper, &user_address, amount, false);
        pools.set(ctx, id, pool);
        
        // Return LP Balance resource
        Ok(create_lp_balance(ctx, pair, amount))
    }
    
    fn deposit_lp(
        ctx: &ProcContext,
        pair: TokenPair,
        recipient: String,
        lp_balance: LpBalance,
    ) -> Result<(), error::Error> {
        let (id, pool_wrapper, pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
        
        // Consume the LP Balance resource
        let (lp_pair, amount) = consume_lp_balance(ctx, lp_balance)?;
        
        // Validate pair matches
        if lp_pair != pair {
            return Err(AmmError::InvalidPair.into());
        }
        
        // Credit recipient's LP balance
        update_lp_balance(ctx, &pool_wrapper, &recipient, amount, true);
        pools.set(ctx, id, pool);
        
        Ok(())
    }
    
    fn transfer_lp(
        ctx: &ProcContext,
        pair: TokenPair,
        to: String,
        lp_balance: LpBalance,
    ) -> Result<(), error::Error> {
        // Transfer is just deposit with resources!
        // The resource system ensures the LP tokens move atomically
        Self::deposit_lp(ctx, pair, to, lp_balance)
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
            
            if amount_in == 0.into() {
                return Some(0.into());
            }
            
            // Determine which token is being swapped
            let (balance_in, balance_out) = if token_in == pool.token_a {
                get_pool_token_balances(&pool, &pool_address).ok()?
            } else if token_in == pool.token_b {
                let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
                (balance_b, balance_a)
            } else {
                return None; // Invalid token_in
            };
            
            if balance_in == 0.into() || balance_out == 0.into() {
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
            
            if input_a == 0.into() || input_b == 0.into() {
                return Some(0.into());
            }
            
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
            let lp_supply = pool.lp_total_supply;
            
            // Calculate LP tokens that would be issued
            let lp_to_issue = if lp_supply == 0.into() {
                // This shouldn't happen after pool creation, but handle it
                numbers::mul_sqrt_integer(input_a, input_b)
            } else if balance_a == 0.into() || balance_b == 0.into() {
                return None; // No liquidity
            } else {
                // Calculate potential LP shares from each input
                let lp_from_a = numbers::mul_div_down_integer(input_a, lp_supply, balance_a);
                let lp_from_b = numbers::mul_div_down_integer(input_b, lp_supply, balance_b);
                
                // The actual LP to issue is the minimum
                if lp_from_a < lp_from_b { lp_from_a } else { lp_from_b }
            };
            
            Some(lp_to_issue)
        })
    }
    
    fn quote_withdraw(ctx: &ViewContext, pair: TokenPair, lp_in: numbers::Integer) -> Option<WithdrawResult> {
        let canonical_pair = CanonicalTokenPair::new(pair.token_a, pair.token_b).ok()?;
        let id = canonical_pair.id();
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = "amm_contract_address";
            
            if lp_in == 0.into() {
                return Some(WithdrawResult { a_out: 0.into(), b_out: 0.into() });
            }
            
            let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address).ok()?;
            let lp_supply = pool.lp_total_supply;
            
            if lp_supply == 0.into() {
                return None; // No LP supply
            }
            
            // Calculate proportional withdrawal amounts
            let a_out = numbers::mul_div_down_integer(lp_in, balance_a, lp_supply);
            let b_out = numbers::mul_div_down_integer(lp_in, balance_b, lp_supply);
            
            Some(WithdrawResult { a_out, b_out })
        })
    }

    // Constants view
    fn min_liquidity(_ctx: &ViewContext) -> numbers::Integer {
        min_liquidity()
    }
}