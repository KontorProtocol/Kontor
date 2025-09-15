use stdlib::*;

contract!(name = "amm");

interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, Storage)]
struct Pool {
    pub token_a: foreign::ContractAddress,
    pub token_b: foreign::ContractAddress,
    pub lp_fee_rate: numbers::Decimal,    // Fee rate as decimal (e.g., 0.003 for 0.3%)
    pub admin_fee_rate: numbers::Decimal,  // Admin's share of fees (e.g., 0.5 for 50% of LP fees)
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
            lp_fee_rate: 0.into(),
            admin_fee_rate: 0.into(),
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
    pub pool_custody_address: String,  // The AMM's address for holding tokens
}

fn ensure_pair_sorted(pair: &TokenPair) -> Result<(), error::Error> {
    // Validate that both tokens are properly specified
    if pair.token_a.name.is_empty() || pair.token_b.name.is_empty() {
        return Err(error::Error::Message("Token addresses must not be empty".to_string()));
    }
    
    // Create canonical string representations for comparison
    let a_str = format!("{}_{}_{}",  pair.token_a.name, pair.token_a.height, pair.token_a.tx_index);
    let b_str = format!("{}_{}_{}",  pair.token_b.name, pair.token_b.height, pair.token_b.tx_index);
    
    // Ensure tokens are different
    if a_str == b_str {
        return Err(error::Error::Message(
            "Pool pair coin types must not be equal".to_string(),
        ));
    }
    
    // Ensure tokens are properly ordered (A < B)
    if a_str > b_str {
        return Err(error::Error::Message(
            "Pool pair must be ordered A < B".to_string(),
        ));
    }
    
    Ok(())
}

fn pair_id(pair: &TokenPair) -> String {
    let a_str = format!("{}_{}_{}",  pair.token_a.name, pair.token_a.height, pair.token_a.tx_index);
    let b_str = format!("{}_{}_{}",  pair.token_b.name, pair.token_b.height, pair.token_b.tx_index);
    format!("{}::{}", a_str, b_str)
}

fn get_pool_custody_address(ctx: &impl ReadContext) -> String {
    // Get the stored custody address (computed once during init)
    storage(ctx).pool_custody_address(ctx)
}

fn get_token_balance(_signer: Option<context::Signer>, token: &foreign::ContractAddress, account: &str) -> Result<numbers::Integer, error::Error> {
    Ok(token_dyn::balance_or_zero(token, account))
}

// Helper function for common token transfer pattern (approve + transfer_from)
fn transfer_token_from_user_to_pool(
    ctx: &ProcContext,
    token: &foreign::ContractAddress,
    amount: numbers::Integer,
    pool_address: &str,
) -> Result<(), error::Error> {
    let user_address = ctx.signer().to_string();
    let spender = ctx.contract_signer().to_string();
    token_dyn::approve(token, ctx.signer(), &spender, amount)?;
    token_dyn::transfer_from(token, ctx.contract_signer(), &user_address, pool_address, amount)
}

// Helper function to load a pool or return error
fn load_pool(ctx: &impl ReadContext, pair: &TokenPair) -> Result<(String, PoolWrapper, Pool), error::Error> {
    let id = pair_id(pair);
    let pools = storage(ctx).pools();
    let pool_wrapper = pools.get(ctx, &id)
        .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
    let pool = pool_wrapper.load(ctx);
    Ok((id, pool_wrapper, pool))
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
    let current_lp = pool_wrapper.lp_ledger().get(ctx, user_address).unwrap_or_default();
    let new_balance = if is_addition {
        numbers::add_integer(current_lp, amount_change)
    } else {
        numbers::sub_integer(current_lp, amount_change)
    };
    pool_wrapper.lp_ledger().set(ctx, user_address.to_string(), new_balance);
}

// Helper function to check admin authorization
fn ensure_admin_auth(ctx: &ProcContext) -> Result<(), error::Error> {
    if ctx.signer().to_string() != storage(ctx).admin(ctx) {
        return Err(error::Error::Message("Not authorized: admin only".to_string()));
    }
    Ok(())
}

// Helper function for slippage validation
fn validate_min_output(actual: numbers::Integer, minimum: numbers::Integer) -> Result<(), error::Error> {
    if actual < minimum {
        return Err(error::Error::Message("Excessive slippage".to_string()));
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
) -> Result<numbers::Integer, error::Error> {
    let pool_address = get_pool_custody_address(ctx);
    let user_address = ctx.signer().to_string();
    
    if balance_in == 0.into() || balance_out == 0.into() {
        return Err(error::Error::Message("Pool has no liquidity".to_string()));
    }

    let (out_value, admin_fee_in_lp) = calc_swap_result(
        amount_in,
        balance_in,
        balance_out,
        pool.lp_total_supply,
        pool.lp_fee_rate,
        pool.admin_fee_rate,
    )?;
    
    validate_min_output(out_value, min_out)?;
    
    // Transfer token in from user to pool
    transfer_token_from_user_to_pool(ctx, token_in, amount_in, &pool_address)?;
    
    // Transfer token out from pool to user
    token_dyn::transfer(token_out, ctx.contract_signer(), &user_address, out_value)?;
    
    // Update admin fees
    pool.admin_fee_lp = numbers::add_integer(pool.admin_fee_lp, admin_fee_in_lp);
    pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, admin_fee_in_lp);
    
    Ok(out_value)
}

fn calc_swap_result(
    i_value: numbers::Integer,
    i_pool_value: numbers::Integer,
    o_pool_value: numbers::Integer,
    pool_lp_value: numbers::Integer,
    lp_fee_rate: numbers::Decimal,
    admin_fee_rate: numbers::Decimal,
) -> Result<(numbers::Integer, numbers::Integer), error::Error> {
    // Convert to decimals
    let i_value_dec: numbers::Decimal = i_value.into();
    let i_pool_dec: numbers::Decimal = i_pool_value.into();
    let o_pool_dec: numbers::Decimal = o_pool_value.into();
    let pool_lp_dec: numbers::Decimal = pool_lp_value.into();
    
    // Calculate LP fee and amount after fee using normal operators
    let lp_fee_value_dec = i_value_dec * lp_fee_rate;
    let in_after_lp_fee_dec = i_value_dec - lp_fee_value_dec;
    
    // Calculate output amount using constant product formula
    // out = (in_after_fee * out_pool) / (in_pool + in_after_fee)
    let out_value_dec = (in_after_lp_fee_dec * o_pool_dec) / (i_pool_dec + in_after_lp_fee_dec);
    
    // Calculate admin fee (as a portion of the LP fee)
    let admin_fee_value_dec = lp_fee_value_dec * admin_fee_rate;
    
    // Convert admin fee to LP tokens proportionally
    let admin_fee_in_lp_dec = if pool_lp_value == 0.into() {
        0.into()
    } else {
        // admin_fee_value * pool_lp / i_pool_value
        (admin_fee_value_dec * pool_lp_dec) / i_pool_dec
    };
    
    // Convert back to integers with explicit rounding down (truncation)
    let out_value = numbers::decimal_to_integer_floor(out_value_dec);
    let admin_fee_in_lp = numbers::decimal_to_integer_floor(admin_fee_in_lp_dec);
    
    Ok((out_value, admin_fee_in_lp))
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        let admin = ctx.signer().to_string();
        let pool_custody_address = ctx.contract_signer().to_string();
        
        AmmStorage {
            pools: Map::default(),
            admin,
            pool_custody_address,
        }
        .init(ctx)
    }

    fn create(
        ctx: &ProcContext,
        pair: TokenPair,
        init_a: numbers::Integer,
        init_b: numbers::Integer,
        lp_fee_rate: numbers::Decimal,
        admin_fee_rate: numbers::Decimal,
    ) -> Result<numbers::Integer, error::Error> {
        ensure_pair_sorted(&pair)?;
        
        if init_a == 0.into() || init_b == 0.into() {
            return Err(error::Error::Message("Input balances cannot be zero".to_string()));
        }
        
        // Validate fees (lp_fee should be < 100%, admin_fee should be <= 100%)
        if lp_fee_rate >= 1.into() {
            return Err(error::Error::Message("Invalid lp fee rate".to_string()));
        }
        if admin_fee_rate > 1.into() {
            return Err(error::Error::Message("Invalid admin fee rate".to_string()));
        }
        if lp_fee_rate < 0.into() || admin_fee_rate < 0.into() {
            return Err(error::Error::Message("Fee rates cannot be negative".to_string()));
        }

        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        
        // Check if pool already exists
        if pools.get(ctx, &id).is_some() {
            return Err(error::Error::Message("Pool already exists".to_string()));
        }
        
        // Also check for reversed pair (should never happen with proper sorting, but be defensive)
        let reversed_id = format!("{}_{}_{}::{}_{}_{}",
            pair.token_b.name, pair.token_b.height, pair.token_b.tx_index,
            pair.token_a.name, pair.token_a.height, pair.token_a.tx_index
        );
        if pools.get(ctx, &reversed_id).is_some() {
            return Err(error::Error::Message("Pool already exists (reversed pair found)".to_string()));
        }

        let pool_address = get_pool_custody_address(ctx);
        let user_address = ctx.signer().to_string();
        
        // Transfer initial liquidity from user to pool
        transfer_token_from_user_to_pool(ctx, &pair.token_a, init_a, &pool_address)?;
        transfer_token_from_user_to_pool(ctx, &pair.token_b, init_b, &pool_address)?;

        // Calculate initial LP tokens: sqrt(init_a * init_b) using clean Decimal math
        let init_a_dec: numbers::Decimal = init_a.into();
        let init_b_dec: numbers::Decimal = init_b.into();
        let product_dec = init_a_dec * init_b_dec;
        let product_int = numbers::decimal_to_integer_floor(product_dec);
        let lp_to_issue = numbers::sqrt_integer(product_int);
        
        // Create pool with LP ledger
        let mut lp_ledger = Map::default();
        lp_ledger.entries.push((user_address, lp_to_issue));
        
        pools.set(
            ctx,
            id,
            Pool {
                token_a: pair.token_a,
                token_b: pair.token_b,
                lp_fee_rate,
                admin_fee_rate,
                admin_fee_lp: 0.into(),
                lp_total_supply: lp_to_issue,
                lp_ledger,
            },
        );

        // EVENT: PoolCreated { pool_id: id, token_a: pair.token_a, token_b: pair.token_b, initial_lp: lp_to_issue }
        
        Ok(lp_to_issue)
    }

    fn values(ctx: &ViewContext, pair: TokenPair) -> Option<PoolValues> {
        let id = pair_id(&pair);
        storage(ctx).pools().get(ctx, id).and_then(|p| {
            let pool = p.load(ctx);
            let pool_address = get_pool_custody_address(ctx);
            
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
        let id = pair_id(&pair);
        storage(ctx).pools().get(ctx, id).map(|p| {
            let pool = p.load(ctx);
            FeeInfo {
                lp_fee_rate: pool.lp_fee_rate,
                admin_fee_rate: pool.admin_fee_rate,
            }
        })
    }

    fn admin_fee_value(ctx: &ViewContext, pair: TokenPair) -> Option<numbers::Integer> {
        let id = pair_id(&pair);
        storage(ctx).pools().get(ctx, id).map(|p| p.load(ctx).admin_fee_lp)
    }

    fn deposit(
        ctx: &ProcContext,
        pair: TokenPair,
        input_a: numbers::Integer,
        input_b: numbers::Integer,
        min_lp_out: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        if input_a == 0.into() || input_b == 0.into() {
            validate_min_output(0.into(), min_lp_out)?;
            return Ok(0.into());
        }

        let pool_address = get_pool_custody_address(ctx);
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
        
        // Convert to decimals for elegant calculation
        let input_a_dec: numbers::Decimal = input_a.into();
        let input_b_dec: numbers::Decimal = input_b.into();
        let balance_a_dec: numbers::Decimal = balance_a.into();
        let balance_b_dec: numbers::Decimal = balance_b.into();
        let lp_supply_dec: numbers::Decimal = pool.lp_total_supply.into();

        // Calculate potential LP shares from each input independently
        let lp_from_a_dec = if balance_a_dec > 0.into() {
            (input_a_dec / balance_a_dec) * lp_supply_dec
        } else {
            0.into() // Edge case: no existing liquidity in token A
        };
        
        let lp_from_b_dec = if balance_b_dec > 0.into() {
            (input_b_dec / balance_b_dec) * lp_supply_dec
        } else {
            0.into() // Edge case: no existing liquidity in token B
        };

        // The actual LP to issue is the minimum - this ensures proportional deposits
        let lp_to_issue_dec = if lp_from_a_dec < lp_from_b_dec { lp_from_a_dec } else { lp_from_b_dec };
        let lp_to_issue = numbers::decimal_to_integer_floor(lp_to_issue_dec);
        
        // Calculate the exact deposit amounts needed for this LP amount
        let deposit_a_dec = if lp_supply_dec > 0.into() {
            (lp_to_issue_dec / lp_supply_dec) * balance_a_dec
        } else {
            input_a_dec // First deposit - use provided amount
        };
        
        let deposit_b_dec = if lp_supply_dec > 0.into() {
            (lp_to_issue_dec / lp_supply_dec) * balance_b_dec
        } else {
            input_b_dec // First deposit - use provided amount
        };
        
        let deposit_a = numbers::decimal_to_integer_ceil(deposit_a_dec); // Round up to ensure sufficient funds
        let deposit_b = numbers::decimal_to_integer_ceil(deposit_b_dec); // Round up to ensure sufficient funds

        validate_min_output(lp_to_issue, min_lp_out)?;

        // Transfer tokens from user to pool
        transfer_token_from_user_to_pool(ctx, &pool.token_a, deposit_a, &pool_address)?;
        transfer_token_from_user_to_pool(ctx, &pool.token_b, deposit_b, &pool_address)?;

        // Update LP tokens (use wrapper for map mutations)
        update_lp_balance(ctx, &pool_wrapper, &user_address, lp_to_issue, true);
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, lp_to_issue);
        pools.set(ctx, id, pool);

        // EVENT: Deposit { user: user_address, token_a_amount: deposit_a, token_b_amount: deposit_b, lp_minted: lp_to_issue }
        
        Ok(lp_to_issue)
    }

    fn withdraw(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_in: numbers::Integer,
        min_a_out: numbers::Integer,
        min_b_out: numbers::Integer,
    ) -> Result<WithdrawResult, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();

        if lp_in == 0.into() {
            return Ok(WithdrawResult { a_out: 0.into(), b_out: 0.into() });
        }

        let user_address = ctx.signer().to_string();
        let pool_address = get_pool_custody_address(ctx);
        
        // Check LP balance
        let user_lp = pool_wrapper.lp_ledger().get(ctx, &user_address).unwrap_or_default();
        if user_lp < lp_in {
            return Err(error::Error::Message("Insufficient LP tokens".to_string()));
        }
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;

        // Convert to decimals for clean calculation
        let lp_in_dec: numbers::Decimal = lp_in.into();
        let balance_a_dec: numbers::Decimal = balance_a.into();
        let balance_b_dec: numbers::Decimal = balance_b.into();
        let lp_supply_dec: numbers::Decimal = pool.lp_total_supply.into();

        // Calculate proportional withdrawal amounts
        let a_out_dec = (lp_in_dec * balance_a_dec) / lp_supply_dec;
        let b_out_dec = (lp_in_dec * balance_b_dec) / lp_supply_dec;
        
        let a_out = numbers::decimal_to_integer_floor(a_out_dec);
        let b_out = numbers::decimal_to_integer_floor(b_out_dec);
        
        validate_min_output(a_out, min_a_out)?;
        validate_min_output(b_out, min_b_out)?;

        // Transfer tokens from pool to user
        token_dyn::transfer(&pool.token_a, ctx.contract_signer(), &user_address, a_out)?;
        token_dyn::transfer(&pool.token_b, ctx.contract_signer(), &user_address, b_out)?;

        // Burn LP tokens
        update_lp_balance(ctx, &pool_wrapper, &user_address, lp_in, false);
        pool.lp_total_supply = numbers::sub_integer(pool.lp_total_supply, lp_in);
        pools.set(ctx, id, pool);
        
        // EVENT: Withdraw { user: user_address, lp_burned: lp_in, token_a_amount: a_out, token_b_amount: b_out }
        
        Ok(WithdrawResult { a_out, b_out })
    }

    fn swap_a(
        ctx: &ProcContext,
        pair: TokenPair,
        amount_in: numbers::Integer,
        min_out: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        let (id, _pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        if amount_in == 0.into() {
            validate_min_output(0.into(), min_out)?;
            return Ok(0.into());
        }
        
        let pool_address = get_pool_custody_address(ctx);
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
        
         let token_a = pool.token_a.clone();
         let token_b = pool.token_b.clone();
         let out_value = execute_swap(
             ctx,
             &mut pool,
             &token_a,  // token in
             &token_b,  // token out
             amount_in,
             balance_a,      // balance in
             balance_b,      // balance out
             min_out,
         )?;
         
         // Save the updated pool
         pools.set(ctx, id, pool);
        
        // EVENT: Swap { user: user_address, token_in: pool.token_a, amount_in, token_out: pool.token_b, amount_out: out_value, fee: admin_fee_in_lp }
        
        Ok(out_value)
    }

    fn swap_b(
        ctx: &ProcContext,
        pair: TokenPair,
        amount_in: numbers::Integer,
        min_out: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        let (id, _pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        if amount_in == 0.into() {
            validate_min_output(0.into(), min_out)?;
            return Ok(0.into());
        }
        
        let pool_address = get_pool_custody_address(ctx);
        
        // Get current pool balances
        let (balance_a, balance_b) = get_pool_token_balances(&pool, &pool_address)?;
        
         let token_a = pool.token_a.clone();
         let token_b = pool.token_b.clone();
         let out_value = execute_swap(
             ctx,
             &mut pool,
             &token_b,  // token in
             &token_a,  // token out
             amount_in,
             balance_b,      // balance in
             balance_a,      // balance out
             min_out,
         )?;
         
         // Save the updated pool
         pools.set(ctx, id, pool);
        
        // EVENT: Swap { user: user_address, token_in: pool.token_b, amount_in, token_out: pool.token_a, amount_out: out_value, fee: admin_fee_in_lp }
        
        Ok(out_value)
    }

    fn admin_withdraw_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        amount: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        let (id, pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        let amount_int = if amount == 0.into() {
            pool.admin_fee_lp
        } else {
            if amount > pool.admin_fee_lp {
                return Err(error::Error::Message("Insufficient admin fees".to_string()));
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
        
        Ok(amount_int)
    }

    fn admin_set_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_fee_rate: numbers::Decimal,
        admin_fee_rate: numbers::Decimal,
    ) -> Result<(), error::Error> {
        // Check admin authorization
        ensure_admin_auth(ctx)?;
        
        // Validate fee rates
        if lp_fee_rate >= 1.into() || admin_fee_rate > 1.into() {
            return Err(error::Error::Message("Invalid fee params".to_string()));
        }
        if lp_fee_rate < 0.into() || admin_fee_rate < 0.into() {
            return Err(error::Error::Message("Fee rates cannot be negative".to_string()));
        }
        
        let (id, _pool_wrapper, mut pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
            
        pool.lp_fee_rate = lp_fee_rate;
        pool.admin_fee_rate = admin_fee_rate;
        pools.set(ctx, id, pool);
        
        // EVENT: FeesUpdated { pool_id: id, lp_fee_bps, admin_fee_pct }
        
        Ok(())
    }
    
    // LP Token management functions
    fn lp_balance(ctx: &ViewContext, pair: TokenPair, owner: String) -> Option<numbers::Integer> {
        let id = pair_id(&pair);
        storage(ctx).pools().get(ctx, id)
            .and_then(|pool| pool.lp_ledger().get(ctx, owner))
    }
    
    fn lp_total_supply(ctx: &ViewContext, pair: TokenPair) -> Option<numbers::Integer> {
        let id = pair_id(&pair);
        storage(ctx).pools().get(ctx, id)
            .map(|pool| pool.lp_total_supply(ctx))
    }
    
    fn transfer_lp(ctx: &ProcContext, pair: TokenPair, to: String, amount: numbers::Integer) -> Result<(), error::Error> {
        let (id, pool_wrapper, pool) = load_pool(ctx, &pair)?;
        let pools = storage(ctx).pools();
        
        let from = ctx.signer().to_string();
        let from_balance = pool_wrapper.lp_ledger().get(ctx, &from).unwrap_or_default();
        
        if from_balance < amount {
            return Err(error::Error::Message("Insufficient LP balance".to_string()));
        }
        
        update_lp_balance(ctx, &pool_wrapper, &from, amount, false);
        update_lp_balance(ctx, &pool_wrapper, &to, amount, true);
        pools.set(ctx, id, pool);
        
        // EVENT: LPTransfer { from, to, amount }
        
        Ok(())
    }
    
    fn admin(ctx: &ViewContext) -> String {
        storage(ctx).admin(ctx)
    }
}