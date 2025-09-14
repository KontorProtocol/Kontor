use stdlib::*;

contract!(name = "amm");

interface!(name = "token_dyn", path = "token/wit");

const BPS_IN_100_PCT: numbers::Integer = numbers::Integer {
    r0: 10_000,
    r1: 0,
    r2: 0,
    r3: 0,
    sign: numbers::Sign::Plus,
};

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

fn calc_swap_result(
    i_value: numbers::Integer,
    i_pool_value: numbers::Integer,
    o_pool_value: numbers::Integer,
    pool_lp_value: numbers::Integer,
    lp_fee_bps: numbers::Integer,
    admin_fee_pct: numbers::Integer,
) -> Result<(numbers::Integer, numbers::Integer), error::Error> {
    let hundred: numbers::Integer = 100.into();
    
    let lp_fee_value = numbers::mul_div_up_integer(i_value, lp_fee_bps, BPS_IN_100_PCT);
    let in_after_lp_fee = numbers::sub_integer(i_value, lp_fee_value);
    let out_value = numbers::mul_div_down_integer(
        in_after_lp_fee,
        o_pool_value,
        numbers::add_integer(i_pool_value, in_after_lp_fee),
    );

    let admin_fee_value = numbers::mul_div_down_integer(lp_fee_value, admin_fee_pct, hundred);
    
    // For simplicity, convert admin fee directly to LP tokens
    // In a real AMM, this would be more sophisticated
    let admin_fee_in_lp = if pool_lp_value == 0.into() {
        0.into()
    } else {
        // Convert admin fee (in input token) to LP tokens proportionally
        numbers::mul_div_down_integer(admin_fee_value, pool_lp_value, i_pool_value)
    };
    
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
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        ensure_pair_sorted(&pair)?;
        
        if init_a == 0.into() || init_b == 0.into() {
            return Err(error::Error::Message("Input balances cannot be zero".to_string()));
        }
        if lp_fee_bps >= BPS_IN_100_PCT {
            return Err(error::Error::Message("Invalid lp fee bps".to_string()));
        }
        let hundred: numbers::Integer = 100.into();
        if admin_fee_pct > hundred {
            return Err(error::Error::Message("Invalid admin fee pct".to_string()));
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
        // User must have approved the AMM to spend their tokens first
        // Ensure allowance for AMM to pull user's tokens
        let spender = ctx.contract_signer().to_string();
        token_dyn::approve(&pair.token_a, ctx.signer(), &spender, init_a)?;
        token_dyn::transfer_from(&pair.token_a, ctx.contract_signer(), &user_address, &pool_address, init_a)?;
        
        token_dyn::approve(&pair.token_b, ctx.signer(), &spender, init_b)?;
        token_dyn::transfer_from(&pair.token_b, ctx.contract_signer(), &user_address, &pool_address, init_b)?;

        let lp_to_issue = numbers::mul_sqrt_integer(init_a, init_b);
        
        // Create pool with LP ledger
        let mut lp_ledger = Map::default();
        lp_ledger.entries.push((user_address, lp_to_issue));
        
        pools.set(
            ctx,
            id,
            Pool {
                token_a: pair.token_a,
                token_b: pair.token_b,
                lp_fee_bps,
                admin_fee_pct,
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
                lp_fee_bps: pool.lp_fee_bps,
                admin_fee_pct: pool.admin_fee_pct,
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
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);

        if input_a == 0.into() || input_b == 0.into() {
            if min_lp_out != 0.into() {
                return Err(error::Error::Message("Excessive slippage".to_string()));
            }
            return Ok(0.into());
        }

        let pool_address = get_pool_custody_address(ctx);
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let balance_a = get_token_balance(Some(ctx.signer()), &pool.token_a, &pool_address)?;
        let balance_b = get_token_balance(Some(ctx.signer()), &pool.token_b, &pool_address)?;
        
        let dab = numbers::mul_integer(input_a, balance_b);
        let dba = numbers::mul_integer(input_b, balance_a);

        let (deposit_a, deposit_b, lp_to_issue) = if dab > dba {
            let deposit_b = input_b;
            let deposit_a = numbers::mul_div_up_integer(dba, 1.into(), balance_b);
            let lp_to_issue = numbers::mul_div_down_integer(deposit_b, pool.lp_total_supply, balance_b);
            (deposit_a, deposit_b, lp_to_issue)
        } else if dab < dba {
            let deposit_a = input_a;
            let deposit_b = numbers::mul_div_up_integer(dab, 1.into(), balance_a);
            let lp_to_issue = numbers::mul_div_down_integer(deposit_a, pool.lp_total_supply, balance_a);
            (deposit_a, deposit_b, lp_to_issue)
        } else {
            let deposit_a = input_a;
            let deposit_b = input_b;
            let lp_to_issue = if pool.lp_total_supply == 0.into() {
                numbers::mul_sqrt_integer(deposit_a, deposit_b)
            } else {
                numbers::mul_div_down_integer(deposit_a, pool.lp_total_supply, balance_a)
            };
            (deposit_a, deposit_b, lp_to_issue)
        };

        if lp_to_issue < min_lp_out {
            return Err(error::Error::Message("Excessive slippage".to_string()));
        }

        // Transfer tokens from user to pool
        let spender = ctx.contract_signer().to_string();
        token_dyn::approve(&pool.token_a, ctx.signer(), &spender, deposit_a)?;
        token_dyn::transfer_from(&pool.token_a, ctx.contract_signer(), &user_address, &pool_address, deposit_a)?;
        
        token_dyn::approve(&pool.token_b, ctx.signer(), &spender, deposit_b)?;
        token_dyn::transfer_from(&pool.token_b, ctx.contract_signer(), &user_address, &pool_address, deposit_b)?;

        // Update LP tokens (use wrapper for map mutations)
        let current_lp = pool_wrapper.lp_ledger().get(ctx, &user_address).unwrap_or_default();
        pool_wrapper
            .lp_ledger()
            .set(ctx, user_address, numbers::add_integer(current_lp, lp_to_issue));
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
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);

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
        let balance_a = get_token_balance(Some(ctx.signer()), &pool.token_a, &pool_address)?;
        let balance_b = get_token_balance(Some(ctx.signer()), &pool.token_b, &pool_address)?;

        let a_out = numbers::mul_div_down_integer(lp_in, balance_a, pool.lp_total_supply);
        let b_out = numbers::mul_div_down_integer(lp_in, balance_b, pool.lp_total_supply);
        
        if a_out < min_a_out || b_out < min_b_out {
            return Err(error::Error::Message("Excessive slippage".to_string()));
        }

        // Transfer tokens from pool to user
        token_dyn::transfer(&pool.token_a, ctx.contract_signer(), &user_address, a_out)?;
        
        token_dyn::transfer(&pool.token_b, ctx.contract_signer(), &user_address, b_out)?;

        // Burn LP tokens
        pool_wrapper
            .lp_ledger()
            .set(ctx, user_address, numbers::sub_integer(user_lp, lp_in));
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
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);
            
        if amount_in == 0.into() {
            if min_out != 0.into() {
                return Err(error::Error::Message("Excessive slippage".to_string()));
            }
            return Ok(0.into());
        }
        
        let pool_address = get_pool_custody_address(ctx);
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let balance_a = get_token_balance(Some(ctx.signer()), &pool.token_a, &pool_address)?;
        let balance_b = get_token_balance(Some(ctx.signer()), &pool.token_b, &pool_address)?;
        
        if balance_a == 0.into() || balance_b == 0.into() {
            return Err(error::Error::Message("Pool has no liquidity".to_string()));
        }

        let (out_value, admin_fee_in_lp) = calc_swap_result(
            amount_in,
            balance_a,
            balance_b,
            pool.lp_total_supply,
            pool.lp_fee_bps,
            pool.admin_fee_pct,
        )?;
        
        if out_value < min_out {
            return Err(error::Error::Message("Excessive slippage".to_string()));
        }
        
        // Transfer token A from user to pool
        let spender = ctx.contract_signer().to_string();
        token_dyn::approve(&pool.token_a, ctx.signer(), &spender, amount_in)?;
        token_dyn::transfer_from(&pool.token_a, ctx.contract_signer(), &user_address, &pool_address, amount_in)?;
        
        // Transfer token B from pool to user
        token_dyn::transfer(&pool.token_b, ctx.contract_signer(), &user_address, out_value)?;
        
        // Update admin fees
        pool.admin_fee_lp = numbers::add_integer(pool.admin_fee_lp, admin_fee_in_lp);
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, admin_fee_in_lp);
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
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);
            
        if amount_in == 0.into() {
            if min_out != 0.into() {
                return Err(error::Error::Message("Excessive slippage".to_string()));
            }
            return Ok(0.into());
        }
        
        let pool_address = get_pool_custody_address(ctx);
        let user_address = ctx.signer().to_string();
        
        // Get current pool balances
        let balance_a = get_token_balance(Some(ctx.signer()), &pool.token_a, &pool_address)?;
        let balance_b = get_token_balance(Some(ctx.signer()), &pool.token_b, &pool_address)?;
        
        if balance_a == 0.into() || balance_b == 0.into() {
            return Err(error::Error::Message("Pool has no liquidity".to_string()));
        }

        let (out_value, admin_fee_in_lp) = calc_swap_result(
            amount_in,
            balance_b,
            balance_a,
            pool.lp_total_supply,
            pool.lp_fee_bps,
            pool.admin_fee_pct,
        )?;
        
        if out_value < min_out {
            return Err(error::Error::Message("Excessive slippage".to_string()));
        }
        
        // Transfer token B from user to pool
        let spender = ctx.contract_signer().to_string();
        token_dyn::approve(&pool.token_b, ctx.signer(), &spender, amount_in)?;
        token_dyn::transfer_from(&pool.token_b, ctx.contract_signer(), &user_address, &pool_address, amount_in)?;
        
        // Transfer token A from pool to user
        token_dyn::transfer(&pool.token_a, ctx.contract_signer(), &user_address, out_value)?;
        
        // Update admin fees
        pool.admin_fee_lp = numbers::add_integer(pool.admin_fee_lp, admin_fee_in_lp);
        pool.lp_total_supply = numbers::add_integer(pool.lp_total_supply, admin_fee_in_lp);
        pools.set(ctx, id, pool);
        
        // EVENT: Swap { user: user_address, token_in: pool.token_b, amount_in, token_out: pool.token_a, amount_out: out_value, fee: admin_fee_in_lp }
        
        Ok(out_value)
    }

    fn admin_withdraw_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        amount: numbers::Integer,
    ) -> Result<numbers::Integer, error::Error> {
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);
            
        // Check admin authorization
        if ctx.signer().to_string() != storage(ctx).admin(ctx) {
            return Err(error::Error::Message("Not authorized: admin only".to_string()));
        }
        
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
        let current_lp = pool_wrapper.lp_ledger().get(ctx, &admin_address).unwrap_or_default();
        pool_wrapper
            .lp_ledger()
            .set(ctx, admin_address, numbers::add_integer(current_lp, amount_int));
        
        pool.admin_fee_lp = numbers::sub_integer(pool.admin_fee_lp, amount_int);
        // Note: We don't reduce lp_total_supply here as the LP tokens already exist, just moving ownership
        pools.set(ctx, id, pool);
        
        // EVENT: AdminWithdrawFees { admin: admin_address, amount: amount_int }
        
        Ok(amount_int)
    }

    fn admin_set_fees(
        ctx: &ProcContext,
        pair: TokenPair,
        lp_fee_bps: numbers::Integer,
        admin_fee_pct: numbers::Integer,
    ) -> Result<(), error::Error> {
        // Check admin authorization
        if ctx.signer().to_string() != storage(ctx).admin(ctx) {
            return Err(error::Error::Message("Not authorized: admin only".to_string()));
        }
        let hundred: numbers::Integer = 100.into();
        if lp_fee_bps >= BPS_IN_100_PCT || admin_fee_pct > hundred {
            return Err(error::Error::Message("Invalid fee params".to_string()));
        }
        
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);
            
        pool.lp_fee_bps = lp_fee_bps;
        pool.admin_fee_pct = admin_fee_pct;
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
        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools.get(ctx, &id)
            .ok_or_else(|| error::Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);
        
        let from = ctx.signer().to_string();
        let from_balance = pool_wrapper.lp_ledger().get(ctx, &from).unwrap_or_default();
        
        if from_balance < amount {
            return Err(error::Error::Message("Insufficient LP balance".to_string()));
        }
        
        let to_balance = pool_wrapper.lp_ledger().get(ctx, &to).unwrap_or_default();
        pool_wrapper
            .lp_ledger()
            .set(ctx, from, numbers::sub_integer(from_balance, amount));
        pool_wrapper
            .lp_ledger()
            .set(ctx, to, numbers::add_integer(to_balance, amount));
        pools.set(ctx, id, pool);
        
        // EVENT: LPTransfer { from, to, amount }
        
        Ok(())
    }
    
    fn admin(ctx: &ViewContext) -> String {
        storage(ctx).admin(ctx)
    }
}