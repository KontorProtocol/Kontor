use stdlib::*;

contract!(name = "amm");

import!(name = "token", height = 0, tx_index = 0, path = "token/wit");

interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, Storage)]
struct Pool {
    pub token_a: ContractAddress,
    pub balance_a: Integer,
    pub token_b: ContractAddress,
    pub balance_b: Integer,
    pub fee_bps: Integer,

    pub lp_total_supply: Integer,
    pub lp_ledger: Map<String, Integer>,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            token_a: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            balance_a: 0.into(),
            token_b: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            balance_b: 0.into(),
            fee_bps: 0.into(),
            lp_total_supply: 0.into(),
            lp_ledger: Map::default(),
        }
    }
}

#[derive(Clone, StorageRoot)]
struct AMMStorage {
    pub pools: Map<String, Pool>,
    pub custody_addr: String,
}

fn token_string(token: &ContractAddress) -> String {
    format!("{}_{}_{}", token.name, token.height, token.tx_index)
}

fn pair_id(pair: &TokenPair) -> String {
    format!("{}::{}", token_string(&pair.a), token_string(&pair.b))
}

fn pair_other_token(
    pair: &TokenPair,
    token_in: &ContractAddress,
) -> Result<ContractAddress, Error> {
    if token_string(token_in) == token_string(&pair.a) {
        Ok(pair.b.clone())
    } else if token_string(token_in) == token_string(&pair.b) {
        Ok(pair.a.clone())
    } else {
        Err(Error::Message(format!("token {} not in pair", token_in)))
    }
}

fn check_pair_order(pair: &TokenPair) -> Result<(), Error> {
    if pair.a.name.is_empty() || pair.b.name.is_empty() {
        return Err(Error::Message(
            "Token addresses must not be empty".to_string(),
        ));
    }

    if token_string(&pair.a) >= token_string(&pair.b) {
        return Err(Error::Message(
            "Token pair must be ordered A < B".to_string(),
        ));
    }

    Ok(())
}

fn check_amount_positive(amount: Integer) -> Result<(), Error> {
    let zero = Integer::default();
    let max_value: Integer = "340_282_366_920_938_463_463_374_607_431".into(); // sqrt(MAX_INT)
    if amount <= zero || amount > max_value {
        return Err(Error::Message("bad amount".to_string()));
    }
    Ok(())
}

fn calc_swap_result(
    amount_in: Integer,
    bal_in: Integer,
    bal_out: Integer,
    fee_bps: Integer,
) -> Result<Integer, Error> {
    check_amount_positive(amount_in)?;
    check_amount_positive(bal_in)?;
    check_amount_positive(bal_out)?;

    // input amount less fee, round down
    let bps_in_100pct = 10000.into();
    let in_less_fee = amount_in * (bps_in_100pct - fee_bps) / bps_in_100pct;

    let new_bal_in = bal_in + in_less_fee;
    check_amount_positive(new_bal_in)?;

    // calculate output amount from delta in output-token balance, round down
    let k = bal_in * bal_out;
    Ok((bal_out * new_bal_in - k) / new_bal_in)
}

impl Amm {
    fn load_pool<C: ReadContext>(ctx: &C, pair: &TokenPair) -> Result<Pool, Error> {
        let id = pair_id(pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools
            .get(ctx, &id)
            .ok_or_else(|| Error::Message("Pool not found".to_string()))?;
        Ok(pool_wrapper.load(ctx))
    }

    fn quote_swap<C: ReadContext>(
        ctx: &C,
        pair: &TokenPair,
        token_in: &ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        let pool = Self::load_pool(ctx, pair)?;
        let (bal_in, bal_out) = if token_string(token_in) == token_string(&pair.a) {
            (pool.balance_a, pool.balance_b)
        } else {
            (pool.balance_b, pool.balance_a)
        };
        calc_swap_result(amount_in, bal_in, bal_out, pool.fee_bps)
    }

    fn quote_deposit<C: ReadContext>(
        ctx: &C,
        pair: &TokenPair,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        check_amount_positive(amount_a)?;
        check_amount_positive(amount_b)?;

        let pool = Self::load_pool(ctx, pair)?;

        let lp_supply = pool.lp_total_supply;
        let lp_shares = if amount_a * pool.balance_b < amount_b * pool.balance_a {
            amount_a * lp_supply / pool.balance_a
        } else {
            amount_b * lp_supply / pool.balance_b
        };

        let supply_minus_one = lp_supply - 1.into();
        Ok(DepositResult {
            deposit_a: (lp_shares * pool.balance_a + supply_minus_one) / lp_supply, // round up
            deposit_b: (lp_shares * pool.balance_b + supply_minus_one) / lp_supply, // round up
            lp_shares,
        })
    }

    fn quote_withdraw<C: ReadContext>(
        ctx: &C,
        pair: &TokenPair,
        shares: Integer,
    ) -> Result<WithdrawResult, Error> {
        check_amount_positive(shares)?;

        let pool = Self::load_pool(ctx, pair)?;
        Ok(WithdrawResult {
            amount_a: shares * pool.balance_a / pool.lp_total_supply,
            amount_b: shares * pool.balance_b / pool.lp_total_supply,
        })
    }
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        let custody_addr = ctx.contract_signer().to_string();

        AMMStorage {
            pools: Map::default(),
            custody_addr,
        }
        .init(ctx)
    }

    fn create(
        ctx: &ProcContext,
        pair: TokenPair,
        amount_a: Integer,
        amount_b: Integer,
        fee_bps: Integer,
    ) -> Result<Integer, Error> {
        check_pair_order(&pair)?;
        check_amount_positive(amount_a)?;
        check_amount_positive(amount_b)?;

        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        if pools.get(ctx, &id).is_some() {
            return Err(Error::Message(
                "pool for this pair already exists".to_string(),
            ));
        }

        let lp_shares = numbers::sqrt_integer(amount_a * amount_b)?;
        check_amount_positive(lp_shares)?;

        let custody_addr = ctx.contract_signer().to_string();
        token_dyn::transfer(&pair.a, ctx.signer(), &custody_addr, amount_a)?;
        token_dyn::transfer(&pair.b, ctx.signer(), &custody_addr, amount_b)?;

        let admin = ctx.signer().to_string();

        pools.set(
            ctx,
            id,
            Pool {
                token_a: pair.a,
                balance_a: amount_a,
                token_b: pair.b,
                balance_b: amount_b,
                fee_bps,
                lp_total_supply: lp_shares,
                lp_ledger: Map::new(&[(admin, lp_shares)]),
            },
        );

        Ok(lp_shares)
    }

    fn fee(ctx: &ViewContext, pair: TokenPair) -> Result<Integer, Error> {
        let pool = Self::load_pool(ctx, &pair)?;
        Ok(pool.fee_bps)
    }

    fn balance(ctx: &ViewContext, pair: TokenPair, acc: String) -> Option<Integer> {
        let pool_wrapper = storage(ctx).pools().get(ctx, pair_id(&pair))?;
        pool_wrapper.lp_ledger().get(ctx, acc)
    }

    fn token_balance(
        ctx: &ViewContext,
        pair: TokenPair,
        token: ContractAddress,
    ) -> Result<Integer, Error> {
        pair_other_token(&pair, &token)?;
        let pool = Self::load_pool(ctx, &pair)?;
        if token_string(&token) == token_string(&pair.a) {
            Ok(pool.balance_a)
        } else {
            Ok(pool.balance_b)
        }
    }

    fn quote_deposit(
        ctx: &ViewContext,
        pair: TokenPair,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        Self::quote_deposit(ctx, &pair, amount_a, amount_b)
    }

    fn deposit(
        ctx: &ProcContext,
        pair: TokenPair,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        let res = Self::quote_deposit(ctx, &pair, amount_a, amount_b)?;

        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools
            .get(ctx, &id)
            .ok_or_else(|| Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);

        let ledger = pool_wrapper.lp_ledger();
        let addr = storage(ctx).custody_addr(ctx);
        token_dyn::transfer(&pair.a, ctx.signer(), &addr, res.deposit_a)?;
        token_dyn::transfer(&pair.b, ctx.signer(), &addr, res.deposit_b)?;
        pool.balance_a = pool.balance_a + res.deposit_a;
        pool.balance_b = pool.balance_b + res.deposit_b;

        let user = ctx.signer().to_string();
        let bal = ledger.get(ctx, &user).unwrap_or_default();
        ledger.set(ctx, user, bal + res.lp_shares);

        pool.lp_total_supply = pool.lp_total_supply + res.lp_shares;
        pools.set(ctx, id, pool);

        Ok(res)
    }

    fn quote_withdraw(
        ctx: &ViewContext,
        pair: TokenPair,
        shares: Integer,
    ) -> Result<WithdrawResult, Error> {
        Self::quote_withdraw(ctx, &pair, shares)
    }

    fn withdraw(
        ctx: &ProcContext,
        pair: TokenPair,
        shares: Integer,
    ) -> Result<WithdrawResult, Error> {
        let res = Self::quote_withdraw(ctx, &pair, shares)?;

        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools
            .get(ctx, &id)
            .ok_or_else(|| Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);

        let ledger = pool_wrapper.lp_ledger();
        let user = ctx.signer().to_string();

        let total = pool.lp_total_supply;
        let bal = ledger.get(ctx, &user).unwrap_or_default();

        if total < shares {
            return Err(Error::Message("insufficient total supply".to_string()));
        }
        if bal < shares {
            return Err(Error::Message("insufficient share balance".to_string()));
        }

        ledger.set(ctx, user.clone(), bal - shares);
        pool.lp_total_supply = total - shares;
        pool.balance_a = pool.balance_a - res.amount_a;
        pool.balance_b = pool.balance_b - res.amount_b;
        pools.set(ctx, id, pool);

        token_dyn::transfer(&pair.a, ctx.contract_signer(), &user, res.amount_a)?;
        token_dyn::transfer(&pair.b, ctx.contract_signer(), &user, res.amount_b)?;

        Ok(res)
    }

    fn quote_swap(
        ctx: &ViewContext,
        pair: TokenPair,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        Self::quote_swap(ctx, &pair, &token_in, amount_in)
    }

    fn swap(
        ctx: &ProcContext,
        pair: TokenPair,
        token_in: ContractAddress,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        let token_out = pair_other_token(&pair, &token_in)?;
        let amount_out = Self::quote_swap(ctx, &pair, &token_in, amount_in)?;

        let id = pair_id(&pair);
        let pools = storage(ctx).pools();
        let pool_wrapper = pools
            .get(ctx, &id)
            .ok_or_else(|| Error::Message("Pool not found".to_string()))?;
        let mut pool = pool_wrapper.load(ctx);

        if amount_out >= min_out {
            let user_addr = ctx.signer().to_string();
            let addr = storage(ctx).custody_addr(ctx);

            token_dyn::transfer(&token_in, ctx.signer(), &addr, amount_in)?;
            token_dyn::transfer(&token_out, ctx.contract_signer(), &user_addr, amount_out)?;

            if token_string(&token_in) == token_string(&pair.a) {
                pool.balance_a = pool.balance_a + amount_in;
                pool.balance_b = pool.balance_b - amount_out;
            } else {
                pool.balance_a = pool.balance_a - amount_out;
                pool.balance_b = pool.balance_b + amount_in;
            }
            pools.set(ctx, id, pool);

            Ok(amount_out)
        } else {
            Err(Error::Message(format!(
                "amount out ({}) below minimum",
                amount_out
            )))
        }
    }
}
