use stdlib::*;

contract!(name = "amm");

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

#[derive(Clone, StorageRoot)]
struct AMMStorage {
    pub pools: Map<String, Pool>,
    pub custodian: String,
}

fn pair_id(pair: &TokenPair) -> String {
    format!("{}::{}", pair.a, pair.b)
}

fn pair_other_token(
    pair: &TokenPair,
    token_in: &ContractAddress,
) -> Result<ContractAddress, Error> {
    if token_in == &pair.a {
        Ok(pair.b.clone())
    } else if token_in == &pair.b {
        Ok(pair.a.clone())
    } else {
        Err(Error::Message(format!("token {} not in pair", token_in)))
    }
}

fn validate_pair(pair: &TokenPair) -> Result<(), Error> {
    if pair.a.name.is_empty() || pair.b.name.is_empty() {
        return Err(Error::Message(
            "Token addresses must not be empty".to_string(),
        ));
    }

    if pair.a.to_string() >= pair.b.to_string() {
        return Err(Error::Message(
            "Token pair must be ordered A < B".to_string(),
        ));
    }

    Ok(())
}

fn validate_amount(amount: Integer) -> Result<(), Error> {
    // 0 < amount < sqrt(MAX_INT)
    if amount <= Integer::default() || amount > "340_282_366_920_938_463_463_374_607_431".into() {
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
    validate_amount(amount_in)?;
    validate_amount(bal_in)?;
    validate_amount(bal_out)?;

    // input amount less fee, round down
    let bps_in_100pct = 10000.into();
    let in_less_fee = amount_in * (bps_in_100pct - fee_bps) / bps_in_100pct;

    let new_bal_in = bal_in + in_less_fee;
    validate_amount(new_bal_in)?;

    // calculate output amount from delta in output-token balance, round down
    let k = bal_in * bal_out;
    Ok((bal_out * new_bal_in - k) / new_bal_in)
}

fn pool_not_found() -> Error {
    Error::Message("Pool not found".to_string())
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        let custodian = ctx.contract_signer().to_string();

        AMMStorage {
            pools: Map::default(),
            custodian,
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
        validate_pair(&pair)?;
        validate_amount(amount_a)?;
        validate_amount(amount_b)?;

        let pools = ctx.model().pools();

        match pools.get(pair_id(&pair)).ok_or(pool_not_found()) {
            Ok(_) => Err(Error::Message(
                "pool for this pair already exists".to_string(),
            )),
            Err(_) => Ok(()),
        }?;

        let lp_shares = (amount_a * amount_b).sqrt()?;

        let admin = ctx.signer().to_string();
        pools.set(
            pair_id(&pair),
            Pool {
                token_a: pair.a.clone(),
                balance_a: amount_a,
                token_b: pair.b.clone(),
                balance_b: amount_b,
                fee_bps,
                lp_total_supply: lp_shares,
                lp_ledger: Map::new(&[(admin, lp_shares)]),
            },
        );

        let custodian = ctx.contract_signer().to_string();
        token_dyn::transfer(&pair.a, ctx.signer(), &custodian, amount_a)?;
        token_dyn::transfer(&pair.b, ctx.signer(), &custodian, amount_b)?;

        Ok(lp_shares)
    }

    fn fee(ctx: &ViewContext, pair: TokenPair) -> Result<Integer, Error> {
        Ok(ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?
            .fee_bps())
    }

    fn balance(ctx: &ViewContext, pair: TokenPair, acc: String) -> Option<Integer> {
        ctx.model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())
            .ok()
            .and_then(|p| p.lp_ledger().get(acc))
    }

    fn token_balance(
        ctx: &ViewContext,
        pair: TokenPair,
        token: ContractAddress,
    ) -> Result<Integer, Error> {
        pair_other_token(&pair, &token)?;
        let pool = ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?;
        if token == pair.a {
            Ok(pool.balance_a())
        } else {
            Ok(pool.balance_b())
        }
    }

    fn quote_deposit(
        ctx: &ViewContext,
        pair: TokenPair,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        validate_amount(amount_a)?;
        validate_amount(amount_b)?;

        let pool = ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?;

        let lp_supply = pool.lp_total_supply();
        let balance_a = pool.balance_a();
        let balance_b = pool.balance_b();
        let lp_shares = if amount_a * balance_b < amount_b * balance_a {
            amount_a * lp_supply / balance_a
        } else {
            amount_b * lp_supply / balance_b
        };

        let supply_minus_one = lp_supply - 1.into();
        Ok(DepositResult {
            deposit_a: (lp_shares * balance_a + supply_minus_one) / lp_supply, // round up
            deposit_b: (lp_shares * balance_b + supply_minus_one) / lp_supply, // round up
            lp_shares,
        })
    }

    fn deposit(
        ctx: &ProcContext,
        pair: TokenPair,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        let res = Self::quote_deposit(&ctx.view_context(), pair.clone(), amount_a, amount_b)?;
        let model = ctx.model();
        let pool = model.pools().get(pair_id(&pair)).ok_or(pool_not_found())?;
        let ledger = pool.lp_ledger();
        let addr = model.custodian();
        pool.set_balance_a(pool.balance_a() + res.deposit_a);
        pool.set_balance_b(pool.balance_b() + res.deposit_b);

        let user = ctx.signer().to_string();
        let bal = ledger.get(&user).unwrap_or_default();
        ledger.set(user, bal + res.lp_shares);
        pool.set_lp_total_supply(pool.lp_total_supply() + res.lp_shares);

        token_dyn::transfer(&pair.a, ctx.signer(), &addr, res.deposit_a)?;
        token_dyn::transfer(&pair.b, ctx.signer(), &addr, res.deposit_b)?;

        Ok(res)
    }

    fn quote_withdraw(
        ctx: &ViewContext,
        pair: TokenPair,
        shares: Integer,
    ) -> Result<WithdrawResult, Error> {
        validate_amount(shares)?;
        let pool = ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?;

        let lp_total_supply = pool.lp_total_supply();
        Ok(WithdrawResult {
            amount_a: shares * pool.balance_a() / lp_total_supply,
            amount_b: shares * pool.balance_b() / lp_total_supply,
        })
    }

    fn withdraw(
        ctx: &ProcContext,
        pair: TokenPair,
        shares: Integer,
    ) -> Result<WithdrawResult, Error> {
        let res = Self::quote_withdraw(&ctx.view_context(), pair.clone(), shares)?;
        let pool = ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?;
        let ledger = pool.lp_ledger();
        let user = ctx.signer().to_string();

        let total = pool.lp_total_supply();
        let bal = ledger.get(&user).unwrap_or_default();

        if total < shares {
            return Err(Error::Message("insufficient total supply".to_string()));
        }
        if bal < shares {
            return Err(Error::Message("insufficient share balance".to_string()));
        }

        ledger.set(user.clone(), bal - shares);
        pool.set_lp_total_supply(total - shares);
        pool.set_balance_a(pool.balance_a() - res.amount_a);
        pool.set_balance_b(pool.balance_b() - res.amount_b);

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
        let pool = ctx
            .model()
            .pools()
            .get(pair_id(&pair))
            .ok_or(pool_not_found())?;
        let (bal_in, bal_out) = if token_in == pair.a {
            (pool.balance_a(), pool.balance_b())
        } else {
            (pool.balance_b(), pool.balance_a())
        };
        calc_swap_result(amount_in, bal_in, bal_out, pool.fee_bps())
    }

    fn swap(
        ctx: &ProcContext,
        pair: TokenPair,
        token_in: ContractAddress,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        let token_out = pair_other_token(&pair, &token_in)?;
        let amount_out = Self::quote_swap(
            &ctx.view_context(),
            pair.clone(),
            token_in.clone(),
            amount_in,
        )?;

        if amount_out < min_out {
            return Err(Error::Message(format!(
                "amount out ({}) below minimum",
                amount_out
            )));
        }

        let model = ctx.model();
        let pool = model.pools().get(pair_id(&pair)).ok_or(pool_not_found())?;
        if token_in == pair.a {
            pool.set_balance_a(pool.balance_a() + amount_in);
            pool.set_balance_b(pool.balance_b() - amount_out);
        } else {
            pool.set_balance_a(pool.balance_a() - amount_out);
            pool.set_balance_b(pool.balance_b() + amount_in);
        }

        token_dyn::transfer(&token_in, ctx.signer(), &model.custodian(), amount_in)?;
        token_dyn::transfer(
            &token_out,
            ctx.contract_signer(),
            &ctx.signer().to_string(),
            amount_out,
        )?;

        Ok(amount_out)
    }
}
