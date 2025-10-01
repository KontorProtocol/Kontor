use stdlib::*;

contract!(name = "pool");

interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, StorageRoot)]
struct PoolStorage {
    pub token_a: ContractAddress,
    pub token_b: ContractAddress,
    pub fee_bps: Integer,

    pub lp_total_supply: Integer,
    pub lp_ledger: Map<String, Integer>,

    pub custodian: String,
}

impl PoolStorage {
    pub fn new(
        ctx: &ProcContext,
        token_a: ContractAddress,
        amount_a: Integer,
        token_b: ContractAddress,
        amount_b: Integer,
        fee_bps: Integer,
    ) -> Result<Self, Error> {
        validate_amount(amount_a)?;
        validate_amount(amount_b)?;

        let lp_shares = numbers::sqrt_integer(amount_a * amount_b)?;
        let custodian = ctx.contract_signer().to_string();
        let pool = PoolStorage {
            token_a: token_a.clone(),
            token_b: token_b.clone(),
            fee_bps,
            lp_total_supply: lp_shares,
            lp_ledger: Map::new(&[(ctx.signer().to_string(), lp_shares)]),
            custodian: custodian.clone(),
        };

        token_dyn::transfer(&token_a, ctx.signer(), &custodian, amount_a)?;
        token_dyn::transfer(&token_b, ctx.signer(), &custodian, amount_b)?;

        Ok(pool)
    }
}

fn token_out(ctx: &impl ReadContext, token_in: &ContractAddress) -> Result<ContractAddress, Error> {
    let token_a = storage(ctx).token_a(ctx);
    let token_b = storage(ctx).token_b(ctx);
    if token_in == &token_a {
        Ok(token_b)
    } else if token_in == &token_b {
        Ok(token_a)
    } else {
        Err(Error::Message(format!("token {} not in pair", token_in)))
    }
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

fn quote_swap(
    ctx: &impl ReadContext,
    token_in: &ContractAddress,
    amount_in: Integer,
) -> Result<Integer, Error> {
    let custodian = storage(ctx).custodian(ctx);
    let bal_in = token_dyn::balance(token_in, &custodian).unwrap_or_default();
    let bal_out = token_dyn::balance(&token_out(ctx, token_in)?, &custodian).unwrap_or_default();
    calc_swap_result(amount_in, bal_in, bal_out, storage(ctx).fee_bps(ctx))
}

fn quote_deposit(
    ctx: &impl ReadContext,
    amount_a: Integer,
    amount_b: Integer,
) -> Result<DepositResult, Error> {
    validate_amount(amount_a)?;
    validate_amount(amount_b)?;

    let token_a = storage(ctx).token_a(ctx);
    let token_b = storage(ctx).token_b(ctx);
    let lp_supply = storage(ctx).lp_total_supply(ctx);

    let custodian = storage(ctx).custodian(ctx);
    let bal_a = token_dyn::balance(&token_a, &custodian).unwrap_or_default();
    let bal_b = token_dyn::balance(&token_b, &custodian).unwrap_or_default();

    let lp_shares = if amount_a * bal_b < amount_b * bal_a {
        amount_a * lp_supply / bal_a
    } else {
        amount_b * lp_supply / bal_b
    };

    let supply_minus_one = lp_supply - 1.into();
    Ok(DepositResult {
        deposit_a: (lp_shares * bal_a + supply_minus_one) / lp_supply, // round up
        deposit_b: (lp_shares * bal_b + supply_minus_one) / lp_supply, // round up
        lp_shares,
    })
}

fn quote_withdraw(ctx: &impl ReadContext, shares: Integer) -> Result<WithdrawResult, Error> {
    validate_amount(shares)?;

    let token_a = storage(ctx).token_a(ctx);
    let token_b = storage(ctx).token_b(ctx);
    let lp_supply = storage(ctx).lp_total_supply(ctx);

    let custodian = storage(ctx).custodian(ctx);
    let bal_a = token_dyn::balance(&token_a, &custodian).unwrap_or_default();
    let bal_b = token_dyn::balance(&token_b, &custodian).unwrap_or_default();

    Ok(WithdrawResult {
        amount_a: shares * bal_a / lp_supply,
        amount_b: shares * bal_b / lp_supply,
    })
}

impl Guest for Pool {
    // Dummy implementation for testing purposes.
    fn init(ctx: &ProcContext) {
        PoolStorage {
            token_a: ContractAddress {
                name: "".to_string(),
                height: 0,
                tx_index: 0,
            },
            token_b: ContractAddress {
                name: "".to_string(),
                height: 0,
                tx_index: 0,
            },
            lp_ledger: Map::default(),
            lp_total_supply: 0.into(),
            fee_bps: 0.into(),
            custodian: "".to_string(),
        }
        .init(ctx);
    }

    // This represents the production init function.
    // Only for local testing purposes.
    fn re_init(
        ctx: &ProcContext,
        token_a: ContractAddress,
        amount_a: Integer,
        token_b: ContractAddress,
        amount_b: Integer,
        fee: Integer,
    ) -> Result<Integer, Error> {
        PoolStorage::new(ctx, token_a, amount_a, token_b, amount_b, fee)?.init(ctx);
        Ok(storage(ctx).lp_total_supply(ctx))
    }

    fn fee(ctx: &ViewContext) -> Integer {
        storage(ctx).fee_bps(ctx)
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        storage(ctx).lp_ledger().get(ctx, acc)
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).lp_ledger();

        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();
        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, from_balance - n);
        ledger.set(ctx, to, to_balance + n);
        Ok(())
    }

    fn token_balance(ctx: &ViewContext, token: ContractAddress) -> Result<Integer, Error> {
        token_out(ctx, &token)?;
        Ok(token_dyn::balance(&token, &storage(ctx).custodian(ctx)).unwrap_or_default())
    }

    fn quote_deposit(
        ctx: &ViewContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        quote_deposit(ctx, amount_a, amount_b)
    }

    fn deposit(
        ctx: &ProcContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        let res = quote_deposit(ctx, amount_a, amount_b)?;
        let ledger = storage(ctx).lp_ledger();
        let custodian = storage(ctx).custodian(ctx);

        let user = ctx.signer().to_string();
        let bal = ledger.get(ctx, &user).unwrap_or_default();
        ledger.set(ctx, user, bal + res.lp_shares);
        storage(ctx).set_lp_total_supply(ctx, storage(ctx).lp_total_supply(ctx) + res.lp_shares);

        token_dyn::transfer(
            &storage(ctx).token_a(ctx),
            ctx.signer(),
            &custodian,
            res.deposit_a,
        )?;
        token_dyn::transfer(
            &storage(ctx).token_b(ctx),
            ctx.signer(),
            &custodian,
            res.deposit_b,
        )?;

        Ok(res)
    }

    fn quote_withdraw(ctx: &ViewContext, shares: Integer) -> Result<WithdrawResult, Error> {
        quote_withdraw(ctx, shares)
    }

    fn withdraw(ctx: &ProcContext, shares: Integer) -> Result<WithdrawResult, Error> {
        let res = quote_withdraw(ctx, shares)?;

        let ledger = storage(ctx).lp_ledger();
        let user = ctx.signer().to_string();

        let total = storage(ctx).lp_total_supply(ctx);
        let bal = ledger.get(ctx, &user).unwrap_or_default();

        if total < shares {
            return Err(Error::Message("insufficient total supply".to_string()));
        }
        if bal < shares {
            return Err(Error::Message("insufficient share balance".to_string()));
        }

        ledger.set(ctx, user.clone(), bal - shares);
        storage(ctx).set_lp_total_supply(ctx, total - shares);

        token_dyn::transfer(
            &storage(ctx).token_a(ctx),
            ctx.contract_signer(),
            &user,
            res.amount_a,
        )?;
        token_dyn::transfer(
            &storage(ctx).token_b(ctx),
            ctx.contract_signer(),
            &user,
            res.amount_b,
        )?;

        Ok(res)
    }

    fn quote_swap(
        ctx: &ViewContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        quote_swap(ctx, &token_in, amount_in)
    }

    fn swap(
        ctx: &ProcContext,
        token_in: ContractAddress,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        let token_out = token_out(ctx, &token_in)?;
        let amount_out = quote_swap(ctx, &token_in, amount_in)?;

        if amount_out < min_out {
            return Err(Error::Message(format!(
                "amount out ({}) below minimum",
                amount_out
            )));
        }

        token_dyn::transfer(
            &token_in,
            ctx.signer(),
            &storage(ctx).custodian(ctx),
            amount_in,
        )?;
        token_dyn::transfer(
            &token_out,
            ctx.contract_signer(),
            &ctx.signer().to_string(),
            amount_out,
        )?;

        Ok(amount_out)
    }
}
