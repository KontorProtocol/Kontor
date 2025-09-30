use stdlib::*;

contract!(name = "amm");

import!(name = "token", height = 0, tx_index = 0, path = "token/wit");

interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, StorageRoot)]
struct AMMStorage {
    pub token_a: ContractAddress,
    pub token_b: ContractAddress,
    pub custody_addr: String,
    pub fee_bps: Integer,

    pub lp_total_supply: Integer,
    pub lp_ledger: Map<String, Integer>,
}

impl Default for AMMStorage {
    fn default() -> Self {
        Self {
            token_a: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            token_b: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            custody_addr: "".to_string(),
            fee_bps: 0.into(),
            lp_total_supply: 0.into(),
            lp_ledger: Map::default(),
        }
    }
}

fn token_string(token: &ContractAddress) -> String {
    format!("{}_{}_{}", token.name, token.height, token.tx_index)
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
    fn token_out<C: ReadContext>(
        ctx: &C,
        token_in: &ContractAddress,
    ) -> Result<ContractAddress, Error> {
        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);
        if token_string(token_in) == token_string(&token_a) {
            Ok(token_b)
        } else if token_string(token_in) == token_string(&token_b) {
            Ok(token_a)
        } else {
            Err(Error::Message(format!("token {} not in pair", token_in)))
        }
    }

    fn quote_swap<C: ReadContext>(
        ctx: &C,
        token_in: &ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        let token_out = Self::token_out(ctx, token_in)?;
        let addr = storage(ctx).custody_addr(ctx);

        let bal_in = token_dyn::balance(token_in, &addr).unwrap_or_default();
        let bal_out = token_dyn::balance(&token_out, &addr).unwrap_or_default();
        let fee_bps = storage(ctx).fee_bps(ctx);

        calc_swap_result(amount_in, bal_in, bal_out, fee_bps)
    }

    fn quote_deposit<C: ReadContext>(
        ctx: &C,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        check_amount_positive(amount_a)?;
        check_amount_positive(amount_b)?;

        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);
        let lp_supply = storage(ctx).lp_total_supply(ctx);

        let addr = storage(ctx).custody_addr(ctx);
        let bal_a = token_dyn::balance(&token_a, &addr).unwrap_or_default();
        let bal_b = token_dyn::balance(&token_b, &addr).unwrap_or_default();

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

    fn quote_withdraw<C: ReadContext>(ctx: &C, shares: Integer) -> Result<WithdrawResult, Error> {
        check_amount_positive(shares)?;

        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);
        let lp_supply = storage(ctx).lp_total_supply(ctx);

        let addr = storage(ctx).custody_addr(ctx);
        let bal_a = token_dyn::balance(&token_a, &addr).unwrap_or_default();
        let bal_b = token_dyn::balance(&token_b, &addr).unwrap_or_default();

        Ok(WithdrawResult {
            amount_a: shares * bal_a / lp_supply,
            amount_b: shares * bal_b / lp_supply,
        })
    }
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        AMMStorage::default().init(ctx);
    }

    fn create(
        ctx: &ProcContext,
        token_a: ContractAddress,
        amount_a: Integer,
        token_b: ContractAddress,
        amount_b: Integer,
        fee_bps: Integer,
    ) -> Result<Integer, Error> {
        if storage(ctx).lp_total_supply(ctx) > 0.into() {
            return Err(Error::Message("already created".to_string()));
        }

        check_amount_positive(amount_a)?;
        check_amount_positive(amount_b)?;

        let lp_shares = numbers::sqrt_integer(amount_a * amount_b)?;
        check_amount_positive(lp_shares)?;

        let custody_addr = ctx.contract_signer().to_string();
        token_dyn::transfer(&token_a, ctx.signer(), &custody_addr, amount_a)?;
        token_dyn::transfer(&token_b, ctx.signer(), &custody_addr, amount_b)?;

        let admin = ctx.signer().to_string();
        let ledger = storage(ctx).lp_ledger();
        ledger.set(ctx, admin, lp_shares);

        storage(ctx).set_token_a(ctx, token_a);
        storage(ctx).set_token_b(ctx, token_b);
        storage(ctx).set_custody_addr(ctx, custody_addr);
        storage(ctx).set_lp_total_supply(ctx, lp_shares);
        storage(ctx).set_fee_bps(ctx, fee_bps);

        Ok(lp_shares)
    }

    fn fee(ctx: &ViewContext) -> Integer {
        storage(ctx).fee_bps(ctx)
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        let ledger = storage(ctx).lp_ledger();
        ledger.get(ctx, acc)
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
        Self::token_out(ctx, &token)?;
        let addr = storage(ctx).custody_addr(ctx);
        Ok(token_dyn::balance(&token, &addr).unwrap_or_default())
    }

    fn quote_deposit(
        ctx: &ViewContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        Self::quote_deposit(ctx, amount_a, amount_b)
    }

    fn deposit(
        ctx: &ProcContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        let res = Self::quote_deposit(ctx, amount_a, amount_b)?;

        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);

        let addr = storage(ctx).custody_addr(ctx);
        token_dyn::transfer(&token_a, ctx.signer(), &addr, res.deposit_a)?;
        token_dyn::transfer(&token_b, ctx.signer(), &addr, res.deposit_b)?;

        let ledger = storage(ctx).lp_ledger();
        let user = ctx.signer().to_string();
        let bal = ledger.get(ctx, &user).unwrap_or_default();
        ledger.set(ctx, user, bal + res.lp_shares);

        let total = storage(ctx).lp_total_supply(ctx);
        storage(ctx).set_lp_total_supply(ctx, total + res.lp_shares);

        Ok(res)
    }

    fn quote_withdraw(ctx: &ViewContext, shares: Integer) -> Result<WithdrawResult, Error> {
        Self::quote_withdraw(ctx, shares)
    }

    fn withdraw(ctx: &ProcContext, shares: Integer) -> Result<WithdrawResult, Error> {
        let res = Self::quote_withdraw(ctx, shares)?;

        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);

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

        token_dyn::transfer(&token_a, ctx.contract_signer(), &user, res.amount_a)?;
        token_dyn::transfer(&token_b, ctx.contract_signer(), &user, res.amount_b)?;

        Ok(res)
    }

    fn quote_swap(
        ctx: &ViewContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        Self::quote_swap(ctx, &token_in, amount_in)
    }

    fn swap(
        ctx: &ProcContext,
        token_in: ContractAddress,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        let token_out = Self::token_out(ctx, &token_in)?;

        let amount_out = Self::quote_swap(ctx, &token_in, amount_in)?;
        if amount_out >= min_out {
            let user_addr = ctx.signer().to_string();
            let addr = storage(ctx).custody_addr(ctx);

            token_dyn::transfer(&token_in, ctx.signer(), &addr, amount_in)?;
            token_dyn::transfer(&token_out, ctx.contract_signer(), &user_addr, amount_out)?;
            Ok(amount_out)
        } else {
            Err(Error::Message(format!(
                "amount out ({}) below minimum",
                amount_out
            )))
        }
    }
}
