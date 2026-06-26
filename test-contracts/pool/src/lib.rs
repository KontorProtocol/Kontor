#![no_std]
contract!(name = "pool");

use stdlib::*;

interface!(name = "token_dyn", path = "../test-token/wit");

#[derive(Clone, StorageRoot)]
struct PoolStorage {
    pub token_a: ContractAddress,
    pub token_b: ContractAddress,
    pub fee_bps: Integer,

    pub lp_total_supply: Integer,
    pub lp_ledger: Map<Holder, Integer>,

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

        let lp_shares = (amount_a * amount_b).sqrt()?;
        let custodian: Holder = (&ctx.contract_signer()).into();
        let signer_holder: Holder = (&ctx.signer()).into();
        let pool = PoolStorage {
            token_a: token_a.clone(),
            token_b: token_b.clone(),
            fee_bps,
            lp_total_supply: lp_shares,
            lp_ledger: Map::new(&[(signer_holder, lp_shares)]),
            custodian: custodian.to_string(),
        };

        token_dyn::transfer(&token_a, ctx.signer(), &custodian, amount_a.try_into()?)?;
        token_dyn::transfer(&token_b, ctx.signer(), &custodian, amount_b.try_into()?)?;

        Ok(pool)
    }
}

fn token_out(
    token_a: &ContractAddress,
    token_b: &ContractAddress,
    token_in: &ContractAddress,
) -> Result<ContractAddress, Error> {
    if token_in == token_a {
        Ok(token_b.clone())
    } else if token_in == token_b {
        Ok(token_a.clone())
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

// test-token now conforms to the native token's interface (holder-ref keys, decimal
// amounts). Pool math stays integer; these convert at the token boundary. The stored
// `custodian` is a holder KEY string (the pool's own contract-signer) — parse it back
// to a `Holder` (which is `Into<HolderRef>`) for the typed token calls.
fn custodian_holder(key: &str) -> Result<Holder, Error> {
    key.parse()
        .map_err(|_| Error::Message("invalid custodian holder".to_string()))
}

// A custodian balance, read through the conforming token (decimal) and narrowed back
// to the integer the pool math uses. Balances are whole, so the conversion is exact.
fn token_balance_int(token: &ContractAddress, holder: &Holder) -> Result<Integer, Error> {
    Ok(match token_dyn::balance(token, holder) {
        Some(d) => d.try_into()?,
        None => Integer::default(),
    })
}

impl Guest for Pool {
    // Dummy implementation for testing purposes.
    fn init(ctx: &ProcContext) -> Contract {
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
        ctx.contract()
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
        Ok(ctx.model().lp_total_supply())
    }

    fn fee(ctx: &ViewContext) -> Integer {
        ctx.model().fee_bps()
    }

    // LP-share balance/transfer conform to the token interface (holder-ref + decimal)
    // so the pool can be driven as a token. Shares are stored as integers; convert at
    // the boundary.
    fn balance(ctx: &ViewContext, acc: HolderRef) -> Option<Decimal> {
        let holder: Holder = acc.try_into().ok()?;
        ctx.model()
            .lp_ledger()
            .get(&holder)
            .and_then(|n| n.try_into().ok())
    }

    fn transfer(ctx: &ProcContext, dst: HolderRef, amt: Decimal) -> Result<Transfer, Error> {
        let from: Holder = (&ctx.signer()).into();
        let to: Holder = dst.try_into()?;
        let n: Integer = amt.try_into()?;
        let ledger = ctx.model().lp_ledger();

        let from_balance = ledger.get(&from).unwrap_or_default();
        let to_balance = ledger.get(&to).unwrap_or_default();
        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(&from, from_balance - n);
        ledger.set(&to, to_balance + n);
        Ok(Transfer {
            src: from.as_ref(),
            dst: to.as_ref(),
            amt,
        })
    }

    fn token_balance(ctx: &ViewContext, token: ContractAddress) -> Result<Integer, Error> {
        let model = ctx.model();
        token_out(&model.token_a(), &model.token_b(), &token)?;
        let custodian = custodian_holder(&model.custodian())?;
        token_balance_int(&token, &custodian)
    }

    fn quote_deposit(
        ctx: &ViewContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        validate_amount(amount_a)?;
        validate_amount(amount_b)?;

        let model = ctx.model();
        let token_a = model.token_a();
        let token_b = model.token_b();
        let lp_supply = model.lp_total_supply();

        let custodian = custodian_holder(&model.custodian())?;
        let bal_a = token_balance_int(&token_a, &custodian)?;
        let bal_b = token_balance_int(&token_b, &custodian)?;

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

    fn deposit(
        ctx: &ProcContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<DepositResult, Error> {
        let res = Self::quote_deposit(&ctx.view_context(), amount_a, amount_b)?;
        let model = ctx.model();
        let ledger = model.lp_ledger();
        let custodian = model.custodian();

        let user: Holder = (&ctx.signer()).into();
        let bal = ledger.get(&user).unwrap_or_default();
        ledger.set(&user, bal + res.lp_shares);
        model.update_lp_total_supply(|t| t + res.lp_shares);

        let custodian = custodian_holder(&custodian)?;
        token_dyn::transfer(
            &model.token_a(),
            ctx.signer(),
            &custodian,
            res.deposit_a.try_into()?,
        )?;
        token_dyn::transfer(
            &model.token_b(),
            ctx.signer(),
            &custodian,
            res.deposit_b.try_into()?,
        )?;

        Ok(res)
    }

    fn quote_withdraw(ctx: &ViewContext, shares: Integer) -> Result<WithdrawResult, Error> {
        validate_amount(shares)?;

        let model = ctx.model();
        let token_a = model.token_a();
        let token_b = model.token_b();
        let lp_supply = model.lp_total_supply();

        let custodian = custodian_holder(&model.custodian())?;
        let bal_a = token_balance_int(&token_a, &custodian)?;
        let bal_b = token_balance_int(&token_b, &custodian)?;

        Ok(WithdrawResult {
            amount_a: shares * bal_a / lp_supply,
            amount_b: shares * bal_b / lp_supply,
        })
    }

    fn withdraw(ctx: &ProcContext, shares: Integer) -> Result<WithdrawResult, Error> {
        let res = Self::quote_withdraw(&ctx.view_context(), shares)?;

        let model = ctx.model();
        let ledger = model.lp_ledger();
        let user: Holder = (&ctx.signer()).into();

        let total = model.lp_total_supply();
        let bal = ledger.get(&user).unwrap_or_default();

        if total < shares {
            return Err(Error::Message("insufficient total supply".to_string()));
        }
        if bal < shares {
            return Err(Error::Message("insufficient share balance".to_string()));
        }

        ledger.set(&user, bal - shares);
        model.set_lp_total_supply(total - shares);

        token_dyn::transfer(
            &model.token_a(),
            ctx.contract_signer(),
            &user,
            res.amount_a.try_into()?,
        )?;
        token_dyn::transfer(
            &model.token_b(),
            ctx.contract_signer(),
            &user,
            res.amount_b.try_into()?,
        )?;

        Ok(res)
    }

    fn quote_swap(
        ctx: &ViewContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        let model = ctx.model();
        let custodian = custodian_holder(&model.custodian())?;
        let bal_in = token_balance_int(&token_in, &custodian)?;
        let bal_out = token_balance_int(
            &token_out(&model.token_a(), &model.token_b(), &token_in)?,
            &custodian,
        )?;
        calc_swap_result(amount_in, bal_in, bal_out, model.fee_bps())
    }

    fn swap(
        ctx: &ProcContext,
        token_in: ContractAddress,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        let model = ctx.model();
        let token_out = token_out(&model.token_a(), &model.token_b(), &token_in)?;
        let amount_out = Self::quote_swap(&ctx.view_context(), token_in.clone(), amount_in)?;

        if amount_out < min_out {
            return Err(Error::Message(format!(
                "amount out ({}) below minimum",
                amount_out
            )));
        }

        let custodian = custodian_holder(&model.custodian())?;
        let recipient: Holder = (&ctx.signer()).into();
        token_dyn::transfer(&token_in, ctx.signer(), &custodian, amount_in.try_into()?)?;
        token_dyn::transfer(
            &token_out,
            ctx.contract_signer(),
            &recipient,
            amount_out.try_into()?,
        )?;

        Ok(amount_out)
    }
}
