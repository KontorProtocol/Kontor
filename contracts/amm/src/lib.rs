use stdlib::*;

// Constant‑product AMM for token pair A/B.
// Fees are 0.3 % (997/1000).

contract!(name = "amm");

const MINIMUM_LIQUIDITY: i64 = 1000;

#[derive(Clone, Default, StorageRoot)]
struct AmmStorage {
    pub reserve_a: Integer,
    pub reserve_b: Integer,
    pub total_shares: Integer,        // total LP tokens
    pub shares: Map<String, Integer>, // LP balance per account
}

fn sqrt(n: Integer) -> Integer {
    // integer square root using Newton's method
    if n <= 0.into() {
        return 0.into();
    }
    let mut x = n.clone();
    let mut y = (x.clone() + 1.into()) / 2.into();
    while y < x {
        x = y.clone();
        y = (x.clone() + n.clone() / x) / 2.into();
    }
    x
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        AmmStorage::default().init(ctx);
    }

    fn add_liquidity(
        ctx: &ProcContext,
        amount_a: Integer,
        amount_b: Integer,
    ) -> Result<Integer, Error> {
        if amount_a <= 0.into() || amount_b <= 0.into() {
            return Err(Error::new("invalid deposit"));
        }

        let reserve_a = storage(ctx).reserve_a(ctx);
        let reserve_b = storage(ctx).reserve_b(ctx);
        let total_shares = storage(ctx).total_shares(ctx);

        // mint LP tokens
        let mint = if total_shares == 0.into() {
            let initial_mint = sqrt(amount_a * amount_b);
            // Enforce minimum liquidity on first deposit
            if initial_mint < MINIMUM_LIQUIDITY.into() {
                return Err(Error::new("initial liquidity below minimum"));
            }
            initial_mint
        } else {
            let share_a = amount_a * total_shares / reserve_a;
            let share_b = amount_b * total_shares / reserve_b;
            share_a.min(share_b)
        };

        if mint <= 0.into() {
            return Err(Error::new("insufficient liquidity minted"));
        }

        storage(ctx).set_reserve_a(ctx, reserve_a + amount_a);
        storage(ctx).set_reserve_b(ctx, reserve_b + amount_b);
        storage(ctx).set_total_shares(ctx, total_shares + mint);

        let addr = ctx.signer().to_string();
        let ledger = storage(ctx).shares();
        let current = ledger.get(ctx, &addr).unwrap_or_default();
        ledger.set(ctx, addr, current + mint);

        Ok(mint)
    }

    fn remove_liquidity(ctx: &ProcContext, share: Integer) -> Result<(Integer, Integer), Error> {
        if share <= 0.into() {
            return Err(Error::new("invalid share amount"));
        }

        let addr = ctx.signer().to_string();
        let ledger = storage(ctx).shares();
        let current = ledger.get(ctx, &addr).unwrap_or_default();
        if current < share {
            return Err(Error::new("insufficient share balance"));
        }

        let reserve_a = storage(ctx).reserve_a(ctx);
        let reserve_b = storage(ctx).reserve_b(ctx);
        let total_shares = storage(ctx).total_shares(ctx);

        let amount_a = reserve_a * share / total_shares;
        let amount_b = reserve_b * share / total_shares;

        ledger.set(ctx, addr, current - share);
        storage(ctx).set_reserve_a(ctx, reserve_a - amount_a);
        storage(ctx).set_reserve_b(ctx, reserve_b - amount_b);
        storage(ctx).set_total_shares(ctx, total_shares - share);

        Ok((amount_a, amount_b))
    }

    fn swap_a_for_b(
        ctx: &ProcContext,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        if amount_in <= 0.into() {
            return Err(Error::new("invalid input"));
        }
        if min_out <= 0.into() {
            return Err(Error::new("min_out must be positive"));
        }

        let reserve_a = storage(ctx).reserve_a(ctx);
        let reserve_b = storage(ctx).reserve_b(ctx);
        if reserve_a == 0.into() || reserve_b == 0.into() {
            return Err(Error::new("no liquidity"));
        }

        let amount_in_fee = amount_in * 997.into();
        let num = amount_in_fee * reserve_b;
        let den = reserve_a * 1000.into() + amount_in_fee;
        let amount_out = num / den;

        if amount_out < min_out {
            return Err(Error::new("slippage exceeded"));
        }

        storage(ctx).set_reserve_a(ctx, reserve_a + amount_in);
        storage(ctx).set_reserve_b(ctx, reserve_b - amount_out);
        Ok(amount_out)
    }

    fn swap_b_for_a(
        ctx: &ProcContext,
        amount_in: Integer,
        min_out: Integer,
    ) -> Result<Integer, Error> {
        if amount_in <= 0.into() {
            return Err(Error::new("invalid input"));
        }
        if min_out <= 0.into() {
            return Err(Error::new("min_out must be positive"));
        }

        let reserve_a = storage(ctx).reserve_a(ctx);
        let reserve_b = storage(ctx).reserve_b(ctx);
        if reserve_a == 0.into() || reserve_b == 0.into() {
            return Err(Error::new("no liquidity"));
        }

        let amount_in_fee = amount_in * 997.into();
        let num = amount_in_fee * reserve_a;
        let den = reserve_b * 1000.into() + amount_in_fee;
        let amount_out = num / den;

        if amount_out < min_out {
            return Err(Error::new("slippage exceeded"));
        }

        storage(ctx).set_reserve_b(ctx, reserve_b + amount_in);
        storage(ctx).set_reserve_a(ctx, reserve_a - amount_out);
        Ok(amount_out)
    }

    fn transfer_shares(ctx: &ProcContext, to: String, amount: Integer) -> Result<(), Error> {
        if amount <= 0.into() {
            return Err(Error::new("invalid transfer amount"));
        }

        let from = ctx.signer().to_string();
        if from == to {
            return Err(Error::new("cannot transfer to self"));
        }

        let ledger = storage(ctx).shares();
        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        if from_balance < amount {
            return Err(Error::new("insufficient share balance"));
        }

        let to_balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, from, from_balance - amount);
        ledger.set(ctx, to.clone(), to_balance + amount);

        Ok(())
    }

    fn get_reserves(ctx: &ViewContext) -> (Integer, Integer) {
        (storage(ctx).reserve_a(ctx), storage(ctx).reserve_b(ctx))
    }

    fn share_of(ctx: &ViewContext, addr: String) -> Integer {
        storage(ctx).shares().get(ctx, addr).unwrap_or_default()
    }
}
