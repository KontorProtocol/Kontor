use stdlib::*;

contract!(name = "amm");

import!(name = "token", height = 0, tx_index = 0, path = "token/wit");

interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, StorageRoot)]
struct AMMStorage {
    pub token_a: ContractAddress,
    pub token_b: ContractAddress,
    pub custody_addr: String,
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
        }
    }
}

fn token_string(token: &ContractAddress) -> String {
    format!("{}_{}_{}", token.name, token.height, token.tx_index)
}

fn pair_id(token_a: &ContractAddress, token_b: &ContractAddress) -> String {
    format!("{}::{}", token_string(token_a), token_string(token_b))
}

fn calc_swap_result(
    amount_in: Integer,
    bal_in: Integer,
    bal_out: Integer,
) -> Option<Integer> {

    let zero = Integer::default();
    if bal_in == zero || bal_out == zero {
        return None;
    }
    if amount_in == zero {
        return Some(zero);
    }

    let k = bal_in * bal_out;
    let new_bal_in = bal_in + amount_in;

    Some(((bal_out * new_bal_in) - k) / new_bal_in)
}

impl Amm {
    fn quote_swap(
        ctx: &ViewContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Option<Integer> {
        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);
        let addr = storage(ctx).custody_addr(ctx);

        let bal_a = token_dyn::balance(&token_a, &addr).unwrap_or_default();
        let bal_b = token_dyn::balance(&token_b, &addr).unwrap_or_default();

        if token_string(&token_in) == token_string(&token_a) {
            calc_swap_result(amount_in, bal_a, bal_b)
        } else if token_string(&token_in) == token_string(&token_b) {
            calc_swap_result(amount_in, bal_b, bal_a)
        } else {
            None
        }
    }
}

impl Guest for Amm {
    fn init(ctx: &ProcContext) {
        AMMStorage::default().init(ctx);
    }

    fn create(ctx: &ProcContext, token_a: ContractAddress, token_b: ContractAddress) {
        let id = pair_id(&token_a, &token_b);
        let custody_addr = ctx.contract_signer().to_string();

        //   transfer_token_from_user_to_pool(ctx, &token_a, init_a, &custody_address)?;
        //   transfer_token_from_user_to_pool(ctx, &token_b, init_b, &custody_address)?;
        //        token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)
        //        token::transfer(token_a, &ctx.contract_signer().to_string(), n)

        AMMStorage {
            token_a,
            token_b,
            custody_addr,
        }
        .init(ctx);
    }

    fn token_balance(ctx: &ViewContext, token: ContractAddress) -> Option<Integer> {
        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);

        if token_string(&token) != token_string(&token_a) &&
            token_string(&token) != token_string(&token_b) {
            return None;
        }

        let addr = storage(ctx).custody_addr(ctx);
        token_dyn::balance(&token, &addr)
    }

    fn quote_swap(
        ctx: &ViewContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Option<Integer> {
        Self::quote_swap(ctx, token_in, amount_in)
    }

    fn swap(
        ctx: &ProcContext,
        token_in: ContractAddress,
        amount_in: Integer,
    ) -> Result<Integer, Error> {
        let user_addr = ctx.signer().to_string();

        let token_a = storage(ctx).token_a(ctx);
        let token_b = storage(ctx).token_b(ctx);
        let addr = storage(ctx).custody_addr(ctx);

        let bal_a = token_dyn::balance(&token_a, &addr).unwrap_or_default();
        let bal_b = token_dyn::balance(&token_b, &addr).unwrap_or_default();

        let (token_out, bal_in, bal_out) = if token_string(&token_in) == token_string(&token_a) {
            (token_b, bal_a, bal_b)
        } else if token_string(&token_in) == token_string(&token_b) {
            (token_a, bal_b, bal_a)
        } else {
            return Err(Error::Message("token not in pair".to_string()))
        };

        if let Some(amount_out) = calc_swap_result(amount_in, bal_in, bal_out) {
            token_dyn::transfer(&token_in, ctx.signer(), &addr, amount_in)?;
            token_dyn::transfer(&token_out, ctx.contract_signer(), &user_addr, amount_out)?;
            return Ok(amount_out);
        } else {
            return Err(Error::Message("swap failed".to_string()));
        }
    }


    fn custody_address(ctx: &ViewContext) -> String {
        storage(ctx).custody_addr(ctx)
    }
}
