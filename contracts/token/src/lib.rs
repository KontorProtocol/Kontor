#![allow(dead_code)]

use fastnum::{ D256, decimal::Context };

macros::contract!(name = "token");

#[derive(Clone, Store, Wrapper, Root)]
struct TokenStorage {
    pub ledger: Map<String, D256>,
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage {
            ledger: Map::default(),
        }
        .init(ctx);
    }

    fn mint(ctx: &ProcContext, n: String) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        // TODO parsing the number from a string adds the possibility of parsing
        // errors to lots of functions; it would be nice if those were caught elsewhere
        // and not cluttering up the contract-code
        let v = D256::from_str(&n, Context::default()).unwrap();

        let balance = ledger.get(ctx, to.clone()).unwrap_or_default();
        ledger.set(ctx, to, balance + v);
    }

    fn transfer(ctx: &ProcContext, to: String, n: String) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, from.clone()).unwrap_or_default();
        let to_balance = ledger.get(ctx, to.clone()).unwrap_or_default();

        let v = D256::from_str(&n, Context::default())?;
        if from_balance < v {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, from_balance - v);
        ledger.set(ctx, to, to_balance + v);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<String> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|v| v.to_string())
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<String> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|v| v.log10().trunc_with_scale(10).to_string())
    }
}
