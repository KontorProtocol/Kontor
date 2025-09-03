use stdlib::*;

contract!(name = "shared-account");

import!(name = "token", height = 0, tx_index = 0, path = "token/wit");

#[derive(Clone, Default, Storage)]
struct Account {
    pub other_tenants: Map<String, bool>,
    pub balance: u64,
    pub owner: String,
}

#[derive(Clone, Default, Storage, Root)]
struct SharedAccountStorage {
    pub accounts: Map<String, Account>,
}

fn authorized(ctx: &ProcContext, account: &AccountWrapper) -> bool {
    account.owner(ctx) == ctx.signer().to_string()
        || account
            .other_tenants()
            .get(ctx, ctx.signer().to_string())
            .is_some_and(|b| b)
}

fn insufficient_balance_error() -> Error {
    Error::Message("insufficient balance".to_string())
}

fn unauthorized_error() -> Error {
    Error::Message("unauthorized".to_string())
}

fn unknown_error() -> Error {
    Error::Message("unknown account".to_string())
}

impl Guest for SharedAccount {
    fn init(ctx: &ProcContext) {
        SharedAccountStorage::default().init(ctx);
    }

    fn open(ctx: &ProcContext, n: u64, other_tenants: Vec<String>) -> Result<String, Error> {
        let balance =
            token::balance(&ctx.signer().to_string()).ok_or(insufficient_balance_error())?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account_id = crypto::generate_id();
        storage(ctx).accounts().set(
            ctx,
            account_id.clone(),
            Account {
                balance: n,
                owner: ctx.signer().to_string(),
                other_tenants: Map::new(
                    &other_tenants
                        .into_iter()
                        .map(|t| (t, true))
                        .collect::<Vec<_>>(),
                ),
            },
        );
        token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)?;
        Ok(account_id)
    }

    fn deposit(ctx: &ProcContext, account_id: String, n: u64) -> Result<(), Error> {
        let balance =
            token::balance(&ctx.signer().to_string()).ok_or(insufficient_balance_error())?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account = storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        account.set_balance(ctx, account.balance(ctx) + n);
        token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)
    }

    fn withdraw(ctx: &ProcContext, account_id: String, n: u64) -> Result<(), Error> {
        let account = storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        let balance = account.balance(ctx);
        if balance < n {
            return Err(insufficient_balance_error());
        }
        account.set_balance(ctx, balance - n);
        token::transfer(ctx.contract_signer(), &ctx.signer().to_string(), n)
    }

    fn balance(ctx: &ViewContext, account_id: String) -> Option<u64> {
        storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .map(|a| a.balance(ctx))
    }

    fn tenants(_ctx: &ViewContext, _account_id: String) -> Option<Vec<String>> {
        Some(vec!["foo".to_string(), "bar".to_string()])
    }
}
