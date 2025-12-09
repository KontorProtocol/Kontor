#![no_std]
contract!(name = "shared-account");

use stdlib::*;

interface!(name = "token", path = "token/wit");

#[derive(Clone, Default, Storage)]
struct Account {
    pub other_tenants: Map<String, bool>,
    pub balance: Integer,
    pub owner: String,
}

#[derive(Clone, Default, StorageRoot)]
struct SharedAccountStorage {
    pub accounts: Map<String, Account>,
}

fn authorized(signer: &Signer, account: &AccountModel) -> bool {
    account.owner() == signer.to_string()
        || account
            .other_tenants()
            .get(signer.to_string())
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

    fn open(
        ctx: &ProcContext,
        token: ContractAddress,
        n: Integer,
        other_tenants: Vec<String>,
    ) -> Result<String, Error> {
        let signer = ctx.signer();
        let balance =
            token::balance(&token, &signer.to_string()).ok_or(insufficient_balance_error())?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account_id = ctx.generate_id();
        ctx.model().accounts().set(
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
        token::transfer(&token, signer, &ctx.contract_signer().to_string(), n)?;
        Ok(account_id)
    }

    fn deposit(
        ctx: &ProcContext,
        token: ContractAddress,
        account_id: String,
        n: Integer,
    ) -> Result<(), Error> {
        let signer = ctx.signer();
        let balance =
            token::balance(&token, &signer.to_string()).ok_or(insufficient_balance_error())?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account = ctx
            .model()
            .accounts()
            .get(account_id)
            .ok_or(unknown_error())?;
        if !authorized(&signer, &account) {
            return Err(unauthorized_error());
        }
        account.update_balance(|b| b + n);
        token::transfer(&token, signer, &ctx.contract_signer().to_string(), n)
    }

    fn withdraw(
        ctx: &ProcContext,
        token: ContractAddress,
        account_id: String,
        n: Integer,
    ) -> Result<(), Error> {
        let signer = ctx.signer();
        let account = ctx
            .model()
            .accounts()
            .get(account_id)
            .ok_or(unknown_error())?;
        if !authorized(&signer, &account) {
            return Err(unauthorized_error());
        }
        let balance = account.balance();
        if balance < n {
            return Err(insufficient_balance_error());
        }
        account.set_balance(balance - n);
        token::transfer(&token, ctx.contract_signer(), &signer.to_string(), n)
    }

    fn balance(ctx: &ViewContext, account_id: String) -> Option<Integer> {
        ctx.model().accounts().get(account_id).map(|a| a.balance())
    }

    fn token_balance(
        _ctx: &ViewContext,
        token: ContractAddress,
        holder: String,
    ) -> Option<Integer> {
        token::balance(&token, &holder)
    }

    fn tenants(ctx: &ViewContext, account_id: String) -> Option<Vec<String>> {
        ctx.model().accounts().get(account_id).map(|a| {
            [a.owner()]
                .into_iter()
                .chain(a.other_tenants().keys())
                .collect()
        })
    }
}
