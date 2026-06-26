#![no_std]
contract!(name = "shared-account");

use stdlib::*;

interface!(name = "token", path = "../test-token/wit");

#[derive(Clone, Default, Storage)]
struct Account {
    pub other_tenants: Map<Holder, bool>,
    pub balance: Integer,
    pub owner: String,
}

#[derive(Clone, Default, StorageRoot)]
struct SharedAccountStorage {
    pub accounts: Map<String, Account>,
}

fn authorized(signer: &Signer, account: &AccountModel) -> bool {
    let holder: Holder = signer.as_holder();
    account.owner() == signer.key() || account.other_tenants().get(&holder).is_some_and(|b| b)
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
    fn init(ctx: &ProcContext) -> Contract {
        SharedAccountStorage::default().init(ctx);
        ctx.contract()
    }

    fn open(
        ctx: &ProcContext,
        token: ContractAddress,
        n: Integer,
        other_tenants: Vec<String>,
    ) -> Result<String, Error> {
        let signer = ctx.signer();
        // test-token now conforms to the native token interface (holder-ref keys,
        // decimal amounts). This contract's balances stay integer; convert at the
        // boundary — a Signer is `Into<HolderRef>`, balances are whole.
        let balance: Integer = token::balance(&token, &signer)
            .ok_or(insufficient_balance_error())?
            .try_into()?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account_id = ctx.generate_id();
        let tenant_holders: Vec<(Holder, bool)> = other_tenants
            .into_iter()
            .map(|t| (t.parse::<Holder>().expect("invalid holder"), true))
            .collect();
        ctx.model().accounts().set(
            &account_id,
            Account {
                balance: n,
                owner: ctx.signer().key(),
                other_tenants: Map::new(&tenant_holders),
            },
        );
        token::transfer(&token, signer, ctx.contract_signer(), n.try_into()?)?;
        Ok(account_id)
    }

    fn deposit(
        ctx: &ProcContext,
        token: ContractAddress,
        account_id: String,
        n: Integer,
    ) -> Result<(), Error> {
        let signer = ctx.signer();
        let balance: Integer = token::balance(&token, &signer)
            .ok_or(insufficient_balance_error())?
            .try_into()?;
        if balance < n {
            return Err(insufficient_balance_error());
        }
        let account = ctx
            .model()
            .accounts()
            .get(&account_id)
            .ok_or(unknown_error())?;
        if !authorized(&signer, &account) {
            return Err(unauthorized_error());
        }
        account.update_balance(|b| b + n);
        token::transfer(&token, signer, ctx.contract_signer(), n.try_into()?)?;
        Ok(())
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
            .get(&account_id)
            .ok_or(unknown_error())?;
        if !authorized(&signer, &account) {
            return Err(unauthorized_error());
        }
        let balance = account.balance();
        if balance < n {
            return Err(insufficient_balance_error());
        }
        account.set_balance(balance - n);
        token::transfer(&token, ctx.contract_signer(), &signer, n.try_into()?)?;
        Ok(())
    }

    fn balance(ctx: &ViewContext, account_id: String) -> Option<Integer> {
        ctx.model().accounts().get(&account_id).map(|a| a.balance())
    }

    fn token_balance(
        _ctx: &ViewContext,
        token: ContractAddress,
        holder: String,
    ) -> Option<Integer> {
        let holder: Holder = holder.parse().ok()?;
        token::balance(&token, &holder).and_then(|d| d.try_into().ok())
    }

    fn tenants(ctx: &ViewContext, account_id: String) -> Option<Vec<String>> {
        ctx.model().accounts().get(&account_id).map(|a| {
            [a.owner()]
                .into_iter()
                .chain(a.other_tenants().keys().map(|h| h.to_string()))
                .collect()
        })
    }
}
