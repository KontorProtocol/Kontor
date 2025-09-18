use stdlib::*;

contract!(name = "shared-account");

// TODO: Fix import! and interface! macros for cross-contract calls
// import!(name = "token", height = 0, tx_index = 0, path = "token/wit");
// interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, Default, Storage)]
struct Account {
    pub other_tenants: Map<String, bool>,
    pub balance_str: String,  // Store as string since Integer doesn't impl Store
    pub owner: String,
}

#[derive(Clone, Default, StorageRoot)]
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

fn parse_integer(_s: &str) -> Integer {
    // Simple parsing - just get a default for now
    // In production, would parse the debug format
    Integer::default()
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

    fn open(ctx: &ProcContext, n: Integer, other_tenants: Vec<String>) -> Result<String, Error> {
        // TODO: Re-enable when import! is fixed
        // let balance =
        //     token::balance(&ctx.signer().to_string()).ok_or(insufficient_balance_error())?;
        // if balance < n {
        //     return Err(insufficient_balance_error());
        // }
        let account_id = crypto::generate_id();
        storage(ctx).accounts().set(
            ctx,
            account_id.clone(),
            Account {
                balance_str: format!("{:?}", n),
                owner: ctx.signer().to_string(),
                other_tenants: Map::new(
                    &other_tenants
                        .into_iter()
                        .map(|t| (t, true))
                        .collect::<Vec<_>>(),
                ),
            },
        );
        // TODO: Re-enable when import! is fixed
        // token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)?;
        Ok(account_id)
    }

    fn deposit(ctx: &ProcContext, account_id: String, n: Integer) -> Result<(), Error> {
        // TODO: Re-enable when import! is fixed
        // let balance =
        //     token::balance(&ctx.signer().to_string()).ok_or(insufficient_balance_error())?;
        // if balance < n {
        //     return Err(insufficient_balance_error());
        // }
        let account = storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        let current_balance = parse_integer(&account.balance_str(ctx));
        let new_balance = numbers::add_integer(current_balance, n);
        account.set_balance_str(ctx, format!("{:?}", new_balance));
        // TODO: Re-enable when import! is fixed
        // token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)
        Ok(())
    }

    fn withdraw(ctx: &ProcContext, account_id: String, n: Integer) -> Result<(), Error> {
        let account = storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        let balance = parse_integer(&account.balance_str(ctx));
        if numbers::cmp_integer(balance.clone(), n.clone()) == numbers::Ordering::Less {
            return Err(insufficient_balance_error());
        }
        account.set_balance_str(ctx, format!("{:?}", numbers::sub_integer(balance, n)));
        // TODO: Re-enable when import! is fixed
        // token::transfer(ctx.contract_signer(), &ctx.signer().to_string(), n)
        Ok(())
    }

    fn balance(ctx: &ViewContext, account_id: String) -> Option<Integer> {
        storage(ctx)
            .accounts()
            .get(ctx, account_id)
            .map(|a| parse_integer(&a.balance_str(ctx)))
    }

    fn token_balance(
        _ctx: &ViewContext,
        _token: ContractAddress,
        _holder: String,
    ) -> Option<Integer> {
        // TODO: Re-enable when interface! is fixed
        // token_dyn::balance(&token, &holder)
        None
    }

    fn tenants(ctx: &ViewContext, account_id: String) -> Option<Vec<String>> {
        storage(ctx).accounts().get(ctx, account_id).map(|a| {
            [a.owner(ctx)]
                .into_iter()
                .chain(a.other_tenants().keys(ctx))
                .collect()
        })
    }
}