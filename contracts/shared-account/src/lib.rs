use stdlib::*;

contract!(name = "shared-account");

// Import functions we need
use kontor::built_in::numbers as numbers;
use kontor::built_in::crypto as crypto;

// TODO: Fix import! and interface! macros for cross-contract calls
// import!(name = "token", height = 0, tx_index = 0, path = "token/wit");
// interface!(name = "token_dyn", path = "token/wit");

#[derive(Clone, Default)]
struct Account {
    pub other_tenants: Map<String, bool>,
    pub balance: Integer,
    pub owner: String,
}


#[derive(Clone, Default)]
struct SharedAccountStorage {
    pub accounts: Map<String, Account>,
}

// Manual storage implementation
fn storage<C>(_ctx: &C) -> SharedAccountStorage {
    SharedAccountStorage::default()
}

impl SharedAccountStorage {
    fn init(&self, _ctx: &impl WriteContext) {
        // Nothing to initialize for a map
    }

    fn accounts(&self) -> MapAccessor<String, Account> {
        MapAccessor::new("accounts")
    }
}

// MapAccessor helper
struct MapAccessor<K, V> {
    base_path: String,
    _phantom: std::marker::PhantomData<(K, V)>,
}

impl<K: ToString + FromString, V: Store + Retrieve + Default> MapAccessor<K, V> {
    fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
            _phantom: std::marker::PhantomData,
        }
    }

    fn get(&self, ctx: &impl ReadContext, key: &K) -> Option<V> {
        let mut path: DotPathBuf = self.base_path.parse().unwrap();
        path = path.push(key.to_string());
        V::__get(ctx, path)
    }

    fn set(&self, ctx: &impl WriteContext, key: K, value: V) {
        let mut path: DotPathBuf = self.base_path.parse().unwrap();
        path = path.push(key.to_string());
        V::__set(ctx, path, value);
    }
}

// Manual Storage implementation for Account
impl Store for Account {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: Self) {
        // Store each field
        ctx.__set_str(&format!("{}.owner", path), &value.owner);
        <Integer as Store>::__set(ctx, format!("{}.balance", path).parse().unwrap(), value.balance);
        // Store other_tenants map entries
        for (k, v) in value.other_tenants.entries.iter() {
            ctx.__set_bool(&format!("{}.other_tenants.{}", path, k), *v);
        }
    }
}

impl Retrieve for Account {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        let owner = ctx.__get_str(&format!("{}.owner", path))?;
        let balance = <Integer as Retrieve>::__get(ctx, format!("{}.balance", path).parse().unwrap())?;

        // For other_tenants, we need to iterate over keys - simplified for now
        let mut other_tenants = Map::default();
        // TODO: Properly iterate over keys in other_tenants

        Some(Account {
            owner,
            balance,
            other_tenants,
        })
    }
}

fn authorized(ctx: &ProcContext, account: &Account) -> bool {
    account.owner == ctx.signer().to_string()
        || account
            .other_tenants
            .entries.iter()
            .find(|(k, _)| k == &ctx.signer().to_string())
            .map(|(_, v)| v)
            .is_some_and(|b| *b)
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
        let mut account = storage(ctx)
            .accounts()
            .get(ctx, &account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        let current_balance = account.balance;
        let new_balance = numbers::add_integer(current_balance, n);
        account.balance = new_balance;
        storage(ctx).accounts().set(ctx, account_id, account);
        // TODO: Re-enable when import! is fixed
        // token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), n)
        Ok(())
    }

    fn withdraw(ctx: &ProcContext, account_id: String, n: Integer) -> Result<(), Error> {
        let mut account = storage(ctx)
            .accounts()
            .get(ctx, &account_id)
            .ok_or(unknown_error())?;
        if !authorized(ctx, &account) {
            return Err(unauthorized_error());
        }
        let balance = account.balance;
        if numbers::cmp_integer(balance.clone(), n.clone()) == numbers::Ordering::Less {
            return Err(insufficient_balance_error());
        }
        account.balance = numbers::sub_integer(balance, n);
        storage(ctx).accounts().set(ctx, account_id, account);
        // TODO: Re-enable when import! is fixed
        // token::transfer(ctx.contract_signer(), &ctx.signer().to_string(), n)
        Ok(())
    }

    fn balance(ctx: &ViewContext, account_id: String) -> Option<Integer> {
        storage(ctx)
            .accounts()
            .get(ctx, &account_id)
            .map(|a| a.balance)
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
        storage(ctx).accounts().get(ctx, &account_id).map(|a| {
            [a.owner.clone()]
                .into_iter()
                .chain(a.other_tenants.entries.iter().map(|(k, _)| k.clone()))
                .collect()
        })
    }
}