#![no_std]
contract!(name = "token");

use stdlib::*;

const BURNER: &str = "burn";
const USER_PREFIX: &str = "u:";
const CONTRACT_PREFIX: &str = "c:";
const UTXO_PREFIX: &str = "o:";
const TAPROOT_PREFIX: &str = "t:";
const BURNER_KEY: &str = "i:burn";
const UTXO_ACCOUNT_PREFIX: &str = "__utxo__";
const TAPROOT_ACCOUNT_PREFIX: &str = "__tap__";

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Decimal>,
    pub total_supply: Decimal,
}

#[derive(Clone)]
enum AccountKey {
    User(u64),
    Contract(i64),
    Utxo { txid: String, vout: u64 },
    Taproot(String),
    Burner,
}

impl AccountKey {
    fn storage_key(&self) -> String {
        match self {
            Self::User(id) => format!("{}{}", USER_PREFIX, id),
            Self::Contract(id) => format!("{}{}", CONTRACT_PREFIX, id),
            Self::Utxo { txid, vout } => format!("{}{}:{}", UTXO_PREFIX, txid, vout),
            Self::Taproot(key) => format!("{}{}", TAPROOT_PREFIX, key),
            Self::Burner => BURNER_KEY.to_string(),
        }
    }

    fn display_key(&self) -> String {
        match self {
            Self::User(id) => id.to_string(),
            Self::Contract(id) => format!("__cid__{}", id),
            Self::Utxo { txid, vout } => format!("{}{}:{}", UTXO_ACCOUNT_PREFIX, txid, vout),
            Self::Taproot(key) => format!("{}{}", TAPROOT_ACCOUNT_PREFIX, key),
            Self::Burner => BURNER.to_string(),
        }
    }

    fn from_public_account(raw: &str) -> Option<Self> {
        if let Ok(id) = raw.parse::<u64>() {
            return Some(Self::User(id));
        }
        raw.strip_prefix("__cid__")
            .and_then(|rest| rest.parse::<i64>().ok())
            .map(Self::Contract)
    }

    fn from_view_account(raw: &str) -> Option<Self> {
        Self::from_public_account(raw)
            .or_else(|| {
                raw.strip_prefix(UTXO_ACCOUNT_PREFIX).and_then(|rest| {
                    let (txid, vout) = rest.rsplit_once(':')?;
                    let vout = vout.parse::<u64>().ok()?;
                    Some(Self::Utxo {
                        txid: txid.to_string(),
                        vout,
                    })
                })
            })
            .or_else(|| {
                raw.strip_prefix(TAPROOT_ACCOUNT_PREFIX)
                    .map(|rest| Self::Taproot(rest.to_string()))
            })
    }

    fn from_storage_key(raw: &str) -> Option<Self> {
        if let Some(rest) = raw.strip_prefix(USER_PREFIX)
            && let Ok(id) = rest.parse::<u64>()
        {
            return Some(Self::User(id));
        }
        if let Some(rest) = raw.strip_prefix(CONTRACT_PREFIX)
            && let Ok(id) = rest.parse::<i64>()
        {
            return Some(Self::Contract(id));
        }
        if let Some(rest) = raw.strip_prefix(UTXO_PREFIX)
            && let Some((txid, vout)) = rest.rsplit_once(':')
            && let Ok(vout) = vout.parse::<u64>()
        {
            return Some(Self::Utxo {
                txid: txid.to_string(),
                vout,
            });
        }
        if let Some(rest) = raw.strip_prefix(TAPROOT_PREFIX) {
            return Some(Self::Taproot(rest.to_string()));
        }
        if raw == BURNER_KEY {
            return Some(Self::Burner);
        }
        None
    }
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0u64.try_into().unwrap() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn public_account(raw: &str) -> Result<AccountKey, Error> {
    AccountKey::from_public_account(raw).ok_or(Error::Message(
        "account must be a canonical signer id or contract id".to_string(),
    ))
}

fn signer_account(signer: &context::Signer) -> Result<AccountKey, Error> {
    if let Some(id) = signer.signer_id() {
        return Ok(AccountKey::User(id));
    }
    public_account(&signer.to_string())
}

fn mint(model: &TokenStorageWriteModel, dst: AccountKey, amt: Decimal) -> Result<Mint, Error> {
    assert_gt_zero(amt)?;
    if amt > 1000u64.try_into().unwrap() {
        return Err(Error::Message("Amount exceeds limit".to_string()));
    }
    let ledger = model.ledger();
    let dst_key = dst.storage_key();
    let new_amt = ledger.get(&dst_key).unwrap_or_default().add(amt)?;
    ledger.set(dst_key, new_amt);
    model.try_update_total_supply(|t| t.add(amt))?;
    Ok(Mint {
        dst: dst.display_key(),
        amt: new_amt,
    })
}

fn transfer(
    ctx: &ProcContext,
    src: AccountKey,
    dst: AccountKey,
    amt: Decimal,
) -> Result<Transfer, Error> {
    assert_gt_zero(amt)?;
    let ledger = ctx.model().ledger();
    let src_key = src.storage_key();
    let dst_key = dst.storage_key();

    let src_amt = ledger.get(&src_key).unwrap_or_default();
    let dst_amt = ledger.get(&dst_key).unwrap_or_default();

    if src_amt < amt {
        return Err(Error::Message("insufficient funds".to_string()));
    }

    ledger.set(src_key, src_amt.sub(amt)?);
    ledger.set(dst_key, dst_amt.add(amt)?);
    Ok(Transfer {
        src: src.display_key(),
        dst: dst.display_key(),
        amt,
    })
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, amt: Decimal) -> Result<Mint, Error> {
        let signer = ctx.signer_proc_context().signer();
        mint(&ctx.proc_context().model(), signer_account(&signer)?, amt)
    }

    fn issue_to(ctx: &CoreContext, dst: String, amt: Decimal) -> Result<Mint, Error> {
        mint(&ctx.proc_context().model(), public_account(&dst)?, amt)
    }

    fn hold(ctx: &CoreContext, amt: Decimal) -> Result<Transfer, Error> {
        let core_signer = ctx.proc_context().signer();
        Self::transfer(
            &ctx.signer_proc_context(),
            signer_account(&core_signer)?.display_key(),
            amt,
        )
    }

    fn release(ctx: &CoreContext, burn_amt: Decimal) -> Result<Burn, Error> {
        let core = ctx.proc_context();
        let burn = Self::burn(&core, burn_amt)?;
        let core_signer = core.signer();
        let amt = core
            .model()
            .ledger()
            .get(signer_account(&core_signer)?.storage_key())
            .unwrap_or_default();
        if amt > 0u64.try_into().unwrap() {
            let signer = ctx.signer_proc_context().signer();
            Self::transfer(&core, signer_account(&signer)?.display_key(), amt)?;
        }
        let signer = ctx.signer_proc_context().signer();
        Ok(Burn {
            src: signer_account(&signer)?.display_key(),
            ..burn
        })
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        let signer = ctx.signer();
        mint(&ctx.model(), signer_account(&signer)?, amt)
    }

    fn burn(ctx: &ProcContext, amt: Decimal) -> Result<Burn, Error> {
        let signer = ctx.signer();
        let transfer = transfer(ctx, signer_account(&signer)?, AccountKey::Burner, amt)?;
        ctx.model().try_update_total_supply(|t| t.sub(amt))?;
        Ok(Burn {
            src: transfer.src,
            amt: transfer.amt,
        })
    }

    fn transfer(ctx: &ProcContext, dst: String, amt: Decimal) -> Result<Transfer, Error> {
        let signer = ctx.signer();
        transfer(ctx, signer_account(&signer)?, public_account(&dst)?, amt)
    }

    fn attach(ctx: &ProcContext, vout: u64, amt: Decimal) -> Result<Transfer, Error> {
        let dst = AccountKey::Utxo {
            txid: ctx.transaction().id(),
            vout,
        };
        let signer = ctx.signer();
        transfer(ctx, signer_account(&signer)?, dst, amt)
    }

    fn detach(ctx: &ProcContext) -> Result<Transfer, Error> {
        let out_point = ctx.transaction().out_point();
        let src = AccountKey::Utxo {
            txid: out_point.txid,
            vout: out_point.vout,
        };
        let amt = ctx
            .model()
            .ledger()
            .get(src.storage_key())
            .ok_or(Error::Message("Source has no balance".to_string()))?;
        let dst =
            if let Some(context::OpReturnData::PubKey(dst)) = ctx.transaction().op_return_data() {
                AccountKey::Taproot(dst)
            } else {
                let signer = ctx.signer();
                signer_account(&signer)?
            };
        transfer(ctx, src, dst, amt)
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Decimal> {
        let acc = AccountKey::from_view_account(&acc)?;
        ctx.model().ledger().get(acc.storage_key())
    }

    fn balances(ctx: &ViewContext) -> Vec<Balance> {
        ctx.model()
            .ledger()
            .keys()
            .filter_map(|key: String| match AccountKey::from_storage_key(&key) {
                Some(AccountKey::User(id)) => Some(Balance {
                    amt: ctx.model().ledger().get(&key).unwrap_or_default(),
                    acc: id.to_string(),
                }),
                _ => None,
            })
            .collect()
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
