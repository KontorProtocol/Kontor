#![no_std]
contract!(name = "nft");

use alloc::collections::BTreeSet;
use core::ops::Bound;
use stdlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../filestorage/wit"
);

const MAX_NFT_ID_LEN_BYTES: usize = 64;
const MAX_ATTRIBUTES: usize = 32;
const MAX_ATTR_KEY_LEN_BYTES: usize = 64;
const MAX_ATTR_VALUE_LEN_BYTES: usize = 2048;
// Upper bound on `limit` accepted by `list_nfts` to keep response sizes
// predictable. Each response supplies the next exclusive NFT-ID cursor.
const MAX_LIST_LIMIT: u64 = 100;

fn page_bounds(after: Option<String>) -> (Bound<String>, Bound<String>) {
    (
        after.map(Bound::Excluded).unwrap_or(Bound::Unbounded),
        Bound::Unbounded,
    )
}

fn collect_page<T>(
    rows: impl Iterator<Item = T>,
    limit: u64,
    key: impl Fn(&T) -> &String,
) -> (Vec<T>, Option<String>) {
    let limit = limit.min(MAX_LIST_LIMIT) as usize;
    if limit == 0 {
        return (Vec::new(), None);
    }
    // One lookahead distinguishes a full final page from a page with more results.
    let mut items: Vec<T> = rows.take(limit + 1).collect();
    let next = if items.len() > limit {
        items.pop();
        items.last().map(|item| key(item).clone())
    } else {
        None
    };
    (items, next)
}

fn nft_page(ctx: &ViewContext, keys: impl Iterator<Item = String>, limit: u64) -> NftPage {
    let (keys, next) = collect_page(keys, limit, |key| key);
    let nfts = ctx.model().nfts();
    let items = keys
        .into_iter()
        .map(|nft_id| {
            let nft = nfts.get(&nft_id).expect("listed NFT exists");
            NftInfo {
                nft_id,
                owner: nft.owner().as_ref(),
                creator: nft.creator().as_ref(),
                agreement_id: nft.agreement_id(),
            }
        })
        .collect();
    NftPage { items, next }
}

fn utxo_holder(out_point: context::OutPoint) -> Holder {
    Holder::from_ref(&HolderRef::Utxo(out_point)).unwrap()
}

// `Holder` is stored directly as a field; the macro-generated Storage
// round-trips it via its canonical key string (same pattern as Map
// keys). Default is dropped from the derive because Holder has no
// sensible default. `creator` is set at mint and never updated;
// `owner` changes on every transfer.
// `creator` is indexed so `list_nfts_by_creator`/`count_nfts_by_creator` are a
// prefix read + framework-maintained count of that creator's bucket — replacing
// the hand-rolled `creator_index` secondary map. `creator` is immutable (set at
// mint, never updated), so the index is pure-append: a mint adds one member, and
// `transfer` (which only changes `owner`) never moves it.
//
// The index COVERS `agreement_id` (`include = …`): also immutable, so the covered
// leaf never churns — the recommended shape for covering (cold field, read via the
// index). `.creator(c).iter()` then yields each NFT's agreement id straight from the
// index without a per-member `get`.
// The `owner` field is indexed (accessor `holder`) so "which NFTs does X currently
// hold?" is a bucket scan + O(1) count instead of an impossible full-map scan. Named
// `holder` (not `owner`) to match the `Holder` type it keys on — a UTXO or the burner
// holds an NFT without "owning" it in a titular sense. PLAIN (no `include`): `owner`
// changes on every transfer/attach/detach, so the framework already relocates the
// member across buckets on `set_owner` — a covering leaf would be rewritten on every
// ownership change for zero read benefit (the hot-field anti-pattern for covering).
// Declared FIRST (id 0) so `creator` keeps id 1 — index ids are positional and part
// of the bucket path.
#[derive(Clone, Storage)]
#[index(holder, by = owner)]
#[index(creator, by = creator, include = (agreement_id))]
struct NftRecord {
    pub owner: Holder,
    pub creator: Holder,
    pub agreement_id: String,
    pub attributes: Map<String, String>,
}

#[derive(Clone, Default, StorageRoot)]
struct NftStorage {
    pub nfts: Map<String, NftRecord>,
    pub total_minted: u64,
}

fn validate(
    model: &NftStorageWriteModel<context::ProcStorage>,
    nft_id: &str,
    attributes: &[Attribute],
) -> Result<(), Error> {
    if nft_id.is_empty() {
        return Err(Error::Message("nft_id cannot be empty".to_string()));
    }
    if nft_id.len() > MAX_NFT_ID_LEN_BYTES {
        return Err(Error::Message("nft_id is too long".to_string()));
    }
    if model.nfts().get(&nft_id.to_string()).is_some() {
        return Err(Error::Message("nft_id already exists".to_string()));
    }
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(Error::Message("too many attributes".to_string()));
    }
    let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
    for attr in attributes {
        if attr.key.is_empty() {
            return Err(Error::Message("attribute key cannot be empty".to_string()));
        }
        if attr.key.len() > MAX_ATTR_KEY_LEN_BYTES {
            return Err(Error::Message("attribute key is too long".to_string()));
        }
        if attr.value.len() > MAX_ATTR_VALUE_LEN_BYTES {
            return Err(Error::Message("attribute value is too long".to_string()));
        }
        if !seen_keys.insert(attr.key.as_str()) {
            return Err(Error::Message("duplicate attribute key".to_string()));
        }
    }
    Ok(())
}

fn change_owner(
    ctx: &ProcContext,
    nft_id: String,
    expected_owner: Holder,
    new_owner: Holder,
    not_owner_msg: &'static str,
) -> Result<NftTransfer, Error> {
    let nft = ctx
        .model()
        .nfts()
        .get(&nft_id)
        .ok_or(Error::Message("nft not found".to_string()))?;
    if nft.owner() != expected_owner {
        return Err(Error::Message(not_owner_msg.to_string()));
    }
    nft.set_owner(new_owner.clone());
    Ok(NftTransfer {
        nft_id,
        src: expected_owner.as_ref(),
        dst: new_owner.as_ref(),
    })
}

impl Guest for Nft {
    fn init(ctx: &ProcContext) -> Contract {
        NftStorage::default().init(ctx);
        ctx.contract()
    }

    fn mint(
        ctx: &ProcContext,
        nft_id: String,
        attributes: Vec<Attribute>,
        file_descriptor: RawFileDescriptor,
    ) -> Result<NftInfo, Error> {
        let model = ctx.model();
        validate(&model, &nft_id, &attributes)?;

        let agreement = filestorage::create_agreement(ctx.signer(), file_descriptor)?;
        let agreement_id = agreement.agreement_id;
        let creator: Holder = (&ctx.signer()).into();
        // At mint time, owner and creator are the same signer. Owner
        // can later be changed by `transfer`; creator is immutable.
        let owner = creator.clone();

        model.nfts().set(
            &nft_id,
            NftRecord {
                owner: owner.clone(),
                creator: creator.clone(),
                agreement_id: agreement_id.clone(),
                attributes: Map::default(),
            },
        );
        // Write attributes into the freshly-inserted record's nested map.
        let record = model
            .nfts()
            .get(&nft_id)
            .expect("nft just inserted above must be retrievable");
        for attr in attributes {
            record.attributes().set(&attr.key, attr.value);
        }
        model.update_total_minted(|total| total + 1);

        Ok(NftInfo {
            nft_id,
            owner: owner.as_ref(),
            creator: creator.as_ref(),
            agreement_id,
        })
    }

    fn transfer(
        ctx: &ProcContext,
        nft_id: String,
        new_owner: HolderRef,
    ) -> Result<NftTransfer, Error> {
        let signer: Holder = (&ctx.signer()).into();
        change_owner(
            ctx,
            nft_id,
            signer,
            new_owner.try_into()?,
            "only owner can transfer",
        )
    }

    // Attaches the NFT to UTXO `(current_txid, vout)`. The new owner becomes
    // `Holder::Utxo(...)`. WARNING: Kontor does not watch UTXO spends. If this
    // UTXO is spent by a Bitcoin transaction without a Kontor `detach`
    // instruction, the NFT remains permanently orphaned under the old UTXO.
    // The caller is responsible for always spending this UTXO via a Kontor
    // transaction that includes `detach`.
    fn attach(ctx: &ProcContext, nft_id: String, vout: u32) -> Result<NftTransfer, Error> {
        let out_point = context::OutPoint {
            txid: ctx.transaction().id(),
            vout,
        };
        let signer: Holder = (&ctx.signer()).into();
        change_owner(
            ctx,
            nft_id,
            signer,
            utxo_holder(out_point),
            "only owner can attach",
        )
    }

    fn detach(ctx: &ProcContext, nft_id: String) -> Result<NftTransfer, Error> {
        // Recipient = `ctx.payer()`. The reactor's Sponsor mechanism
        // determines the payer per the override rules:
        //   - Direct + cross-input Sponsor (swap path): payer = sponsor's
        //     signer (the buyer) → NFT detaches to the buyer.
        //   - Direct + no Sponsor (revoke path): payer = signer of this
        //     input (the seller, who pre-signed the escrow leaf) → NFT
        //     returns to the seller.
        // `ctx.payer()` is a Holder (not a Signer) — we can transfer the
        // NFT to it but not authorize spends on its behalf.
        let src = utxo_holder(ctx.transaction().out_point());
        change_owner(
            ctx,
            nft_id,
            src,
            ctx.payer(),
            "nft is not attached to this utxo",
        )
    }

    fn get_info(ctx: &ViewContext, nft_id: String) -> Option<NftInfo> {
        ctx.model().nfts().get(&nft_id).map(|nft| NftInfo {
            nft_id: nft_id.clone(),
            owner: nft.owner().as_ref(),
            creator: nft.creator().as_ref(),
            agreement_id: nft.agreement_id(),
        })
    }

    fn total_minted(ctx: &ViewContext) -> u64 {
        ctx.model().total_minted()
    }

    fn list_nfts(ctx: &ViewContext, after: Option<String>, limit: u64) -> NftPage {
        if limit == 0 {
            return NftPage {
                items: Vec::new(),
                next: None,
            };
        }
        nft_page(
            ctx,
            ctx.model().nfts().range(page_bounds(after)).keys(),
            limit,
        )
    }

    fn list_nfts_by_creator(
        ctx: &ViewContext,
        creator: HolderRef,
        after: Option<String>,
        limit: u64,
    ) -> NftPage {
        let Ok(creator): Result<Holder, _> = creator.try_into() else {
            return NftPage {
                items: Vec::new(),
                next: None,
            };
        };
        if limit == 0 {
            return NftPage {
                items: Vec::new(),
                next: None,
            };
        }
        nft_page(
            ctx,
            ctx.model()
                .nfts()
                .creator(creator)
                .range(page_bounds(after))
                .keys(),
            limit,
        )
    }

    fn count_nfts_by_creator(ctx: &ViewContext, creator: HolderRef) -> u64 {
        let Ok(creator): Result<Holder, _> = creator.try_into() else {
            return 0;
        };
        ctx.model().nfts().creator(creator).len()
    }

    fn list_nfts_by_holder(
        ctx: &ViewContext,
        holder: HolderRef,
        after: Option<String>,
        limit: u64,
    ) -> NftPage {
        let Ok(holder): Result<Holder, _> = holder.try_into() else {
            return NftPage {
                items: Vec::new(),
                next: None,
            };
        };
        if limit == 0 {
            return NftPage {
                items: Vec::new(),
                next: None,
            };
        }
        nft_page(
            ctx,
            ctx.model()
                .nfts()
                .holder(holder)
                .range(page_bounds(after))
                .keys(),
            limit,
        )
    }

    fn count_nfts_by_holder(ctx: &ViewContext, holder: HolderRef) -> u64 {
        let Ok(holder): Result<Holder, _> = holder.try_into() else {
            return 0;
        };
        ctx.model().nfts().holder(holder).len()
    }

    fn agreement_ids_by_creator(
        ctx: &ViewContext,
        creator: HolderRef,
        after: Option<String>,
        limit: u64,
    ) -> AgreementPage {
        let Ok(creator): Result<Holder, _> = creator.try_into() else {
            return AgreementPage {
                items: Vec::new(),
                next: None,
            };
        };
        if limit == 0 {
            return AgreementPage {
                items: Vec::new(),
                next: None,
            };
        }
        let (rows, next) = collect_page(
            ctx.model()
                .nfts()
                .creator(creator)
                .range(page_bounds(after))
                .iter(),
            limit,
            |(nft_id, _)| nft_id,
        );
        AgreementPage {
            items: rows
                .into_iter()
                .map(|(_, covered)| covered.agreement_id)
                .collect(),
            next,
        }
    }

    fn get_attributes(ctx: &ViewContext, nft_id: String) -> Vec<Attribute> {
        let Some(nft) = ctx.model().nfts().get(&nft_id) else {
            return Vec::new();
        };
        nft.attributes()
            .entries()
            .map(|(key, value)| Attribute { key, value })
            .collect()
    }

    fn get_attribute(ctx: &ViewContext, nft_id: String, key: String) -> Option<String> {
        ctx.model().nfts().get(&nft_id)?.attributes().get(&key)
    }
}
