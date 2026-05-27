#![no_std]
contract!(name = "nft");

use alloc::collections::BTreeSet;
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
// predictable. Callers paginate by issuing successive calls with `offset`.
const MAX_LIST_LIMIT: u64 = 100;

fn utxo_holder(out_point: context::OutPoint) -> Holder {
    Holder::from_ref(&HolderRef::Utxo(out_point)).unwrap()
}

// `Holder` is stored directly as a field; the macro-generated Storage
// round-trips it via its canonical key string (same pattern as Map
// keys). Default is dropped from the derive because Holder has no
// sensible default. `creator` is set at mint and never updated;
// `owner` changes on every transfer.
#[derive(Clone, Storage)]
struct NftRecord {
    pub owner: Holder,
    pub creator: Holder,
    pub agreement_id: String,
    pub attributes: Map<String, String>,
}

// Per-creator secondary index used by `list_nfts_by_creator`. Append
// only: `nft_ids` is populated at `mint` and never mutated afterwards
// (transfers do not move NFTs across creator buckets), so the bool
// value is always `true` and exists solely because the storage layer
// requires a primitive value type. `count` mirrors the size of the map
// so that `count_nfts_by_creator` is O(1) and so that the parent path
// `creator_index.{creator}` materializes on first insert (writing the
// `count` primitive is what forces path creation; an empty `Map` write
// would be a no-op).
#[derive(Clone, Default, Storage)]
struct CreatorIndex {
    pub count: u64,
    pub nft_ids: Map<String, bool>,
}

#[derive(Clone, Default, StorageRoot)]
struct NftStorage {
    pub nfts: Map<String, NftRecord>,
    pub total_minted: u64,
    pub creator_index: Map<Holder, CreatorIndex>,
}

// Record `nft_id` under `creator`'s bucket. Only called from `mint`,
// and only ever once per `nft_id` (because `nft_id` is globally unique
// and creator is immutable), so this is a pure append.
fn creator_index_add(model: &NftStorageWriteModel, creator: &Holder, nft_id: &str) {
    let creator_index = model.creator_index();
    if creator_index.get(creator).is_none() {
        creator_index.set(creator, CreatorIndex::default());
    }
    // Safe to unwrap: writing the `count` primitive above materializes
    // the parent path so `get` is guaranteed to succeed.
    let entry = creator_index
        .get(creator)
        .expect("creator_index entry just inserted");
    entry.nft_ids().set(&nft_id.to_string(), true);
    entry.set_count(entry.count() + 1);
}

fn validate(
    model: &NftStorageWriteModel,
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
        creator_index_add(&model, &creator, &nft_id);

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
    fn attach(ctx: &ProcContext, nft_id: String, vout: u64) -> Result<NftTransfer, Error> {
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

    fn list_nfts(ctx: &ViewContext, offset: u64, limit: u64) -> Vec<NftInfo> {
        // `limit == 0` is a valid no-op query; values above `MAX_LIST_LIMIT`
        // are clamped silently so callers cannot DOS the view with huge
        // page sizes. Ordering follows the underlying `Map` key iteration
        // (lexicographic on the stringified `nft_id`) and is therefore
        // stable across calls as long as the store is not mutated in
        // between.
        let limit = limit.min(MAX_LIST_LIMIT) as usize;
        if limit == 0 {
            return Vec::new();
        }
        // On wasm32, `usize` is 32 bits; saturate rather than truncate so
        // that callers passing an offset >= 2^32 get an empty page instead
        // of silently wrapping back to the start of the collection.
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let nfts = ctx.model().nfts();
        nfts.keys()
            .skip(offset)
            .take(limit)
            .filter_map(|nft_id: String| {
                nfts.get(&nft_id).map(|nft| NftInfo {
                    nft_id,
                    owner: nft.owner().as_ref(),
                    creator: nft.creator().as_ref(),
                    agreement_id: nft.agreement_id(),
                })
            })
            .collect()
    }

    fn list_nfts_by_creator(
        ctx: &ViewContext,
        creator: HolderRef,
        offset: u64,
        limit: u64,
    ) -> Vec<NftInfo> {
        // Mirror the `list_nfts` semantics: silently clamp `limit` to
        // `MAX_LIST_LIMIT`, treat `limit == 0` as an empty page and an
        // out-of-range `offset` as an empty page. An invalid `HolderRef`
        // also degrades to an empty list rather than surfacing an error;
        // view functions should not fail on malformed query parameters.
        let limit = limit.min(MAX_LIST_LIMIT) as usize;
        if limit == 0 {
            return Vec::new();
        }
        let Ok(creator): Result<Holder, _> = creator.try_into() else {
            return Vec::new();
        };
        let Some(entry) = ctx.model().creator_index().get(&creator) else {
            return Vec::new();
        };
        // See `list_nfts` for why we saturate instead of casting.
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let nfts = ctx.model().nfts();
        // The index is append-only (transfers do not move NFTs across
        // creator buckets), so every key in `nft_ids` is a current
        // member and we can paginate directly with skip/take without
        // any extra filtering pass.
        entry
            .nft_ids()
            .keys()
            .skip(offset)
            .take(limit)
            .filter_map(|nft_id: String| {
                nfts.get(&nft_id).map(|nft| NftInfo {
                    nft_id,
                    owner: nft.owner().as_ref(),
                    creator: nft.creator().as_ref(),
                    agreement_id: nft.agreement_id(),
                })
            })
            .collect()
    }

    fn count_nfts_by_creator(ctx: &ViewContext, creator: HolderRef) -> u64 {
        // Mirrors `list_nfts_by_creator`'s lenient input handling: an
        // unknown or invalid creator is reported as 0 NFTs.
        let Ok(creator): Result<Holder, _> = creator.try_into() else {
            return 0;
        };
        ctx.model()
            .creator_index()
            .get(&creator)
            .map(|entry| entry.count())
            .unwrap_or(0)
    }

    fn get_attributes(ctx: &ViewContext, nft_id: String) -> Vec<Attribute> {
        let Some(nft) = ctx.model().nfts().get(&nft_id) else {
            return Vec::new();
        };
        nft.attributes()
            .keys()
            .filter_map(|key: String| {
                nft.attributes()
                    .get(&key)
                    .map(|value| Attribute { key, value })
            })
            .collect()
    }

    fn get_attribute(ctx: &ViewContext, nft_id: String, key: String) -> Option<String> {
        ctx.model().nfts().get(&nft_id)?.attributes().get(&key)
    }
}
