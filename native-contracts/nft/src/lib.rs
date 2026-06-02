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
// Upper bound on `limit` accepted by every paginated `list_*` view
// (`list_nfts`, `list_nfts_by_creator`, `list_nfts_by_holder`) to keep
// response sizes predictable. Callers paginate by issuing successive calls
// with `offset`.
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

// Generic index bucket shared by `creator_index` and `holder_index`.
// `count` mirrors the map size for O(1) count queries. The `bool` value
// in `nft_ids` is always `true`; a Map<String, bool> is used because the
// storage layer requires a primitive value — a Set is not available.
// Writing `count` on first insert also materialises the parent path
// so that `creator_index.{creator}` / `holder_index.{holder}` exist
// even before any `nft_ids` entry is added.
#[derive(Clone, Default, Storage)]
struct NftIndex {
    pub count: u64,
    pub nft_ids: Map<String, bool>,
}

// Both secondary indexes are populated from this contract version onward and
// have no retroactive backfill: any NFT minted before the index existed is
// absent from it until the next operation that touches its bucket (a transfer
// records the *new* holder; the old, never-indexed holder is simply skipped).
// On a fresh deployment this is a non-issue — there is no prior NFT state.
#[derive(Clone, Default, StorageRoot)]
struct NftStorage {
    pub nfts: Map<String, NftRecord>,
    pub total_minted: u64,
    pub creator_index: Map<Holder, NftIndex>,
    pub holder_index: Map<Holder, NftIndex>,
}

// Record `nft_id` under `creator`'s bucket. Only called from `mint`,
// and only ever once per `nft_id` (because `nft_id` is globally unique
// and creator is immutable), so this is a pure append.
fn creator_index_add(model: &NftStorageWriteModel, creator: &Holder, nft_id: &str) {
    let creator_index = model.creator_index();
    let entry = match creator_index.get(creator) {
        Some(e) => e,
        None => {
            creator_index.set(creator, NftIndex::default());
            creator_index
                .get(creator)
                .expect("creator_index entry just inserted")
        }
    };
    entry.nft_ids().set(&nft_id.to_string(), true);
    entry.set_count(entry.count() + 1);
}

fn holder_index_add(model: &NftStorageWriteModel, holder: &Holder, nft_id: &str) {
    let holder_index = model.holder_index();
    let entry = match holder_index.get(holder) {
        Some(e) => e,
        None => {
            holder_index.set(holder, NftIndex::default());
            holder_index
                .get(holder)
                .expect("holder_index entry just inserted")
        }
    };
    entry.nft_ids().set(&nft_id.to_string(), true);
    entry.set_count(entry.count() + 1);
}

// Decrement `holder`'s live count when an NFT leaves its bucket on a transfer.
// The id is intentionally NOT removed from `nft_ids`: this index is append-only
// (the storage layer exposes no key-removal primitive), so ids a holder once
// owned linger in the map and are filtered out at read time by
// `list_nfts_by_holder` re-checking current ownership. `count` stays exact
// because it is decremented here and incremented in `holder_index_add`, keeping
// `count_nfts_by_holder` O(1).
fn holder_index_dec(model: &NftStorageWriteModel, holder: &Holder) {
    if let Some(entry) = model.holder_index().get(holder) {
        entry.set_count(entry.count().saturating_sub(1));
    }
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
    // `nft_id` is used verbatim as a storage path segment (in `nfts.{nft_id}`
    // and `…nft_ids.{nft_id}`). Map-key iteration splits paths on `.`, so a
    // `.` in the id would fracture the segment and corrupt `keys()` grouping;
    // restricting to a dot-free charset keeps every id a single clean segment.
    if !nft_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Message(
            "nft_id must contain only alphanumeric characters, hyphens, or underscores".to_string(),
        ));
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
    holder_index_dec(&ctx.model(), &expected_owner);
    holder_index_add(&ctx.model(), &new_owner, &nft_id);
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
        holder_index_add(&model, &owner, &nft_id);

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

    fn list_nfts_by_holder(
        ctx: &ViewContext,
        holder: HolderRef,
        offset: u64,
        limit: u64,
    ) -> Vec<NftInfo> {
        // Same lenient semantics as `list_nfts_by_creator`: silently clamp
        // `limit` to `MAX_LIST_LIMIT`, treat `limit == 0` and an out-of-range
        // `offset` as an empty page, and degrade an invalid `HolderRef` to an
        // empty list rather than surfacing an error.
        let limit = limit.min(MAX_LIST_LIMIT) as usize;
        if limit == 0 {
            return Vec::new();
        }
        let Ok(holder): Result<Holder, _> = holder.try_into() else {
            return Vec::new();
        };
        let Some(entry) = ctx.model().holder_index().get(&holder) else {
            return Vec::new();
        };
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let nfts = ctx.model().nfts();
        // `holder_index` is append-only: `nft_ids` retains every id this holder
        // has ever owned, including ones since transferred away (no key-removal
        // primitive exists, so stale ids are never pruned). Re-check current
        // ownership to drop them; `offset`/`limit` paginate over the live set, so
        // the ownership filter must run before skip/take.
        entry
            .nft_ids()
            .keys()
            .filter_map(|nft_id: String| {
                nfts.get(&nft_id)
                    .filter(|nft| nft.owner() == holder)
                    .map(|nft| NftInfo {
                        nft_id,
                        owner: nft.owner().as_ref(),
                        creator: nft.creator().as_ref(),
                        agreement_id: nft.agreement_id(),
                    })
            })
            .skip(offset)
            .take(limit)
            .collect()
    }

    fn count_nfts_by_holder(ctx: &ViewContext, holder: HolderRef) -> u64 {
        // Mirrors `count_nfts_by_creator`'s lenient input handling: an unknown
        // or invalid holder is reported as 0 NFTs. O(1) via the cached `count`.
        let Ok(holder): Result<Holder, _> = holder.try_into() else {
            return 0;
        };
        ctx.model()
            .holder_index()
            .get(&holder)
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
