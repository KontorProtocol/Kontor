#![no_std]
contract!(name = "nft");

use stdlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../filestorage/wit"
);

const MAX_NFT_ID_LEN_BYTES: usize = 64;
const MAX_DESCRIPTION_LEN_BYTES: usize = 2048;

// `owner` is stored as the canonical `Holder` key string (same as
// `Holder::to_string()`), then parsed back via `FromStr` at the API boundary.
// This mirrors how `Map<Holder, _>` serializes its keys in other native
// contracts and avoids storing a wit-bindgen resource (which doesn't support
// `Storage`) or an enum variant (incompatible with the auto-derived `Retrieve`
// for `HolderRef`).
#[derive(Clone, Default, Storage)]
struct NftRecord {
    pub owner: String,
    pub agreement_id: String,
    pub description: String,
}

#[derive(Clone, Default, StorageRoot)]
struct NftStorage {
    pub nfts: Map<String, NftRecord>,
    pub total_nfts: u64,
}

fn validate(model: &NftStorageWriteModel, nft_id: &str, description: &str) -> Result<(), Error> {
    if nft_id.is_empty() {
        return Err(Error::Message("nft_id cannot be empty".to_string()));
    }
    if nft_id.len() > MAX_NFT_ID_LEN_BYTES {
        return Err(Error::Message("nft_id is too long".to_string()));
    }
    if description.is_empty() {
        return Err(Error::Message("description cannot be empty".to_string()));
    }
    if description.len() > MAX_DESCRIPTION_LEN_BYTES {
        return Err(Error::Message("description is too long".to_string()));
    }
    if model.nfts().get(&nft_id.to_string()).is_some() {
        return Err(Error::Message("nft_id already exists".to_string()));
    }
    Ok(())
}

impl Guest for Nft {
    fn init(ctx: &ProcContext) {
        NftStorage::default().init(ctx);
    }

    fn mint(
        ctx: &ProcContext,
        nft_id: String,
        description: String,
        file_descriptor: RawFileDescriptor,
    ) -> Result<NftInfo, Error> {
        // Effects before interactions (CEI pattern): validate inputs and
        // local uniqueness invariants before the cross-contract call into
        // filestorage. `file_id` validity is delegated to
        // `filestorage::create_agreement`; the returned `agreement_id` is
        // stored as the NFT's link to the underlying file.
        let model = ctx.model();
        validate(&model, &nft_id, &description)?;

        let agreement = filestorage::create_agreement(ctx.signer(), file_descriptor)?;
        let agreement_id = agreement.agreement_id;
        let owner: Holder = (&ctx.signer()).into();

        model.nfts().set(
            &nft_id,
            NftRecord {
                owner: owner.to_string(),
                agreement_id: agreement_id.clone(),
                description: description.clone(),
            },
        );
        model.update_total_nfts(|total| total + 1);

        Ok(NftInfo {
            nft_id,
            owner: owner.as_ref(),
            agreement_id,
            description,
        })
    }

    fn transfer(
        ctx: &ProcContext,
        nft_id: String,
        new_owner: HolderRef,
    ) -> Result<NftTransfer, Error> {
        let model = ctx.model();
        let nft = model
            .nfts()
            .get(&nft_id)
            .ok_or(Error::Message("nft not found".to_string()))?;

        let signer: Holder = (&ctx.signer()).into();
        let current_owner: Holder = nft.owner().parse().expect("stored owner must be valid");
        if current_owner != signer {
            return Err(Error::Message("only owner can transfer".to_string()));
        }

        let new_owner: Holder = new_owner.try_into()?;
        nft.set_owner(new_owner.to_string());
        Ok(NftTransfer {
            nft_id,
            src: signer.as_ref(),
            dst: new_owner.as_ref(),
        })
    }

    fn get_info(ctx: &ViewContext, nft_id: String) -> Option<NftInfo> {
        ctx.model().nfts().get(&nft_id).map(|nft| {
            let owner: Holder = nft.owner().parse().expect("stored owner must be valid");
            NftInfo {
                nft_id: nft_id.clone(),
                owner: owner.as_ref(),
                agreement_id: nft.agreement_id(),
                description: nft.description(),
            }
        })
    }

    fn total_nfts(ctx: &ViewContext) -> u64 {
        ctx.model().total_nfts()
    }
}
