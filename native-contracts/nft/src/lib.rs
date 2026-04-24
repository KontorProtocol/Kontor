#![no_std]
contract!(name = "nft");

use stdlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../filestorage/wit"
);

const MAX_NAME_LEN_BYTES: usize = 64;
const MAX_DESCRIPTION_LEN_BYTES: usize = 2048;

#[derive(Clone, Default, Storage)]
struct StoredMetadata {
    pub name: String,
    pub description: String,
}

// `owner` is stored as the canonical Holder key string (the same value produced
// by `Holder::to_string()`), then materialized back into a `Holder`/`HolderRef`
// via `FromStr` at the API boundary. We can't store a raw `Holder` resource
// because wit-bindgen resources don't implement the Storage derive, and the
// auto-derived Storage for `HolderRef` (a variant) is incompatible with the
// `Retrieve` impl generated for it (it expects a single string, not a variant
// subpath). Storing the canonical key string keeps storage simple and matches
// how `Map<Holder, _>` already serializes its keys in other native contracts.
#[derive(Clone, Default, Storage)]
struct TokenRecord {
    pub owner: String,
    pub metadata: StoredMetadata,
}

#[derive(Clone, Default, StorageRoot)]
struct NftStorage {
    pub tokens: Map<String, TokenRecord>,
    pub token_id_by_name: Map<String, String>,
    pub total_tokens: u64,
}

fn validate_metadata(name: &str, description: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::new("name cannot be empty"));
    }
    if name.len() > MAX_NAME_LEN_BYTES {
        return Err(Error::new("name is too long"));
    }
    if description.is_empty() {
        return Err(Error::new("description cannot be empty"));
    }
    if description.len() > MAX_DESCRIPTION_LEN_BYTES {
        return Err(Error::new("description is too long"));
    }
    Ok(())
}

fn parse_owner(s: String) -> Holder {
    Holder::from_str(&s).expect("stored owner key must always be a valid Holder")
}

impl Guest for Nft {
    fn init(ctx: &ProcContext) {
        NftStorage::default().init(ctx);
    }

    fn mint(
        ctx: &ProcContext,
        name: String,
        description: String,
        descriptor: RawFileDescriptor,
    ) -> Result<NftMint, Error> {
        // Effects-before-interactions (CEI): validate inputs and check
        // uniqueness invariants before the cross-contract call into
        // filestorage. file_id validity (non-empty, etc.) is delegated to
        // filestorage::create_agreement.
        validate_metadata(&name, &description)?;

        let model = ctx.model();
        if model.token_id_by_name().get(&name).is_some() {
            return Err(Error::new("name already exists"));
        }

        let agreement = filestorage::create_agreement(ctx.signer(), descriptor)?;
        let token_id = agreement.agreement_id;
        let owner: Holder = ctx.signer().into();

        model.tokens().set(
            &token_id,
            TokenRecord {
                owner: owner.to_string(),
                metadata: StoredMetadata {
                    name: name.clone(),
                    description: description.clone(),
                },
            },
        );
        model.token_id_by_name().set(&name, token_id.clone());
        model.update_total_tokens(|total| total + 1);

        Ok(NftMint {
            token_id,
            owner: owner.as_ref(),
            metadata: TokenMetadata { name, description },
        })
    }

    fn transfer(
        ctx: &ProcContext,
        token_id: String,
        new_owner: HolderRef,
    ) -> Result<NftTransfer, Error> {
        let model = ctx.model();
        let token = model
            .tokens()
            .get(&token_id)
            .ok_or(Error::new("token not found"))?;

        let signer: Holder = ctx.signer().into();
        let current_owner = parse_owner(token.owner());
        if current_owner != signer {
            return Err(Error::new("only owner can transfer"));
        }

        let new_owner: Holder = new_owner.try_into()?;
        token.set_owner(new_owner.to_string());
        Ok(NftTransfer {
            token_id,
            src: signer.as_ref(),
            dst: new_owner.as_ref(),
        })
    }

    fn owner_of(ctx: &ViewContext, token_id: String) -> Option<HolderRef> {
        ctx.model()
            .tokens()
            .get(&token_id)
            .map(|token| parse_owner(token.owner()).as_ref())
    }

    fn metadata_of(ctx: &ViewContext, token_id: String) -> Option<TokenMetadata> {
        ctx.model()
            .tokens()
            .get(&token_id)
            .map(|token| token.metadata().load().into())
    }

    fn token_id_by_name(ctx: &ViewContext, name: String) -> Option<String> {
        ctx.model().token_id_by_name().get(&name)
    }

    fn total_tokens(ctx: &ViewContext) -> u64 {
        ctx.model().total_tokens()
    }
}

impl From<StoredMetadata> for TokenMetadata {
    fn from(m: StoredMetadata) -> Self {
        Self {
            name: m.name,
            description: m.description,
        }
    }
}
