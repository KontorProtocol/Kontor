#![no_std]
contract!(name = "registry");

use stdlib::*;

#[derive(Clone, Default, Storage)]
struct Entry {
    pub signer_id: u64,
    pub bls_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct RegistryStorage {
    pub next_signer_id: u64,
    pub entries: Map<String, Entry>,
    pub by_id: Map<u64, String>,
}

fn assert_bls_pubkey_len(bls_pubkey: &[u8]) -> Result<(), Error> {
    if bls_pubkey.len() != 96 {
        return Err(Error::Message("expected 96-byte BLS pubkey".to_string()));
    }
    Ok(())
}

impl Guest for Registry {
    fn init(ctx: &ProcContext) {
        RegistryStorage::default().init(ctx);
    }

    fn register_bls_key(ctx: &CoreContext, bls_pubkey: Vec<u8>) -> Result<RegistryEntry, Error> {
        assert_bls_pubkey_len(&bls_pubkey)?;

        let x_only_pubkey = ctx.signer_proc_context().signer().to_string();
        let model = ctx.proc_context().model();

        if let Some(entry) = model.entries().get(&x_only_pubkey) {
            if entry.bls_pubkey() != bls_pubkey {
                return Err(Error::Message(
                    "BLS pubkey already registered for signer".to_string(),
                ));
            }
            return Ok(RegistryEntry {
                signer_id: entry.signer_id(),
                x_only_pubkey,
                bls_pubkey,
            });
        }

        let signer_id = model.next_signer_id();
        model.update_next_signer_id(|n| n + 1);

        model.entries().set(
            x_only_pubkey.clone(),
            Entry {
                signer_id,
                bls_pubkey: bls_pubkey.clone(),
            },
        );
        model.by_id().set(signer_id, x_only_pubkey.clone());

        Ok(RegistryEntry {
            signer_id,
            x_only_pubkey,
            bls_pubkey,
        })
    }

    fn get_entry(ctx: &ViewContext, x_only_pubkey: String) -> Option<RegistryEntry> {
        let entry = ctx.model().entries().get(&x_only_pubkey)?;
        Some(RegistryEntry {
            signer_id: entry.signer_id(),
            x_only_pubkey,
            bls_pubkey: entry.bls_pubkey(),
        })
    }

    fn get_entry_by_id(ctx: &ViewContext, signer_id: u64) -> Option<RegistryEntry> {
        let x_only_pubkey = ctx.model().by_id().get(signer_id)?;
        let entry = ctx.model().entries().get(&x_only_pubkey)?;
        Some(RegistryEntry {
            signer_id: entry.signer_id(),
            x_only_pubkey,
            bls_pubkey: entry.bls_pubkey(),
        })
    }

    fn get_signer_id(ctx: &ViewContext, x_only_pubkey: String) -> Option<u64> {
        ctx.model()
            .entries()
            .get(&x_only_pubkey)
            .map(|e| e.signer_id())
    }

    fn get_bls_pubkey(ctx: &ViewContext, x_only_pubkey: String) -> Option<Vec<u8>> {
        ctx.model()
            .entries()
            .get(&x_only_pubkey)
            .map(|e| e.bls_pubkey())
    }
}
