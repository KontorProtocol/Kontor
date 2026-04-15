#![no_std]
contract!(name = "registry");

use context::Holder;
use stdlib::*;

#[derive(Clone, Default, Storage)]
struct Entry {
    pub signer_id: u64,
    pub bls_pubkey: Vec<u8>,
    pub next_nonce: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct RegistryStorage {
    pub next_signer_id: u64,
    pub entries: Map<Holder, Entry>,
    pub by_id: Map<u64, String>,
}

impl Guest for Registry {
    fn init(ctx: &ProcContext) {
        RegistryStorage::default().init(ctx);
    }

    fn ensure_signer(ctx: &CoreContext, x_only_pubkey: String) -> RegistryEntry {
        let model = ctx.proc_context().model();
        let holder: Holder = x_only_pubkey.parse().expect("invalid holder");

        if let Some(entry) = model.entries().get(&holder) {
            return RegistryEntry {
                signer_id: entry.signer_id(),
                x_only_pubkey,
                bls_pubkey: {
                    let bls_pubkey = entry.bls_pubkey();
                    if bls_pubkey.is_empty() {
                        None
                    } else {
                        Some(bls_pubkey)
                    }
                },
                next_nonce: entry.next_nonce(),
            };
        }

        let signer_id = model.next_signer_id();
        model.update_next_signer_id(|n| n + 1);

        model.entries().set(
            holder,
            Entry {
                signer_id,
                bls_pubkey: Vec::new(),
                next_nonce: 0,
            },
        );
        model.by_id().set(signer_id, x_only_pubkey.clone());

        RegistryEntry {
            signer_id,
            x_only_pubkey,
            bls_pubkey: None,
            next_nonce: 0,
        }
    }

    fn register_bls_key(ctx: &CoreContext, bls_pubkey: Vec<u8>) -> RegistryEntry {
        let x_only_pubkey = ctx.signer_proc_context().signer().to_string();
        let holder: Holder = x_only_pubkey.parse().expect("invalid holder");
        let model = ctx.proc_context().model();

        if let Some(entry) = model.entries().get(&holder) {
            model.entries().set(
                holder,
                Entry {
                    signer_id: entry.signer_id(),
                    bls_pubkey: bls_pubkey.clone(),
                    next_nonce: entry.next_nonce(),
                },
            );
            return RegistryEntry {
                signer_id: entry.signer_id(),
                x_only_pubkey,
                bls_pubkey: Some(bls_pubkey),
                next_nonce: entry.next_nonce(),
            };
        }

        let signer_id = model.next_signer_id();
        model.update_next_signer_id(|n| n + 1);

        model.entries().set(
            holder,
            Entry {
                signer_id,
                bls_pubkey: bls_pubkey.clone(),
                next_nonce: 0,
            },
        );
        model.by_id().set(signer_id, x_only_pubkey.clone());

        RegistryEntry {
            signer_id,
            x_only_pubkey,
            bls_pubkey: Some(bls_pubkey),
            next_nonce: 0,
        }
    }

    fn advance_nonce(ctx: &CoreContext, signer_id: u64, caller_nonce: u64) -> Result<u64, Error> {
        let model = ctx.proc_context().model();
        let x_only_pubkey = model
            .by_id()
            .get(signer_id)
            .ok_or_else(|| Error::Message("unknown signer id".to_string()))?;
        let holder: Holder = x_only_pubkey.parse().expect("invalid holder");
        let entry = model
            .entries()
            .get(&holder)
            .ok_or_else(|| Error::Message("registry entry missing for signer id".to_string()))?;

        let stored_nonce = entry.next_nonce();
        if stored_nonce != caller_nonce {
            return Err(Error::Message(format!(
                "nonce mismatch for signer_id {}: got {}, expected {}",
                signer_id, caller_nonce, stored_nonce
            )));
        }

        let next_nonce = stored_nonce
            .checked_add(1)
            .ok_or_else(|| Error::Message("nonce overflow".to_string()))?;

        model.entries().set(
            holder,
            Entry {
                signer_id: entry.signer_id(),
                bls_pubkey: entry.bls_pubkey(),
                next_nonce,
            },
        );

        Ok(next_nonce)
    }

    fn get_entry(ctx: &ViewContext, x_only_pubkey: String) -> Option<RegistryEntry> {
        let entry = ctx.model().entries().get(&x_only_pubkey)?;
        let bls_pubkey = entry.bls_pubkey();
        Some(RegistryEntry {
            signer_id: entry.signer_id(),
            x_only_pubkey,
            bls_pubkey: if bls_pubkey.is_empty() {
                None
            } else {
                Some(bls_pubkey)
            },
            next_nonce: entry.next_nonce(),
        })
    }

    fn get_entry_by_id(ctx: &ViewContext, signer_id: u64) -> Option<RegistryEntry> {
        let x_only_pubkey = ctx.model().by_id().get(signer_id)?;
        let entry = ctx.model().entries().get(&x_only_pubkey)?;
        let bls_pubkey = entry.bls_pubkey();
        Some(RegistryEntry {
            signer_id: entry.signer_id(),
            x_only_pubkey,
            bls_pubkey: if bls_pubkey.is_empty() {
                None
            } else {
                Some(bls_pubkey)
            },
            next_nonce: entry.next_nonce(),
        })
    }

    fn get_signer_id(ctx: &ViewContext, x_only_pubkey: String) -> Option<u64> {
        ctx.model().entries().get(&x_only_pubkey).map(|e| e.signer_id())
    }

    fn get_bls_pubkey(ctx: &ViewContext, x_only_pubkey: String) -> Option<Vec<u8>> {
        let entry = ctx.model().entries().get(&x_only_pubkey)?;
        let bls_pubkey = entry.bls_pubkey();
        if bls_pubkey.is_empty() {
            None
        } else {
            Some(bls_pubkey)
        }
    }

    fn get_next_signer_id(ctx: &ViewContext) -> u64 {
        ctx.model().next_signer_id()
    }
}
