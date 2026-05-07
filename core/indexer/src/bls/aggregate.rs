use std::collections::HashMap;

use anyhow::{Result, anyhow};
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use indexer_types::{Inst, Insts};

use super::{
    BLS_SIGNATURE_BYTES, KONTOR_BLS_DST, MAX_BLS_BULK_OPS, MAX_BLS_BULK_TOTAL_MESSAGE_BYTES,
};
use crate::database::queries::get_signer_entry_by_id;
use crate::runtime::Runtime;

/// Resolved signer_id → x_only_pubkey mapping returned by [`verify_aggregate`]
/// so the block handler can look up signers without redundant registry calls.
pub type SignerMap = HashMap<u64, String>;

pub(super) struct SignerResolver {
    pub(super) pk_cache: HashMap<u64, BlsPublicKey>,
    pub(super) signer_map: SignerMap,
}

impl SignerResolver {
    pub(super) fn new() -> Self {
        Self {
            pk_cache: HashMap::new(),
            signer_map: HashMap::new(),
        }
    }

    pub(super) async fn resolve(
        &mut self,
        runtime: &mut Runtime,
        signer_id: u64,
    ) -> Result<BlsPublicKey> {
        if let Some(pk) = self.pk_cache.get(&signer_id) {
            return Ok(*pk);
        }

        let conn = runtime.get_storage_conn();
        let entry = get_signer_entry_by_id(&conn, signer_id as i64)
            .await?
            .ok_or_else(|| anyhow!("unknown signer_id {signer_id}"))?;
        let x_only_pubkey = entry.x_only_pubkey.clone().ok_or_else(|| {
            anyhow!("signer_id {signer_id} is not a user signer (no x_only_pubkey)")
        })?;
        self.signer_map.insert(signer_id, x_only_pubkey);
        let raw_bytes = entry
            .bls_pubkey
            .ok_or_else(|| anyhow!("signer_id {signer_id} has no BLS pubkey registered"))?;

        let pk = BlsPublicKey::key_validate(&raw_bytes)
            .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;
        self.pk_cache.insert(signer_id, pk);
        Ok(pk)
    }
}

/// Validate the stateless shape of an aggregate `Insts` envelope.
pub fn validate_aggregate_shape(insts: &Insts) -> Result<&indexer_types::AggregateInfo> {
    let agg = insts
        .aggregate
        .as_ref()
        .ok_or_else(|| anyhow!("validate_aggregate_shape called on non-aggregate Insts"))?;

    if insts.ops.is_empty() {
        return Err(anyhow!("aggregate must contain at least one operation"));
    }
    if insts.ops.len() > MAX_BLS_BULK_OPS {
        return Err(anyhow!(
            "aggregate contains {} operations (max {})",
            insts.ops.len(),
            MAX_BLS_BULK_OPS
        ));
    }
    if agg.signer_ids.len() != insts.ops.len() {
        return Err(anyhow!(
            "signer_ids length ({}) != ops length ({})",
            agg.signer_ids.len(),
            insts.ops.len()
        ));
    }
    for inst in &insts.ops {
        match inst {
            Inst::Call { nonce: Some(_), .. } => {}
            Inst::Call { nonce: None, .. } => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (missing nonce)"
                ));
            }
            Inst::RegisterBlsKey { .. } => {
                return Err(anyhow!(
                    "RegisterBlsKey is not allowed in aggregate path (use direct)"
                ));
            }
            Inst::Publish { .. } => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (got Publish)"
                ));
            }
            Inst::Issuance => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (got Issuance)"
                ));
            }
        }
    }
    Ok(agg)
}

/// Verify the BLS aggregate signature on an `Insts` envelope.
///
/// Returns a `SignerMap` (signer_id → x_only_pubkey) so the caller can resolve
/// signers for execution without redundant registry lookups.
pub async fn verify_aggregate(runtime: &mut Runtime, insts: &Insts) -> Result<SignerMap> {
    let agg = validate_aggregate_shape(insts)?;
    if agg.signature.len() != BLS_SIGNATURE_BYTES {
        return Err(anyhow!(
            "invalid aggregate signature length: expected {BLS_SIGNATURE_BYTES}, got {}",
            agg.signature.len()
        ));
    }

    let aggregate_sig = BlsSignature::sig_validate(&agg.signature, true)
        .map_err(|e| anyhow!("invalid aggregate signature bytes: {e:?}"))?;

    let mut resolver = SignerResolver::new();
    let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(insts.ops.len());
    let mut pks: Vec<BlsPublicKey> = Vec::with_capacity(insts.ops.len());
    let mut total_message_bytes: usize = 0;

    for (inst, &signer_id) in insts.ops.iter().zip(agg.signer_ids.iter()) {
        let msg = inst.aggregate_signing_message(signer_id)?;
        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "aggregate signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }
        pks.push(resolver.resolve(runtime, signer_id).await?);
        msgs.push(msg);
    }

    let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let pk_refs: Vec<&BlsPublicKey> = pks.iter().collect();
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    if verify_result != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(anyhow!(
            "BLS aggregate signature verification failed: {verify_result:?}"
        ));
    }

    Ok(resolver.signer_map)
}
