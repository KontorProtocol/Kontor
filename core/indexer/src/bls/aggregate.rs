use std::collections::HashMap;

use anyhow::{Result, anyhow};
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use indexer_types::{InstKind, Insts, SignerClaim};

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
    if agg.signers.len() != insts.ops.len() {
        return Err(anyhow!(
            "signers length ({}) != ops length ({})",
            agg.signers.len(),
            insts.ops.len()
        ));
    }
    // Publisher's sponsorship offer must be a positive cap when present.
    // `Some(0)` would silently trap every sponsored op out-of-fuel on the
    // first instruction — almost certainly a publisher misconfiguration, so
    // reject the whole bulk.
    if let Some(0) = agg.publisher_sponsorship {
        return Err(anyhow!(
            "AggregateInfo.publisher_sponsorship = Some(0) is invalid; \
             use None to opt out of sponsorship"
        ));
    }
    for inst in &insts.ops {
        match &inst.kind {
            InstKind::Call { .. } => {}
            InstKind::RegisterBlsKey { .. } => {
                return Err(anyhow!(
                    "RegisterBlsKey is not allowed in aggregate path (use direct)"
                ));
            }
            InstKind::Publish { .. } => {
                return Err(anyhow!("aggregate path only supports Call (got Publish)"));
            }
            InstKind::Issuance => {
                return Err(anyhow!("aggregate path only supports Call (got Issuance)"));
            }
        }
    }
    Ok(agg)
}

/// Resolved aggregate output: per-op `signer_id` (after `SignerClaim`
/// resolution) paired with the `signer_id → x_only_pubkey` map so the caller
/// can avoid redundant registry lookups during op execution.
#[derive(Debug)]
pub struct AggregateResolved {
    pub signer_ids: Vec<u64>,
    pub signer_map: SignerMap,
}

/// Verify the BLS aggregate signature on an `Insts` envelope.
///
/// Resolves each `SignerClaim` to an internal `signer_id`
/// (`SignerClaim::Id` direct, `SignerClaim::PubKey` via
/// `get_or_create_identity`), looks up each signer's registered BLS pubkey,
/// and verifies the aggregate signature against the per-op signing message
/// `postcard((signer_id, nonce, inst))`.
pub async fn verify_aggregate(runtime: &mut Runtime, insts: &Insts) -> Result<AggregateResolved> {
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
    let mut signer_ids: Vec<u64> = Vec::with_capacity(insts.ops.len());
    let mut total_message_bytes: usize = 0;

    for (inst, agg_signer) in insts.ops.iter().zip(agg.signers.iter()) {
        let signer_id = match &agg_signer.identity {
            SignerClaim::Id(id) => *id,
            SignerClaim::PubKey(pk) => {
                let identity = runtime
                    .get_or_create_identity(&pk.to_string())
                    .await
                    .map_err(|e| anyhow!("resolving SignerClaim::PubKey: {e}"))?;
                identity.signer_id() as u64
            }
        };
        let msg = inst.aggregate_signing_message(signer_id, agg_signer.nonce)?;
        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "aggregate signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }
        pks.push(resolver.resolve(runtime, signer_id).await?);
        msgs.push(msg);
        signer_ids.push(signer_id);
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

    Ok(AggregateResolved {
        signer_ids,
        signer_map: resolver.signer_map,
    })
}
