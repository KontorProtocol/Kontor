use std::collections::HashMap;

use anyhow::{Result, anyhow};
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use indexer_types::{InstKind, Insts, SignerRef};

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
        let entry = get_signer_entry_by_id(&conn, signer_id)
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

    /// Populate `signer_map` for a signer_id without requiring a registered
    /// BLS pubkey. Used for aggregate `RegisterBlsKey` ops, where the
    /// bls_pubkey is in the Inst payload (no DB row yet) but the executor
    /// still expects the signer_id → x_only_pubkey mapping to be available.
    ///
    /// If `claim_pubkey` is provided (the call site already had the x_only
    /// from a `SignerRef::XOnlyPubkey`), it's used directly; otherwise we read
    /// it from the signers table.
    pub(super) async fn ensure_x_only(
        &mut self,
        runtime: &mut Runtime,
        signer_id: u64,
        claim_pubkey: Option<String>,
    ) -> Result<()> {
        if self.signer_map.contains_key(&signer_id) {
            return Ok(());
        }
        let x_only = match claim_pubkey {
            Some(pk) => pk,
            None => {
                let conn = runtime.get_storage_conn();
                let entry = get_signer_entry_by_id(&conn, signer_id)
                    .await?
                    .ok_or_else(|| anyhow!("unknown signer_id {signer_id}"))?;
                entry.x_only_pubkey.ok_or_else(|| {
                    anyhow!("signer_id {signer_id} is not a user signer (no x_only_pubkey)")
                })?
            }
        };
        self.signer_map.insert(signer_id, x_only);
        Ok(())
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
    // Per-op `gas_limit == 0` on a sponsored op would silently trap the
    // op out-of-fuel on its first instruction — almost certainly a
    // publisher misconfiguration since the publisher signs the bulk and
    // controls the gas_limit. Reject early.
    for (inst, signer) in insts.ops.iter().zip(agg.signers.iter()) {
        if signer.sponsored && inst.gas_limit == 0 {
            return Err(anyhow!(
                "aggregate sponsored op has Inst.gas_limit = 0; \
                 the publisher's commitment must be a positive cap"
            ));
        }
    }
    for inst in &insts.ops {
        match &inst.kind {
            InstKind::Call { .. } | InstKind::RegisterBlsKey { .. } => {}
            InstKind::Publish { .. } => {
                return Err(anyhow!(
                    "aggregate path supports Call and RegisterBlsKey (got Publish)"
                ));
            }
            InstKind::UpdateProvenance { .. } => {
                return Err(anyhow!(
                    "aggregate path supports Call and RegisterBlsKey (got UpdateProvenance)"
                ));
            }
            InstKind::Issuance => {
                return Err(anyhow!(
                    "aggregate path supports Call and RegisterBlsKey (got Issuance)"
                ));
            }
            // Sponsor is a unilateral payer designation — by construction
            // it can have only one signer (the input it rides on) and is
            // not aggregatable across BLS co-signers.
            InstKind::Sponsor => {
                return Err(anyhow!(
                    "aggregate path does not support Sponsor (not aggregatable)"
                ));
            }
        }
    }
    Ok(agg)
}

/// Resolved aggregate output: per-op `signer_id` (after `SignerRef`
/// resolution) paired with the `signer_id → x_only_pubkey` map so the caller
/// can avoid redundant registry lookups during op execution.
#[derive(Debug)]
pub struct AggregateResolved {
    pub signer_ids: Vec<u64>,
    pub signer_map: SignerMap,
}

/// Verify the BLS aggregate signature on an `Insts` envelope.
///
/// Resolves each `SignerRef` to an internal `signer_id`
/// (`SignerRef::SignerId` direct, `SignerRef::XOnlyPubkey` via
/// `get_or_create_identity`), sources the verification BLS pubkey
/// per-op-kind (DB lookup for `Call`; payload bytes for `RegisterBlsKey`,
/// since the registrant has no prior bls_keys row), and verifies the
/// aggregate signature against the per-op signing message
/// `postcard((signer_id, nonce, inst))`.
///
/// For `RegisterBlsKey` ops: aggregate verify proves the supplied
/// bls_pubkey's owner consented to this op, but does NOT establish the
/// x_only_pubkey ↔ bls_pubkey binding — that's the job of
/// `runtime.register_bls_key`'s `RegistrationProof::verify` during op
/// execution.
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
        // Build the signing message and enforce the bytes cap before any
        // identity resolution or DB lookups — keeps oversized payloads from
        // costing us I/O.
        let msg = inst.aggregate_signing_message(
            &agg_signer.identity,
            agg_signer.nonce,
            agg_signer.sponsored,
        )?;
        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "aggregate signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }

        let (signer_id, claim_pubkey) = match &agg_signer.identity {
            SignerRef::SignerId(id) => (*id, None),
            SignerRef::XOnlyPubkey(pk) => {
                let identity = runtime
                    .get_or_create_identity(&pk.to_string())
                    .await
                    .map_err(|e| anyhow!("resolving SignerRef::XOnlyPubkey: {e}"))?;
                (identity.signer_id(), Some(pk.to_string()))
            }
        };

        let pk = match &inst.kind {
            InstKind::RegisterBlsKey { bls_pubkey, .. } => {
                // The registrant has no bls_keys row yet — verify against the
                // bls_pubkey they're submitting. A valid aggregate-sig
                // contribution at this position proves the submitter has the
                // bls_pubkey's secret key. The x_only_pubkey ↔ bls_pubkey
                // binding is established later by RegistrationProof::verify
                // in runtime.register_bls_key.
                let validated = BlsPublicKey::key_validate(bls_pubkey).map_err(|e| {
                    anyhow!("invalid bls_pubkey bytes in RegisterBlsKey (subgroup check): {e:?}")
                })?;
                // Always populate signer_map. PubKey claim gives us the x_only
                // directly; Id claim requires a registry lookup (an existing
                // signer is re-registering or first-registering a BLS key).
                // Downstream `process_aggregate_input` checks this map and
                // silently drops ops whose signer_id isn't in it, so missing
                // an entry would cause a verified op to be skipped.
                resolver
                    .ensure_x_only(runtime, signer_id, claim_pubkey)
                    .await?;
                validated
            }
            _ => resolver.resolve(runtime, signer_id).await?,
        };

        pks.push(pk);
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
