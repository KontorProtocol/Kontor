use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use kontor_crypto::{
    FieldElement, KontorPoRError, LedgerFrontier, StatelessLedger, aggregate_root_from_files,
    poseidon::calculate_root_commitment, verify_stateless,
};

use crate::database::types::{
    bytes_to_field_element, field_element_to_bytes, validate_padded_len, validate_root,
};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use wasmtime::component::{Accessor, Resource};

use super::{
    ChallengeInput, ContractAddress, Decimal, Error, RawFileDescriptor, Runtime, VerifyResult,
    fuel::Fuel,
    hash_bytes,
    wit::kontor::built_in,
    wit::{self, FileDescriptor, Holder, Signer},
};
use built_in::context::HolderRef;
use stdlib::CheckedArithmetics;

/// Pack frontier peaks into the flat byte blob the contract persists: each peak's
/// canonical 32-byte field repr, concatenated low-height-first.
fn encode_peaks(peaks: &[FieldElement]) -> Vec<u8> {
    let mut out = Vec::with_capacity(peaks.len() * 32);
    for p in peaks {
        out.extend_from_slice(&field_element_to_bytes(p));
    }
    out
}

/// Inverse of [`encode_peaks`]: split the blob into 32-byte chunks and decode each
/// as a canonical field element. Errors on a non-multiple-of-32 length or a
/// non-canonical encoding (corrupt persisted state, never valid input).
fn decode_peaks(bytes: &[u8]) -> Result<Vec<FieldElement>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err(format!(
            "frontier peaks blob length {} is not a multiple of 32",
            bytes.len()
        ));
    }
    let mut peaks = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks_exact(32) {
        let arr: [u8; 32] = chunk.try_into().expect("chunks_exact(32) yields 32 bytes");
        let fe = bytes_to_field_element(&arr)
            .ok_or_else(|| "frontier peak is not a valid field element".to_string())?;
        peaks.push(fe);
    }
    Ok(peaks)
}

impl Runtime {
    async fn _aggregate_root<T>(
        &self,
        accessor: &Accessor<T, Self>,
        files: Vec<(Vec<u8>, u64, u64)>,
    ) -> Result<Result<Vec<u8>, Error>> {
        Fuel::AggregateRoot(files.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;

        // Reduce each (root, padded_len, ledger_index) to (root_field, depth, slot).
        // `root` must be a valid field element (this doubles as validation).
        // kontor-crypto 0.3.0 places each leaf at its stable, append-only `slot`
        // (gaps zero-filled), so there is NO sort — the tree position is the stored
        // slot, not the lexicographic `file_id` rank — and caller order is irrelevant.
        let mut files_rd: Vec<(FieldElement, usize, usize)> = Vec::with_capacity(files.len());
        for (root, padded_len, ledger_index) in files {
            let root = match validate_root(&root) {
                Ok((_, fe)) => fe,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            let depth = match validate_padded_len(padded_len) {
                Ok(d) => d,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            files_rd.push((root, depth, ledger_index as usize));
        }
        match aggregate_root_from_files(&files_rd) {
            Ok(root) => Ok(Ok(root.to_vec())),
            Err(e) => Ok(Err(Error::Validation(format!(
                "aggregate-root failed: {}",
                e
            )))),
        }
    }

    /// Incremental counterpart to `_aggregate_root`: fold this block's new files
    /// into the persisted `LedgerFrontier` and return `(count, peaks, root)`. The
    /// frontier's root is byte-identical to `aggregate_root` over slots `0..count`,
    /// so the contract gets the same valid root at O(k) instead of O(n) per block.
    async fn _frontier_append<T>(
        &self,
        accessor: &Accessor<T, Self>,
        count: u64,
        peaks: Vec<u8>,
        new_files: Vec<(Vec<u8>, u64, u64)>,
    ) -> Result<Result<(u64, Vec<u8>, Vec<u8>), Error>> {
        Fuel::FrontierAppend(new_files.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;

        // Persisted peaks are concatenated 32-byte canonical field reprs, one per set
        // bit of `count`. `from_parts` re-checks that structural invariant.
        let peaks_fe = match decode_peaks(&peaks) {
            Ok(p) => p,
            Err(m) => return Ok(Err(Error::Validation(m))),
        };
        let mut frontier = match LedgerFrontier::from_parts(count, peaks_fe) {
            Ok(f) => f,
            Err(e) => return Ok(Err(Error::Validation(format!("frontier from_parts: {e}")))),
        };

        // The frontier appends contiguously at its current `count`, so each new file's
        // slot must be exactly the next one. Asserting it (rather than trusting the
        // contract's ordering) keeps the incremental root in lock-step with what a
        // full `aggregate_root` over the same slots would produce.
        for (expected_slot, (root, padded_len, ledger_index)) in (count..).zip(new_files) {
            if ledger_index != expected_slot {
                return Ok(Err(Error::Validation(format!(
                    "frontier-append expects contiguous slots: got ledger_index {ledger_index}, expected {expected_slot}"
                ))));
            }
            let root_fe = match validate_root(&root) {
                Ok((_, fe)) => fe,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            let depth = match validate_padded_len(padded_len) {
                Ok(d) => d,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            frontier.append(root_fe, depth);
        }

        Ok(Ok((
            frontier.count(),
            encode_peaks(frontier.peaks()),
            frontier.root().to_vec(),
        )))
    }

    async fn _compute_challenge_id<T>(
        &self,
        accessor: &Accessor<T, Self>,
        file: RawFileDescriptor,
        block_height: u64,
        num_challenges: u64,
        seed: Vec<u8>,
        prover_id: u64,
    ) -> Result<Result<String, Error>> {
        Fuel::ComputeChallengeId
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let fd = match FileDescriptor::try_from_raw(file) {
            Ok(fd) => fd,
            Err(e) => return Ok(Err(e)),
        };
        Ok(fd.compute_challenge_id(block_height, num_challenges, &seed, prover_id))
    }

    async fn _proof_from_bytes<T>(
        &self,
        accessor: &Accessor<T, Self>,
        bytes: Vec<u8>,
    ) -> Result<Result<Resource<wit::Proof>, Error>> {
        Fuel::ProofFromBytes(bytes.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let mut table = self.table.lock().await;
        Ok(match wit::Proof::from_bytes(&bytes) {
            Ok(proof) => Ok(table.push(proof)?),
            Err(error) => Err(error),
        })
    }

    async fn _proof_verify<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
        challenge_inputs: Vec<ChallengeInput>,
        valid_roots: Vec<Vec<u8>>,
        files: Vec<(String, Vec<u8>, u64, u64)>,
    ) -> Result<Result<VerifyResult, Error>> {
        Fuel::ProofVerify
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let table = self.table.lock().await;
        let proof = table.get(&rep)?;

        // Each input carries the file's full metadata (from the contract's own
        // `agreement-data`), so we build the challenges directly — no host lookup.
        let mut challenges = Vec::new();
        for input in &challenge_inputs {
            let fd = match FileDescriptor::try_from_raw(input.file.clone()) {
                Ok(fd) => fd,
                Err(e) => return Ok(Err(e)),
            };
            match fd.build_challenge(
                input.block_height,
                input.num_challenges,
                &input.seed,
                input.prover_id,
            ) {
                Ok(challenge) => challenges.push(challenge),
                Err(e) => return Ok(Err(e)),
            }
        }

        // Validate each accepted root as a canonical field element, not merely 32
        // bytes (mirrors `_aggregate_root`). `is_valid_root` compares the proof root's
        // canonical `to_repr()` against this set, so a non-canonical encoding could
        // never match — it would silently reject an otherwise-valid proof. Insert the
        // canonical bytes `validate_root` returns and surface a clear error instead.
        let mut roots = HashSet::with_capacity(valid_roots.len());
        for r in &valid_roots {
            match validate_root(r) {
                Ok((bytes, _)) => {
                    roots.insert(bytes);
                }
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            }
        }

        // Build the file-registry snapshot the stateless verifier resolves ledger
        // indices from: `file_id -> (stable slot, root-commitment)`. The contract
        // supplies each file's `(file_id, root, padded_len, ledger_index)`; the host
        // validates `root` as a canonical field element and `padded_len` as a positive
        // power of two (same gates as aggregate-root) and derives
        // `rc = calculate_root_commitment(root, depth)` exactly as the crypto ledger
        // does, so the verifier's view matches the prover's.
        let mut file_map: BTreeMap<String, (usize, FieldElement)> = BTreeMap::new();
        for (file_id, root, padded_len, ledger_index) in &files {
            let root_fe = match validate_root(root) {
                Ok((_, fe)) => fe,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            let depth = match validate_padded_len(*padded_len) {
                Ok(d) => d,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            let rc = calculate_root_commitment(root_fe, FieldElement::from(depth as u64));
            file_map.insert(file_id.clone(), (*ledger_index as usize, rc));
        }

        let ledger = StatelessLedger {
            valid_roots: &roots,
            files: &file_map,
        };

        match verify_stateless(&challenges, &proof.inner, &ledger) {
            Ok(true) => Ok(Ok(VerifyResult::Verified)),
            Ok(false) => Ok(Ok(VerifyResult::Rejected)),
            Err(KontorPoRError::InvalidInput(_))
            | Err(KontorPoRError::InvalidChallengeCount { .. }) => Ok(Ok(VerifyResult::Invalid)),
            Err(KontorPoRError::Snark(_)) => Ok(Ok(VerifyResult::Rejected)),
            Err(KontorPoRError::InvalidLedgerRoot { proof_root, reason }) => {
                Ok(Err(Error::Validation(format!(
                    "Invalid ledger root in proof: {} - {}",
                    proof_root, reason
                ))))
            }
            // Invariant violation, NOT a bad proof: `verify_proof` builds `challenges`
            // and `files` from the same agreements, so every challenged file resolves
            // and its root-commitment matches by construction. Reaching here means the
            // host built those two views inconsistently — a node bug, unreachable by any
            // user input. Return a bare `anyhow` error (no wasmtime trap, no inner WIT
            // Error) so the runtime classifies it `NonDeterministic` and shuts the node
            // down, rather than a deterministic reject that would bake a host bug into
            // consensus (and silently diverge once the bug is fixed).
            Err(
                e @ (KontorPoRError::FileNotInLedger { .. } | KontorPoRError::MetadataMismatch),
            ) => Err(anyhow!("invariant violation in verify_proof: {e}")),
            Err(other) => Ok(Err(Error::Validation(format!(
                "Unexpected verification error: {}",
                other
            )))),
        }
    }

    pub(crate) async fn _sha256<T>(
        &self,
        accessor: &Accessor<T, Runtime>,
        input: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Fuel::CryptoHash(input.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(hash_bytes(&input).to_vec())
    }

    /// Recent-window block entropy — see the `crypto.block-entropy` WIT doc. The
    /// window/lookup lives in [`Storage::block_entropy`]; this meters the call.
    pub(crate) async fn _block_entropy<T>(
        &self,
        accessor: &Accessor<T, Runtime>,
        height: u64,
    ) -> Result<Option<Vec<u8>>> {
        Fuel::BlockEntropy
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage.block_entropy(height).await
    }

    pub(crate) async fn _hkdf_derive<T>(
        &self,
        accessor: &Accessor<T, Runtime>,
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Fuel::CryptoHash((ikm.len() + salt.len() + info.len()) as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let salt_ref = if salt.is_empty() {
            None
        } else {
            Some(salt.as_slice())
        };
        let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .map_err(|e| anyhow::anyhow!("HKDF expand error: {}", e))?;
        Ok(okm.to_vec())
    }
}

impl built_in::error::Host for Runtime {}

// Types-only interface (raw-file-descriptor lives here for the cross-contract
// ABI); no functions, so just the marker impl — like `error`.
impl built_in::file_registry_types::Host for Runtime {}

impl built_in::testing::Host for Runtime {}

impl built_in::testing::HostWithStore for Runtime {
    async fn host_error<T>(
        _accessor: &wasmtime::component::Accessor<T, Self>,
    ) -> anyhow::Result<String> {
        #[cfg(feature = "testing")]
        anyhow::bail!("deliberate host error for testing");
        #[cfg(not(feature = "testing"))]
        Ok(String::new())
    }

    async fn host_panic<T>(
        _accessor: &wasmtime::component::Accessor<T, Self>,
    ) -> anyhow::Result<String> {
        #[cfg(feature = "testing")]
        panic!("deliberate host panic for testing");
        #[cfg(not(feature = "testing"))]
        Ok(String::new())
    }
}

impl built_in::file_registry::Host for Runtime {}

impl built_in::file_registry::HostWithStore for Runtime {
    async fn aggregate_root<T>(
        accessor: &Accessor<T, Self>,
        files: Vec<(Vec<u8>, u64, u64)>,
    ) -> Result<Result<Vec<u8>, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._aggregate_root(accessor, files)
            .await
    }

    async fn frontier_append<T>(
        accessor: &Accessor<T, Self>,
        count: u64,
        peaks: Vec<u8>,
        new_files: Vec<(Vec<u8>, u64, u64)>,
    ) -> Result<Result<(u64, Vec<u8>, Vec<u8>), Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._frontier_append(accessor, count, peaks, new_files)
            .await
    }

    async fn compute_challenge_id<T>(
        accessor: &Accessor<T, Self>,
        file: RawFileDescriptor,
        block_height: u64,
        num_challenges: u64,
        seed: Vec<u8>,
        prover_id: u64,
    ) -> Result<Result<String, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._compute_challenge_id(
                accessor,
                file,
                block_height,
                num_challenges,
                seed,
                prover_id,
            )
            .await
    }
}

impl built_in::file_registry::HostProof for Runtime {}

impl built_in::file_registry::HostProofWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<wit::Proof>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn from_bytes<T>(
        accessor: &Accessor<T, Self>,
        bytes: Vec<u8>,
    ) -> Result<Result<Resource<wit::Proof>, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proof_from_bytes(accessor, bytes)
            .await
    }

    async fn verify<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
        challenges: Vec<built_in::file_registry_types::ChallengeInput>,
        valid_roots: Vec<Vec<u8>>,
        files: Vec<(String, Vec<u8>, u64, u64)>,
    ) -> Result<Result<VerifyResult, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proof_verify(accessor, rep, challenges, valid_roots, files)
            .await
    }
}

impl built_in::deposit::Host for Runtime {}

impl built_in::deposit::HostWithStore for Runtime {
    /// The storage-deposit floor for `holder` = the sum of their FROZEN per-row
    /// deposits (integer `deposited_gas`) live across all contracts, priced to token
    /// here (× gas→token). The token consults this on every debit to enforce
    /// `balance - floor >= amount`. NATIVE-ONLY (registered into the native linker):
    /// user contracts read a floor via the token's `floor` view.
    ///
    /// Takes an already-RESOLVED `holder` (not a `holder-ref`): deposits are keyed by
    /// depositor SIGNER-ID, and a holder obtained via `Holder::from_ref` has already had
    /// any x-only-pubkey resolved to its signer-id through that ONE canonical path. The
    /// debit check passes the acting signer's holder; the `floor` view resolves its
    /// `holder-ref` arg first. Non-signer holders (core/burner/utxo) own no deposits → 0.
    async fn storage_floor<T>(
        accessor: &Accessor<T, Self>,
        holder: Resource<Holder>,
    ) -> Result<Decimal> {
        let runtime = accessor.with(|mut access| access.get().clone());
        let holder_ref = {
            let table = runtime.table.lock().await;
            table.get(&holder)?.holder_ref.clone()
        };
        let signer_id = match holder_ref {
            HolderRef::SignerId(id) => id,
            // An x-only pubkey reaching here is UNRESOLVED: the `floor` view resolves
            // its holder-ref (a signers-table lookup) before calling this, so a
            // lingering pubkey means the lookup found no signer-id. For a holder that
            // HAS deposited that's the "unresolved-pubkey floor reads 0" symptom —
            // typically a stale `/view` snapshot where the signer row committed with the
            // deposit isn't visible yet. Log it (still return 0) so the otherwise-silent
            // 0 is greppable alongside the `/view` snapshot-staleness warning.
            HolderRef::XOnlyPubkey(pk) => {
                tracing::warn!(
                    target: "view_snapshot",
                    pubkey = %pk,
                    "storage_floor got an UNRESOLVED x-only pubkey -> returning 0; the \
                     signer-id lookup found nothing (stale /view snapshot?), so a real \
                     deposit would read as 0"
                );
                return Ok(Decimal::try_from(0u64)?);
            }
            // Core / burner / utxo holders own no deposits — 0 is correct, no warning.
            _ => return Ok(Decimal::try_from(0u64)?),
        };
        // O(1) read of the eager `depositor_footprint` cache (maintained in the write
        // path), not a fresh cross-contract scan; price the integer-gas floor to token.
        let gas = runtime.storage.footprint().total_gas(signer_id).await?;
        Ok(Decimal::try_from(gas)?.mul(runtime.gas_to_token_multiplier)?)
    }
}

impl built_in::crypto::Host for Runtime {}

impl built_in::crypto::HostWithStore for Runtime {
    async fn sha256<T>(accessor: &Accessor<T, Self>, input: Vec<u8>) -> Result<Vec<u8>> {
        accessor
            .with(|mut access| access.get().clone())
            ._sha256(accessor, input)
            .await
    }

    async fn hkdf_derive<T>(
        accessor: &Accessor<T, Self>,
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>> {
        accessor
            .with(|mut access| access.get().clone())
            ._hkdf_derive(accessor, ikm, salt, info)
            .await
    }

    async fn block_entropy<T>(
        accessor: &Accessor<T, Self>,
        height: u64,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._block_entropy(accessor, height)
            .await
    }
}

impl built_in::foreign::Host for Runtime {}

impl built_in::foreign::HostWithStore for Runtime {
    async fn call<T>(
        accessor: &Accessor<T, Self>,
        signer: Option<Resource<Signer>>,
        contract_address: ContractAddress,
        expr: String,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._call(accessor, signer, &contract_address, &expr)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{bytes_to_field_element, decode_peaks, encode_peaks};
    use kontor_crypto::FieldElement;

    fn fe(n: u8) -> FieldElement {
        let mut b = [0u8; 32];
        b[0] = n;
        bytes_to_field_element(&b).expect("small canonical repr is a valid field element")
    }

    #[test]
    fn peaks_roundtrip() {
        let peaks: Vec<FieldElement> = (1..=5u8).map(fe).collect();
        let encoded = encode_peaks(&peaks);
        assert_eq!(encoded.len(), peaks.len() * 32);
        assert_eq!(decode_peaks(&encoded).expect("roundtrip decodes"), peaks);
    }

    #[test]
    fn empty_peaks_roundtrip() {
        assert!(encode_peaks(&[]).is_empty());
        assert!(decode_peaks(&[]).expect("empty decodes").is_empty());
    }

    #[test]
    fn decode_rejects_non_multiple_of_32() {
        assert!(decode_peaks(&[0u8; 31]).is_err());
        assert!(decode_peaks(&[0u8; 33]).is_err());
    }

    // Pins the exact mechanism behind `create_agreement` validating a lone descriptor
    // at slot 0 rather than its real `ledger_index`: `aggregate_root`'s sparsity guard
    // (implied leaf_count may exceed file_count by at most MAX_LEDGER_INDEX_SPARSITY_GAP
    // = 1024) is correct for the whole set but, for ONE file in isolation, reads a high
    // absolute slot as maximal sparsity and rejects it. Passing the absolute slot here
    // hard-capped the registry at ~1025 files; slot 0 always validates. (The full-set
    // fold uses contiguous slots, where leaf_count == file_count, so it never trips.)
    #[test]
    fn single_file_aggregate_validates_at_slot_0_but_caps_at_absolute_slot() {
        let root = fe(7); // any canonical field element
        let depth = 8usize; // padded_len 256
        assert!(
            kontor_crypto::aggregate_root_from_files(&[(root, depth, 0)]).is_ok(),
            "a lone file validates at slot 0 regardless of registry size"
        );
        assert!(
            kontor_crypto::aggregate_root_from_files(&[(root, depth, 1024)]).is_ok(),
            "slot 1024 still fits (gap == 1024)"
        );
        assert!(
            kontor_crypto::aggregate_root_from_files(&[(root, depth, 1025)]).is_err(),
            "slot 1025 trips the sparsity guard (gap 1025 > 1024) — the old ~1025-file cap; \
             create_agreement must validate at slot 0, not the absolute ledger_index"
        );
    }
}
