use anyhow::Result;
use hkdf::Hkdf;
use kontor_crypto::{
    FieldElement, KontorPoRError, StatelessLedger, aggregate_root_from_files,
    poseidon::calculate_root_commitment, verify_stateless,
};

use crate::database::types::{padded_len_to_depth, validate_root};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use wasmtime::component::{Accessor, Resource};

use super::{
    ChallengeInput, ContractAddress, Error, RawFileDescriptor, Runtime, VerifyResult,
    fuel::Fuel,
    hash_bytes,
    wit::kontor::built_in,
    wit::{self, FileDescriptor, Signer},
};

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
            files_rd.push((root, padded_len_to_depth(padded_len), ledger_index as usize));
        }
        match aggregate_root_from_files(&files_rd) {
            Ok(root) => Ok(Ok(root.to_vec())),
            Err(e) => Ok(Err(Error::Validation(format!(
                "aggregate-root failed: {}",
                e
            )))),
        }
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
        // validates `root` as a canonical field element (same gate as aggregate-root)
        // and derives `rc = calculate_root_commitment(root, depth)` exactly as the
        // crypto ledger does, so the verifier's view matches the prover's.
        let mut file_map: BTreeMap<String, (usize, FieldElement)> = BTreeMap::new();
        for (file_id, root, padded_len, ledger_index) in &files {
            let root_fe = match validate_root(root) {
                Ok((_, fe)) => fe,
                Err(m) => return Ok(Err(Error::Validation(m.to_string()))),
            };
            let depth = padded_len_to_depth(*padded_len);
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
