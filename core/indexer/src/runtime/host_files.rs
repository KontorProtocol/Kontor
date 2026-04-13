use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use wasmtime::component::{Accessor, Resource};

use super::{
    ChallengeInput, ContractAddress, Error, RawFileDescriptor, Runtime, VerifyResult,
    fuel::Fuel,
    hash_bytes,
    wit::kontor::built_in,
    wit::{self, FileDescriptor, Signer},
};

impl Runtime {
    async fn _add_file<T>(
        &self,
        accessor: &Accessor<T, Self>,
        file_descriptor: Resource<FileDescriptor>,
    ) -> Result<()> {
        Fuel::AddFile.consume(accessor, self.gauge.as_ref()).await?;
        let table = self.table.lock().await;
        let file_metadata_row = table.get(&file_descriptor)?.file_metadata_row.clone();
        self.file_ledger
            .add_file(&self.storage.conn, &file_metadata_row)
            .await
    }

    async fn _file_id<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
    ) -> Result<String> {
        Fuel::GetFileId
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let table = self.table.lock().await;
        let file_id = table.get(&rep)?.file_metadata_row.file_id.clone();

        Ok(file_id)
    }

    async fn _get_file_descriptor<T>(
        &self,
        accessor: &Accessor<T, Self>,
        file_id: String,
    ) -> Result<Option<Resource<FileDescriptor>>> {
        Fuel::GetFileDescriptor
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let fd = self
            .file_ledger
            .get_file_descriptor(&self.storage.conn, &file_id)
            .await?;
        let mut table = self.table.lock().await;
        match fd {
            Some(file_descriptor) => Ok(Some(table.push(file_descriptor)?)),
            None => Ok(None),
        }
    }

    async fn _from_raw<T>(
        &self,
        accessor: &Accessor<T, Self>,
        raw: RawFileDescriptor,
    ) -> Result<Result<Resource<FileDescriptor>, Error>> {
        Fuel::FromRawFileDescriptor
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let mut table = self.table.lock().await;

        Ok(
            match FileDescriptor::try_from_raw(raw, self.storage.height) {
                Ok(fd) => Ok(table.push(fd)?),
                Err(error) => Err(error),
            },
        )
    }

    async fn _compute_challenge_id<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
        block_height: u64,
        num_challenges: u64,
        seed: Vec<u8>,
        prover_id: String,
    ) -> Result<Result<String, Error>> {
        Fuel::ComputeChallengeId
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let table = self.table.lock().await;
        let file_descriptor = table.get(&rep)?;

        Ok(file_descriptor.compute_challenge_id(block_height, num_challenges, &seed, prover_id))
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

    async fn _proof_challenge_ids<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
    ) -> Result<Vec<String>> {
        Fuel::ProofChallengeIds
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let table = self.table.lock().await;
        let proof = table.get(&rep)?;
        Ok(proof.challenge_ids())
    }

    async fn _proof_verify<T>(
        &self,
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
        challenge_inputs: Vec<ChallengeInput>,
    ) -> Result<Result<VerifyResult, Error>> {
        Fuel::ProofVerify
            .consume(accessor, self.gauge.as_ref())
            .await?;

        let table = self.table.lock().await;
        let proof = table.get(&rep)?;

        let mut challenges = Vec::new();
        for input in &challenge_inputs {
            let fd = match self
                .file_ledger
                .get_file_descriptor(&self.storage.conn, &input.file_id)
                .await?
            {
                Some(fd) => fd,
                None => {
                    return Ok(Err(Error::Validation(format!(
                        "File not found: {}",
                        input.file_id
                    ))));
                }
            };

            match fd.build_challenge(
                input.block_height,
                input.num_challenges,
                &input.seed,
                input.prover_id.clone(),
            ) {
                Ok(challenge) => challenges.push(challenge),
                Err(e) => return Ok(Err(e)),
            }
        }

        let result = self
            .file_ledger
            .verify_proof(&proof.inner, &challenges)
            .await;

        match result {
            Ok(true) => Ok(Ok(VerifyResult::Verified)),
            Ok(false) => Ok(Ok(VerifyResult::Rejected)),
            Err(e) => {
                use kontor_crypto::KontorPoRError;
                match e {
                    KontorPoRError::InvalidInput(_)
                    | KontorPoRError::InvalidChallengeCount { .. }
                    | KontorPoRError::FileNotInLedger { .. } => Ok(Ok(VerifyResult::Invalid)),

                    KontorPoRError::Snark(_) => Ok(Ok(VerifyResult::Rejected)),

                    KontorPoRError::InvalidLedgerRoot { proof_root, reason } => {
                        Ok(Err(Error::Validation(format!(
                            "Invalid ledger root in proof: {} - {}",
                            proof_root, reason
                        ))))
                    }

                    other => Ok(Err(Error::Validation(format!(
                        "Unexpected verification error: {}",
                        other
                    )))),
                }
            }
        }
    }

    pub(crate) async fn _hash<T>(
        &self,
        accessor: &Accessor<T, Runtime>,
        input: String,
    ) -> Result<(String, Vec<u8>)> {
        Fuel::CryptoHash(input.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = hash_bytes(input.as_bytes());
        let s = hex::encode(bs);
        Ok((s, bs.to_vec()))
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

impl built_in::testing::Host for Runtime {}

impl built_in::testing::HostWithStore for Runtime {
    async fn host_error<T>(
        _accessor: &wasmtime::component::Accessor<T, Self>,
    ) -> anyhow::Result<String> {
        #[cfg(debug_assertions)]
        anyhow::bail!("deliberate host error for testing");
        #[cfg(not(debug_assertions))]
        Ok(String::new())
    }

    async fn host_panic<T>(
        _accessor: &wasmtime::component::Accessor<T, Self>,
    ) -> anyhow::Result<String> {
        #[cfg(debug_assertions)]
        panic!("deliberate host panic for testing");
        #[cfg(not(debug_assertions))]
        Ok(String::new())
    }
}

impl built_in::file_registry::Host for Runtime {}

impl built_in::file_registry::HostFileDescriptor for Runtime {}

impl built_in::file_registry::HostWithStore for Runtime {
    async fn add_file<T>(
        accessor: &Accessor<T, Self>,
        file_descriptor: Resource<FileDescriptor>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._add_file(accessor, file_descriptor)
            .await
    }

    async fn get_file_descriptor<T>(
        accessor: &Accessor<T, Self>,
        file_id: String,
    ) -> Result<Option<Resource<FileDescriptor>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_file_descriptor(accessor, file_id)
            .await
    }
}

impl built_in::file_registry::HostFileDescriptorWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FileDescriptor>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn file_id<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._file_id(accessor, rep)
            .await
    }

    async fn from_raw<T>(
        accessor: &Accessor<T, Self>,
        raw: RawFileDescriptor,
    ) -> Result<Result<Resource<FileDescriptor>, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._from_raw(accessor, raw)
            .await
    }

    async fn compute_challenge_id<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<FileDescriptor>,
        block_height: u64,
        num_challenges: u64,
        seed: Vec<u8>,
        prover_id: String,
    ) -> Result<Result<String, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._compute_challenge_id(accessor, rep, block_height, num_challenges, seed, prover_id)
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

    async fn challenge_ids<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
    ) -> Result<Vec<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proof_challenge_ids(accessor, rep)
            .await
    }

    async fn verify<T>(
        accessor: &Accessor<T, Self>,
        rep: Resource<wit::Proof>,
        challenges: Vec<built_in::file_registry::ChallengeInput>,
    ) -> Result<Result<VerifyResult, Error>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proof_verify(accessor, rep, challenges)
            .await
    }
}

impl built_in::crypto::Host for Runtime {}

impl built_in::crypto::HostWithStore for Runtime {
    async fn hash<T>(accessor: &Accessor<T, Self>, input: String) -> Result<(String, Vec<u8>)> {
        accessor
            .with(|mut access| access.get().clone())
            ._hash(accessor, input)
            .await
    }

    async fn hash_with_salt<T>(
        accessor: &Accessor<T, Self>,
        input: String,
        salt: String,
    ) -> Result<(String, Vec<u8>)> {
        accessor
            .with(|mut access| access.get().clone())
            ._hash(accessor, input + salt.as_str())
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

    async fn get_contract_address<T>(accessor: &Accessor<T, Self>) -> Result<ContractAddress> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_contract_address(accessor)
            .await
    }
}
