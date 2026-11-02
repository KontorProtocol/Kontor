use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use malachitebft_app::types::Keypair;
use malachitebft_signing_ed25519::PrivateKey;
use rand::Rng;
use sha3::{Digest, Keccak256};

use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::identity::ChainId;

use super::{DurableSigner, SignerIdentity, SigningError};

const MAGIC: &[u8; 4] = b"KGO1";
// Header: magic || chain[32] || network seed[32] || Keccak256(prefix).
// Records: u64_be(generation) || validator tag || validator[32] ||
// Keccak256(domain || previous digest || record payload), starting from the header digest.
const HEADER_BYTES: usize = 100;
const RECORD_BYTES: usize = 73;
const RECORD_DOMAIN: &[u8] = b"kontor/engine-generation/v1\0";

struct State {
    journal: File,
    digest: [u8; 32],
    last: u64,
    active: Option<u64>,
    seen_validators: BTreeSet<[u8; 32]>,
    fault: Option<String>,
}

pub(crate) struct GenerationOwner {
    directory: PathBuf,
    chain: ChainId,
    network_key: [u8; 32],
    state: Mutex<State>,
    _ownership: File,
}

#[derive(Clone)]
pub(crate) struct OwnedGeneration {
    owner: Arc<GenerationOwner>,
    generation: u64,
    validator: Option<[u8; 32]>,
    prior_validator_seen: bool,
}

impl GenerationOwner {
    pub(crate) fn open(directory: &Path, chain: ChainId) -> Result<Arc<Self>, SigningError> {
        let existed = path_present(directory)?;
        fs::create_dir_all(directory).map_err(storage)?;
        if !fs::symlink_metadata(directory)
            .map_err(storage)?
            .file_type()
            .is_dir()
        {
            return Err(fault("generation owner directory is not a plain directory"));
        }
        let directory = fs::canonicalize(directory).map_err(storage)?;
        if !existed && let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
        let lock_path = directory.join("generation.lock");
        let journal_path = directory.join("generations.log");
        let lock_existed = path_present(&lock_path)?;
        let journal_existed = path_present(&journal_path)?;
        if lock_existed != journal_existed {
            return Err(fault("generation lock and journal presence differ"));
        }
        if !journal_existed
            && (path_present(&directory.join("signatures.log"))?
                || path_present(&directory.join("signers"))?)
        {
            return Err(fault("signing history exists without generation journal"));
        }
        let ownership = if lock_existed {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(storage)?
        } else {
            open_private_new(&lock_path).map_err(storage)?
        };
        ownership
            .try_lock()
            .map_err(|error| SigningError::Storage(error.to_string()))?;
        verify_private_regular(&lock_path, &ownership)?;
        if !lock_existed {
            sync_directory(&directory)?;
        }
        let (mut journal, network_key, mut digest) = if journal_existed {
            let mut journal = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&journal_path)
                .map_err(storage)?;
            verify_private_regular(&journal_path, &journal)?;
            let mut header = [0u8; HEADER_BYTES];
            journal.read_exact(&mut header).map_err(storage)?;
            let expected = hash(&header[..68]);
            if &header[..4] != MAGIC || header[4..36] != chain.0 || header[68..] != expected {
                return Err(fault("generation journal header differs"));
            }
            let mut network_key = [0; 32];
            network_key.copy_from_slice(&header[36..68]);
            (journal, network_key, expected)
        } else {
            let mut journal = open_private_new(&journal_path).map_err(storage)?;
            verify_private_regular(&journal_path, &journal)?;
            let mut network_key = [0; 32];
            rand::rng().fill_bytes(&mut network_key);
            let mut header = [0u8; HEADER_BYTES];
            header[..4].copy_from_slice(MAGIC);
            header[4..36].copy_from_slice(&chain.0);
            header[36..68].copy_from_slice(&network_key);
            let checksum = hash(&header[..68]);
            header[68..].copy_from_slice(&checksum);
            journal.write_all(&header).map_err(storage)?;
            journal.sync_all().map_err(storage)?;
            sync_directory(&directory)?;
            (journal, network_key, checksum)
        };
        let mut last = 0u64;
        let mut seen_validators = BTreeSet::new();
        while let Some((generation, validator, next_digest)) = read_record(&mut journal, digest)? {
            if last.checked_add(1) != Some(generation) {
                return Err(fault("generation journal is not consecutive"));
            }
            last = generation;
            digest = next_digest;
            if let Some(validator) = validator {
                seen_validators.insert(validator);
            }
        }
        if journal_existed && last == 0 {
            return Err(fault("existing generation journal has no reservation"));
        }
        Ok(Arc::new(Self {
            directory,
            chain,
            network_key,
            state: Mutex::new(State {
                journal,
                digest,
                last,
                active: None,
                seen_validators,
                fault: None,
            }),
            _ownership: ownership,
        }))
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        validator: Option<[u8; 32]>,
    ) -> Result<OwnedGeneration, SigningError> {
        let mut state = self.state.lock().map_err(poisoned)?;
        if let Some(reason) = &state.fault {
            return Err(SigningError::Fault(reason.clone()));
        }
        if state.active.is_some() {
            return Err(SigningError::InvalidRequest(
                "previous engine generation has not joined".into(),
            ));
        }
        let generation = state.last.checked_add(1).ok_or(SigningError::Stale)?;
        let prior_validator_seen =
            validator.is_some_and(|key| state.seen_validators.contains(&key));
        if let Err(error) = append_record(&mut state, generation, validator) {
            state.fault = Some(error.to_string());
            return Err(error);
        }
        state.last = generation;
        state.active = Some(generation);
        if let Some(validator) = validator {
            state.seen_validators.insert(validator);
        }
        Ok(OwnedGeneration {
            owner: Arc::clone(self),
            generation,
            validator,
            prior_validator_seen,
        })
    }
}

impl OwnedGeneration {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn network_key(&self) -> [u8; 32] {
        self.owner.network_key
    }

    pub(crate) fn validate_signer(
        &self,
        signer: Option<&DurableSigner>,
    ) -> Result<(), SigningError> {
        self.with_active(|| match (self.validator, signer) {
            (None, None) => Ok(()),
            (Some(validator), Some(signer))
                if signer.public_key == validator
                    && signer.identity.generation == self.generation
                    && signer.identity.context.chain == self.owner.chain
                    && signer.owned_generation.as_ref().is_some_and(|owned| {
                        Arc::ptr_eq(&owned.owner, &self.owner)
                            && owned.generation == self.generation
                            && owned.validator == self.validator
                    }) =>
            {
                Ok(())
            }
            _ => Err(SigningError::InvalidRequest(
                "signer does not belong to reserved engine generation".into(),
            )),
        })
    }

    // The node calls this only after the engine worker joined, or startup created no worker.
    // Dropping a token does not release the active generation after a timeout.
    pub(crate) fn joined(&self) -> Result<(), SigningError> {
        let mut state = self.owner.state.lock().map_err(poisoned)?;
        match state.active {
            Some(active) if active == self.generation => {
                state.active = None;
                Ok(())
            }
            None if state.last == self.generation => Ok(()),
            _ => Err(SigningError::Stale),
        }
    }

    pub(super) fn with_active<T>(
        &self,
        operation: impl FnOnce() -> Result<T, SigningError>,
    ) -> Result<T, SigningError> {
        let state = self.owner.state.lock().map_err(poisoned)?;
        if let Some(reason) = &state.fault {
            return Err(SigningError::Fault(reason.clone()));
        }
        match state.active {
            Some(active) if active == self.generation => operation(),
            Some(_) => Err(SigningError::Stale),
            None => Err(SigningError::Fenced),
        }
    }

    pub(super) fn signer_identity(
        &self,
        context: EraContext,
        key: &PrivateKey,
    ) -> Result<SignerIdentity, SigningError> {
        if context.chain != self.owner.chain || self.validator != Some(*key.public_key().as_bytes())
        {
            return Err(SigningError::InvalidRequest(
                "signer key or chain differs from reserved generation".into(),
            ));
        }
        let network_keypair = Keypair::ed25519_from_bytes(self.owner.network_key)
            .map_err(|_| SigningError::InvalidRequest("invalid persisted network key".into()))?;
        Ok(SignerIdentity {
            context,
            generation: self.generation,
            network_peer_id: network_keypair.public().to_peer_id().to_bytes(),
        })
    }

    pub(super) fn signer_directory(&self, public_key: &[u8; 32]) -> Result<PathBuf, SigningError> {
        let parent = self.owner.directory.join("signers");
        let existed = path_present(&parent)?;
        fs::create_dir_all(&parent).map_err(storage)?;
        if !fs::symlink_metadata(&parent)
            .map_err(storage)?
            .file_type()
            .is_dir()
        {
            return Err(fault("signer parent is not a plain directory"));
        }
        if !existed {
            sync_directory(&self.owner.directory)?;
        }
        let directory = parent.join(hex::encode(public_key));
        let signer_existed = path_present(&directory)?;
        if signer_existed
            && !fs::symlink_metadata(&directory)
                .map_err(storage)?
                .file_type()
                .is_dir()
        {
            return Err(fault("signer directory is not a plain directory"));
        }
        if self.prior_validator_seen && !signer_existed {
            return Err(fault("previous signer directory is missing"));
        }
        if signer_existed && !path_present(&directory.join("signatures.log"))? {
            return Err(fault("existing signer directory has no signing journal"));
        }
        Ok(directory)
    }
}

fn append_record(
    state: &mut State,
    generation: u64,
    validator: Option<[u8; 32]>,
) -> Result<(), SigningError> {
    let mut payload = [0u8; 41];
    payload[..8].copy_from_slice(&generation.to_be_bytes());
    if let Some(validator) = validator {
        payload[8] = 1;
        payload[9..].copy_from_slice(&validator);
    }
    let digest = record_hash(state.digest, &payload);
    state.journal.seek(SeekFrom::End(0)).map_err(storage)?;
    state.journal.write_all(&payload).map_err(storage)?;
    state.journal.write_all(&digest).map_err(storage)?;
    state.journal.sync_all().map_err(storage)?;
    state.digest = digest;
    Ok(())
}

type GenerationRecord = (u64, Option<[u8; 32]>, [u8; 32]);

fn read_record(
    journal: &mut File,
    previous: [u8; 32],
) -> Result<Option<GenerationRecord>, SigningError> {
    let mut record = [0u8; RECORD_BYTES];
    if journal.read(&mut record[..1]).map_err(storage)? == 0 {
        return Ok(None);
    }
    journal.read_exact(&mut record[1..]).map_err(storage)?;
    let mut payload = [0u8; 41];
    payload.copy_from_slice(&record[..41]);
    let digest = record_hash(previous, &payload);
    if record[41..] != digest {
        return Err(fault("generation journal record digest differs"));
    }
    let generation = u64::from_be_bytes(payload[..8].try_into().expect("fixed length"));
    let validator = match payload[8] {
        0 if payload[9..].iter().all(|byte| *byte == 0) => None,
        1 => Some(payload[9..].try_into().expect("fixed length")),
        _ => return Err(fault("generation journal validator tag is invalid")),
    };
    Ok(Some((generation, validator, digest)))
}

fn record_hash(previous: [u8; 32], payload: &[u8; 41]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(previous);
    hasher.update(payload);
    hasher.finalize().into()
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn open_private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn path_present(path: &Path) -> Result<bool, SigningError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage(error)),
    }
}

fn verify_private_regular(path: &Path, file: &File) -> Result<(), SigningError> {
    if !fs::symlink_metadata(path)
        .map_err(storage)?
        .file_type()
        .is_file()
        || !file.metadata().map_err(storage)?.file_type().is_file()
    {
        return Err(fault("generation owner file is not a plain file"));
    }
    #[cfg(unix)]
    if file.metadata().map_err(storage)?.permissions().mode() & 0o077 != 0 {
        return Err(fault("generation owner file permissions are not private"));
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), SigningError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(storage)
}

fn storage(error: io::Error) -> SigningError {
    SigningError::Storage(error.to_string())
}

fn fault(reason: &str) -> SigningError {
    SigningError::Fault(reason.into())
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> SigningError {
    fault("generation owner lock poisoned")
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use malachitebft_core_types::{NilOrVal, Round};
    use tempfile::TempDir;

    use super::*;
    use crate::consensus::test_fixtures;
    use crate::consensus::{Address, Height, Vote};
    use crate::protocol::coordinator::durable_signer::{DurableSigner, SigningRequest, VoteStep};

    fn directory(root: &TempDir) -> PathBuf {
        root.path().join("local-authority")
    }

    fn open_owner(root: &TempDir) -> Arc<GenerationOwner> {
        GenerationOwner::open(&directory(root), test_fixtures::context().chain).unwrap()
    }

    #[test]
    fn reservation_survives_crash_and_preserves_separate_network_identity() {
        let root = TempDir::new().unwrap();
        let first = open_owner(&root);
        let generation = first.reserve(None).unwrap();
        assert_eq!(generation.generation(), 1);
        let network_key = generation.network_key();
        assert_ne!(network_key, [11; 32]);
        assert!(matches!(
            first.reserve(None),
            Err(SigningError::InvalidRequest(_))
        ));
        assert!(matches!(
            GenerationOwner::open(&directory(&root), test_fixtures::context().chain),
            Err(SigningError::Storage(_))
        ));
        drop(generation);
        assert!(matches!(
            first.reserve(None),
            Err(SigningError::InvalidRequest(_))
        ));
        drop(first);

        let reopened = open_owner(&root);
        let second = reopened.reserve(None).unwrap();
        assert_eq!(second.generation(), 2);
        assert_eq!(second.network_key(), network_key);
        second.joined().unwrap();
        let third = reopened.reserve(None).unwrap();
        assert_eq!(third.generation(), 3);
    }

    #[test]
    fn joined_token_cannot_sign_or_clear_a_new_generation() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let key = PrivateKey::from([11; 32]);
        let public = *key.public_key().as_bytes();
        let follower = owner.reserve(None).unwrap();
        let network_key = follower.network_key();
        follower.joined().unwrap();
        let validator = owner.reserve(Some(public)).unwrap();
        assert_eq!(validator.generation(), 2);
        assert_eq!(validator.network_key(), network_key);
        assert!(matches!(
            DurableSigner::open_owned(
                validator.clone(),
                test_fixtures::context(),
                PrivateKey::from([12; 32]),
            ),
            Err(SigningError::InvalidRequest(_))
        ));
        let mut wrong_chain = test_fixtures::context();
        wrong_chain.chain = ChainId([99; 32]);
        assert!(matches!(
            DurableSigner::open_owned(validator.clone(), wrong_chain, key.clone()),
            Err(SigningError::InvalidRequest(_))
        ));
        assert!(matches!(
            DurableSigner::open_owned(follower.clone(), test_fixtures::context(), key.clone()),
            Err(SigningError::Fenced | SigningError::Stale)
        ));
        let signer =
            DurableSigner::open_owned(validator.clone(), test_fixtures::context(), key.clone())
                .unwrap();
        let address = Address::from_public_key(&key.public_key());
        let vote = Vote::new_prevote(Height::new(1), Round::new(0), NilOrVal::Nil, address);
        let request = SigningRequest::Vote {
            generation: validator.generation(),
            height: 1,
            round: 0,
            step: VoteStep::Prevote,
            value_id: None,
            validator_address: address.into_inner(),
            preimage: vote.to_sign_bytes().to_vec(),
        };
        signer.sign(request.clone()).unwrap();
        signer.fence_generation(validator.generation()).unwrap();
        validator.joined().unwrap();
        assert!(matches!(
            signer.sign(request.clone()),
            Err(SigningError::Fenced)
        ));
        assert!(matches!(
            DurableSigner::open_owned(validator.clone(), test_fixtures::context(), key.clone()),
            Err(SigningError::Fenced)
        ));
        let next = owner.reserve(Some(public)).unwrap();
        assert_eq!(next.generation(), 3);
        assert!(matches!(signer.sign(request), Err(SigningError::Stale)));
        assert_eq!(follower.joined(), Err(SigningError::Stale));
        assert_eq!(validator.joined(), Err(SigningError::Stale));
        assert!(matches!(
            owner.reserve(None),
            Err(SigningError::InvalidRequest(_))
        ));
        drop(signer);
        let reopened =
            DurableSigner::open_owned(next.clone(), test_fixtures::context(), key).unwrap();
        assert_eq!(reopened.public_key(), public);
    }

    #[test]
    fn admission_requires_exact_owner_generation_and_mode() {
        let root = TempDir::new().unwrap();
        let other_root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let other_owner = open_owner(&other_root);
        let key = PrivateKey::from([11; 32]);
        let public = *key.public_key().as_bytes();
        let other_follower = other_owner.reserve(None).unwrap();
        other_follower.joined().unwrap();
        let other = other_owner.reserve(Some(public)).unwrap();
        let other_signer =
            DurableSigner::open_owned(other, test_fixtures::context(), key.clone()).unwrap();
        let follower = owner.reserve(None).unwrap();
        follower.validate_signer(None).unwrap();
        assert!(matches!(
            follower.validate_signer(Some(&other_signer)),
            Err(SigningError::InvalidRequest(_))
        ));
        follower.joined().unwrap();

        let validator = owner.reserve(Some(public)).unwrap();
        assert_eq!(validator.generation(), 2);
        assert!(matches!(
            validator.validate_signer(None),
            Err(SigningError::InvalidRequest(_))
        ));
        assert!(matches!(
            validator.validate_signer(Some(&other_signer)),
            Err(SigningError::InvalidRequest(_))
        ));
        let raw = DurableSigner::open(
            &root.path().join("raw-signer"),
            validator
                .signer_identity(test_fixtures::context(), &key)
                .unwrap(),
            key.clone(),
        )
        .unwrap();
        assert!(matches!(
            validator.validate_signer(Some(&raw)),
            Err(SigningError::InvalidRequest(_))
        ));
        let owned =
            DurableSigner::open_owned(validator.clone(), test_fixtures::context(), key).unwrap();
        validator.validate_signer(Some(&owned)).unwrap();
        validator.joined().unwrap();
        assert_eq!(
            validator.validate_signer(Some(&owned)),
            Err(SigningError::Fenced)
        );
    }

    #[test]
    fn missing_or_truncated_state_and_chain_mismatch_fail_closed() {
        for damage in ["missing", "header", "partial"] {
            let root = TempDir::new().unwrap();
            let owner = open_owner(&root);
            let generation = owner.reserve(None).unwrap();
            drop(generation);
            drop(owner);
            let path = directory(&root).join("generations.log");
            match damage {
                "missing" => fs::remove_file(path).unwrap(),
                "header" => {
                    let file = OpenOptions::new().write(true).open(path).unwrap();
                    file.set_len(HEADER_BYTES as u64).unwrap();
                    file.sync_all().unwrap();
                }
                "partial" => {
                    let file = OpenOptions::new().write(true).open(path).unwrap();
                    file.set_len((HEADER_BYTES + 5) as u64).unwrap();
                    file.sync_all().unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                GenerationOwner::open(&directory(&root), test_fixtures::context().chain).is_err()
            );
        }

        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let generation = owner.reserve(None).unwrap();
        drop(generation);
        drop(owner);
        assert!(matches!(
            GenerationOwner::open(&directory(&root), ChainId([99; 32])),
            Err(SigningError::Fault(_))
        ));
    }

    #[test]
    fn deleted_lock_is_not_recreated_by_repeated_failed_opens() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let generation = owner.reserve(None).unwrap();
        let lock_path = directory(&root).join("generation.lock");
        fs::remove_file(&lock_path).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                GenerationOwner::open(&directory(&root), test_fixtures::context().chain),
                Err(SigningError::Fault(_))
            ));
            assert!(!path_present(&lock_path).unwrap());
        }
        assert!(matches!(
            owner.reserve(None),
            Err(SigningError::InvalidRequest(_))
        ));
        drop(generation);
    }

    #[test]
    fn missing_prior_validator_history_is_not_recreated() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let key = PrivateKey::from([11; 32]);
        let public = *key.public_key().as_bytes();
        let generation = owner.reserve(Some(public)).unwrap();
        let signer =
            DurableSigner::open_owned(generation.clone(), test_fixtures::context(), key.clone())
                .unwrap();
        signer.fence_generation(generation.generation()).unwrap();
        generation.joined().unwrap();
        drop(signer);
        drop(generation);
        drop(owner);
        fs::remove_dir_all(directory(&root).join("signers").join(hex::encode(public))).unwrap();
        let reopened = open_owner(&root);
        let next = reopened.reserve(Some(public)).unwrap();
        assert!(matches!(
            DurableSigner::open_owned(next, test_fixtures::context(), key),
            Err(SigningError::Fault(_))
        ));
    }

    #[test]
    fn signing_history_prevents_reinitializing_a_lost_generation_journal() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let key = PrivateKey::from([11; 32]);
        let generation = owner.reserve(Some(*key.public_key().as_bytes())).unwrap();
        let signer =
            DurableSigner::open_owned(generation.clone(), test_fixtures::context(), key).unwrap();
        signer.fence_generation(generation.generation()).unwrap();
        generation.joined().unwrap();
        drop(signer);
        drop(generation);
        drop(owner);
        fs::remove_file(directory(&root).join("generations.log")).unwrap();
        fs::remove_file(directory(&root).join("generation.lock")).unwrap();
        assert!(matches!(
            GenerationOwner::open(&directory(&root), test_fixtures::context().chain),
            Err(SigningError::Fault(_))
        ));
        assert!(!path_present(&directory(&root).join("generation.lock")).unwrap());
    }

    #[test]
    fn failed_reservation_is_sticky_and_never_returns_a_generation() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let first = owner.reserve(None).unwrap();
        first.joined().unwrap();
        owner.state.lock().unwrap().journal =
            File::open(directory(&root).join("generations.log")).unwrap();
        assert!(matches!(owner.reserve(None), Err(SigningError::Storage(_))));
        assert!(matches!(owner.reserve(None), Err(SigningError::Fault(_))));
        drop(first);
        drop(owner);
        let reopened = open_owner(&root);
        assert_eq!(reopened.reserve(None).unwrap().generation(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn network_identity_file_is_private() {
        let root = TempDir::new().unwrap();
        let owner = open_owner(&root);
        let generation = owner.reserve(None).unwrap();
        let mode = fs::metadata(directory(&root).join("generations.log"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        drop(generation);
    }
}
