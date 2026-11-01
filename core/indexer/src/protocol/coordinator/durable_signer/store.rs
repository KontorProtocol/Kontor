use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use malachitebft_signing_ed25519::{PrivateKey, Signature};
use sha3::{Digest, Keccak256};

use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::coordinator::certified_input::EraContext;
use crate::protocol::identity::{ChainId, ProtocolId};

use super::{MAX_SIGNING_PREIMAGE_BYTES, SignerIdentity, SigningError};

const MAGIC: &[u8; 4] = b"KDS1";
const MAX_RECORD_BYTES: usize = 4096;
// Journal header: magic || chain[32] || validator[32]. Each frame is u32_be(payload length)
// || canonical_codec payload || Keccak256(previous frame hash || length || payload), seeded at zero.
// A sign record stores the preimage length and Keccak256(domain || u64_be(length) || canonical preimage).
// Replay cannot recover the preimage, so exact retries validate it again and verify the stored signature.
const MESSAGE_DOMAIN: &[u8] = b"kontor/durable-signing-message/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EntryRole {
    Proposal,
    ProposalFin,
    Prevote,
    Precommit,
    ValidatorProof,
}

impl EntryRole {
    fn tag(self) -> u8 {
        match self {
            Self::Proposal => 1,
            Self::ProposalFin => 2,
            Self::Prevote => 3,
            Self::Precommit => 4,
            Self::ValidatorProof => 5,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SigningError> {
        match tag {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::ProposalFin),
            3 => Ok(Self::Prevote),
            4 => Ok(Self::Precommit),
            5 => Ok(Self::ValidatorProof),
            _ => Err(corrupt("unknown signing role")),
        }
    }

    fn is_proposal(self) -> bool {
        matches!(self, Self::Proposal | Self::ProposalFin)
    }
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedRequest {
    pub(super) generation: u64,
    pub(super) height: u64,
    pub(super) round: u32,
    pub(super) role: EntryRole,
    pub(super) commitment: Option<Vec<u8>>,
    pub(super) preimage: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SlotKey {
    Consensus(u64, u32, EntryRole),
    Proof(Vec<u8>),
}

#[derive(Clone)]
struct SignedRecord {
    preimage_digest: [u8; 32],
    preimage_length: usize,
    commitment: Option<Vec<u8>>,
    signature: [u8; 64],
}

struct Inner {
    journal: File,
    digest: [u8; 32],
    identity: SignerIdentity,
    fenced: bool,
    maximum: Option<(u64, u32)>,
    slots: BTreeMap<SlotKey, SignedRecord>,
    proposal_commitments: BTreeMap<(u64, u32), Vec<u8>>,
    fault: Option<String>,
}

pub(super) struct Store {
    inner: Mutex<Inner>,
    key: PrivateKey,
    _ownership: File,
}

impl Store {
    pub(super) fn open(
        directory: &Path,
        requested: &SignerIdentity,
        key: PrivateKey,
    ) -> Result<Self, SigningError> {
        let existed = directory.exists();
        fs::create_dir_all(directory).map_err(storage)?;
        if !existed {
            if let Some(parent) = directory.parent() {
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(storage)?;
            }
        }
        let lock_path = directory.join("owner.lock");
        let lock_existed = lock_path.exists();
        let ownership = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(storage)?;
        ownership
            .try_lock()
            .map_err(|error| SigningError::Storage(error.to_string()))?;
        if !lock_existed {
            sync_directory(directory)?;
        }

        let path = directory.join("signatures.log");
        if lock_existed && !path.exists() {
            return Err(corrupt(
                "signer journal disappeared from an owned directory",
            ));
        }
        let (mut journal, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(storage)?,
                false,
            ),
            Err(error) => return Err(storage(error)),
        };
        let public_key = *key.public_key().as_bytes();
        let chain = requested.context.chain.0;
        if created {
            journal.write_all(MAGIC).map_err(storage)?;
            journal.write_all(&chain).map_err(storage)?;
            journal.write_all(&public_key).map_err(storage)?;
            journal.sync_all().map_err(storage)?;
            sync_directory(directory)?;
        } else {
            let mut header = [0; 68];
            journal.read_exact(&mut header).map_err(storage)?;
            if &header[..4] != MAGIC || header[4..36] != chain || header[36..68] != public_key {
                return Err(corrupt("signer journal chain or validator differs"));
            }
        }
        let mut inner = Inner {
            journal,
            digest: [0; 32],
            identity: requested.clone(),
            fenced: false,
            maximum: None,
            slots: BTreeMap::new(),
            proposal_commitments: BTreeMap::new(),
            fault: None,
        };
        let mut current: Option<SignerIdentity> = None;
        while let Some(payload) = inner.read_record()? {
            let mut input = Decoder::new(&payload);
            match input.tag().map_err(codec)? {
                1 => {
                    let identity = decode_identity(&mut input)?;
                    input.finish().map_err(codec)?;
                    if identity.generation == 0
                        || identity.network_peer_id.is_empty()
                        || identity.network_peer_id.len() > 256
                        || identity.context.chain.0 != chain
                        || current
                            .as_ref()
                            .is_some_and(|last| identity.generation <= last.generation)
                    {
                        return Err(corrupt("signing generation did not advance"));
                    }
                    current = Some(identity);
                    inner.fenced = false;
                }
                2 => {
                    let generation = input.u64().map_err(codec)?;
                    input.finish().map_err(codec)?;
                    if current.as_ref().map(|value| value.generation) != Some(generation)
                        || inner.fenced
                    {
                        return Err(corrupt("invalid generation fence"));
                    }
                    inner.fenced = true;
                }
                3 => {
                    let active = current
                        .as_ref()
                        .ok_or_else(|| corrupt("sign before open"))?;
                    if inner.fenced {
                        return Err(corrupt("sign after generation fence"));
                    }
                    let generation = input.u64().map_err(codec)?;
                    let context = decode_context(&mut input)?;
                    let height = input.u64().map_err(codec)?;
                    let round = u32::from_be_bytes(input.fixed().map_err(codec)?);
                    let role = EntryRole::from_tag(input.tag().map_err(codec)?)?;
                    let peer_id = input.bytes().map_err(codec)?.to_vec();
                    let commitment_bytes = input.bytes().map_err(codec)?.to_vec();
                    let preimage_length = usize::try_from(input.u64().map_err(codec)?)
                        .ok()
                        .filter(|length| *length <= MAX_SIGNING_PREIMAGE_BYTES)
                        .ok_or_else(|| corrupt("signing message length invalid"))?;
                    let preimage_digest: [u8; 32] = input.fixed().map_err(codec)?;
                    let signature: [u8; 64] = input.fixed().map_err(codec)?;
                    input.finish().map_err(codec)?;
                    if generation != active.generation
                        || context != active.context
                        || (role == EntryRole::ValidatorProof && peer_id != active.network_peer_id)
                    {
                        return Err(corrupt("signing record context differs"));
                    }
                    let commitment = (!commitment_bytes.is_empty()).then_some(commitment_bytes);
                    let request = ValidatedRequest {
                        generation,
                        height,
                        round,
                        role,
                        commitment,
                        preimage: Vec::new(),
                    };
                    let slot = request.slot(&peer_id)?;
                    inner.admit(&request, &slot)?;
                    inner.record(slot, request, signature, preimage_digest, preimage_length);
                }
                _ => return Err(corrupt("unknown signer journal record")),
            }
        }
        if current.is_none() && !created {
            return Err(corrupt("existing signer journal has no generation record"));
        }
        match current {
            Some(last) if requested.generation < last.generation => {
                return Err(SigningError::Stale);
            }
            Some(last) if requested.generation == last.generation => {
                if inner.fenced {
                    return Err(SigningError::Fenced);
                }
                if *requested != last {
                    return Err(corrupt("signer generation identity differs"));
                }
            }
            _ => {
                inner.append_open(requested)?;
                inner.fenced = false;
            }
        }
        inner.identity = requested.clone();
        Ok(Self {
            inner: Mutex::new(inner),
            key,
            _ownership: ownership,
        })
    }

    pub(super) fn sign(&self, request: ValidatedRequest) -> Result<[u8; 64], SigningError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SigningError::Fault("signer lock poisoned".into()))?;
        inner.available(request.generation)?;
        if request.preimage.len() > MAX_SIGNING_PREIMAGE_BYTES {
            return Err(SigningError::InvalidRequest(
                "signing message exceeds bound".into(),
            ));
        }
        let peer_id = if request.role == EntryRole::ValidatorProof {
            inner.identity.network_peer_id.as_slice()
        } else {
            &[]
        };
        let slot = request.slot(peer_id)?;
        let request_digest = message_digest(&request.preimage);
        if let Some(previous) = inner.slots.get(&slot) {
            let identical = previous.preimage_length == request.preimage.len()
                && previous.preimage_digest == request_digest
                && previous.commitment == request.commitment;
            let signature = previous.signature;
            if !identical {
                return Err(SigningError::Conflict);
            }
            if self
                .key
                .public_key()
                .verify(&request.preimage, &Signature::from_bytes(signature))
                .is_err()
            {
                let reason = "stored signing signature does not verify".to_string();
                inner.fault = Some(reason.clone());
                return Err(SigningError::Fault(reason));
            }
            return Ok(signature);
        }
        inner.admit(&request, &slot)?;
        let signature = self.key.sign(&request.preimage).to_bytes();
        let payload = encode_sign(&inner.identity, &request, &slot, &signature, request_digest)?;
        if let Err(error) = inner.append(&payload) {
            inner.fault = Some(error.to_string());
            return Err(error);
        }
        let preimage_length = request.preimage.len();
        inner.record(slot, request, signature, request_digest, preimage_length);
        Ok(signature)
    }

    pub(super) fn fence_generation(&self, generation: u64) -> Result<(), SigningError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SigningError::Fault("signer lock poisoned".into()))?;
        if let Some(fault) = &inner.fault {
            return Err(SigningError::Fault(fault.clone()));
        }
        if generation != inner.identity.generation {
            return Err(SigningError::Stale);
        }
        if inner.fenced {
            return Ok(());
        }
        let mut output = Encoder::default();
        output.tag(2).map_err(codec)?;
        output.u64(generation).map_err(codec)?;
        if let Err(error) = inner.append(&output.finish()) {
            inner.fault = Some(error.to_string());
            return Err(error);
        }
        inner.fenced = true;
        Ok(())
    }
}

impl ValidatedRequest {
    fn slot(&self, peer_id: &[u8]) -> Result<SlotKey, SigningError> {
        if self.role == EntryRole::ValidatorProof {
            if self.height != 0
                || self.round != 0
                || self.commitment.is_some()
                || peer_id.is_empty()
            {
                return Err(corrupt("invalid validator proof slot"));
            }
            Ok(SlotKey::Proof(peer_id.to_vec()))
        } else {
            if self.height == 0 || !peer_id.is_empty() {
                return Err(corrupt("invalid consensus signing slot"));
            }
            if self.role.is_proposal() != self.commitment.is_some() {
                return Err(corrupt("invalid proposal commitment"));
            }
            Ok(SlotKey::Consensus(self.height, self.round, self.role))
        }
    }
}

impl Inner {
    fn available(&self, generation: u64) -> Result<(), SigningError> {
        if let Some(fault) = &self.fault {
            return Err(SigningError::Fault(fault.clone()));
        }
        if generation != self.identity.generation {
            return Err(SigningError::Stale);
        }
        if self.fenced {
            return Err(SigningError::Fenced);
        }
        Ok(())
    }

    fn admit(&self, request: &ValidatedRequest, slot: &SlotKey) -> Result<(), SigningError> {
        if self.slots.contains_key(slot) {
            return Err(SigningError::Conflict);
        }
        if let SlotKey::Consensus(height, round, role) = slot {
            let position = (*height, *round);
            let known_commitment = self.proposal_commitments.get(&position);
            if role.is_proposal()
                && known_commitment.is_some_and(|value| Some(value) != request.commitment.as_ref())
            {
                return Err(SigningError::Conflict);
            }
            if self.maximum.is_some_and(|maximum| position < maximum)
                && !(role.is_proposal() && known_commitment.is_some())
            {
                return Err(SigningError::Stale);
            }
        }
        Ok(())
    }

    fn record(
        &mut self,
        slot: SlotKey,
        request: ValidatedRequest,
        signature: [u8; 64],
        preimage_digest: [u8; 32],
        preimage_length: usize,
    ) {
        if let SlotKey::Consensus(height, round, role) = &slot {
            let position = (*height, *round);
            self.maximum = Some(self.maximum.map_or(position, |old| old.max(position)));
            if role.is_proposal() {
                self.proposal_commitments
                    .entry(position)
                    .or_insert_with(|| request.commitment.clone().expect("validated proposal"));
            }
        }
        self.slots.insert(
            slot,
            SignedRecord {
                preimage_digest,
                preimage_length,
                commitment: request.commitment,
                signature,
            },
        );
    }

    fn append_open(&mut self, identity: &SignerIdentity) -> Result<(), SigningError> {
        let mut output = Encoder::default();
        output.tag(1).map_err(codec)?;
        encode_identity(&mut output, identity)?;
        self.append(&output.finish())
    }

    fn append(&mut self, payload: &[u8]) -> Result<(), SigningError> {
        let length = u32::try_from(payload.len())
            .ok()
            .filter(|value| *value as usize <= MAX_RECORD_BYTES)
            .ok_or_else(|| corrupt("signer journal record exceeds bound"))?;
        let length = length.to_be_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(self.digest);
        hasher.update(length);
        hasher.update(payload);
        let digest: [u8; 32] = hasher.finalize().into();
        self.journal.seek(SeekFrom::End(0)).map_err(storage)?;
        self.journal.write_all(&length).map_err(storage)?;
        self.journal.write_all(payload).map_err(storage)?;
        self.journal.write_all(&digest).map_err(storage)?;
        self.journal.sync_all().map_err(storage)?;
        self.digest = digest;
        Ok(())
    }

    fn read_record(&mut self) -> Result<Option<Vec<u8>>, SigningError> {
        let mut length = [0; 4];
        let read = self.journal.read(&mut length).map_err(storage)?;
        if read == 0 {
            return Ok(None);
        }
        self.journal
            .read_exact(&mut length[read..])
            .map_err(storage)?;
        let size = u32::from_be_bytes(length) as usize;
        if size == 0 || size > MAX_RECORD_BYTES {
            return Err(corrupt("signer journal frame length invalid"));
        }
        let mut payload = vec![0; size];
        self.journal.read_exact(&mut payload).map_err(storage)?;
        let mut expected = [0; 32];
        self.journal.read_exact(&mut expected).map_err(storage)?;
        let mut hasher = Keccak256::new();
        hasher.update(self.digest);
        hasher.update(length);
        hasher.update(&payload);
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected {
            return Err(corrupt("signer journal frame digest differs"));
        }
        self.digest = actual;
        Ok(Some(payload))
    }
}

fn encode_context(output: &mut Encoder, context: EraContext) -> Result<(), SigningError> {
    output.fixed(&context.chain.0).map_err(codec)?;
    output.fixed(&context.era).map_err(codec)?;
    output.fixed(&context.protocol.0).map_err(codec)?;
    output.fixed(&context.codec.to_be_bytes()).map_err(codec)
}

fn decode_context(input: &mut Decoder<'_>) -> Result<EraContext, SigningError> {
    let chain = input.fixed().map_err(codec)?;
    let era = input.fixed().map_err(codec)?;
    let protocol = input.fixed().map_err(codec)?;
    let codec = u32::from_be_bytes(input.fixed().map_err(codec)?);
    Ok(EraContext {
        chain: ChainId(chain),
        era,
        protocol: ProtocolId(protocol),
        codec,
    })
}

fn encode_identity(output: &mut Encoder, identity: &SignerIdentity) -> Result<(), SigningError> {
    output.u64(identity.generation).map_err(codec)?;
    encode_context(output, identity.context)?;
    output.bytes(&identity.network_peer_id).map_err(codec)
}

fn decode_identity(input: &mut Decoder<'_>) -> Result<SignerIdentity, SigningError> {
    let generation = input.u64().map_err(codec)?;
    Ok(SignerIdentity {
        context: decode_context(input)?,
        generation,
        network_peer_id: input.bytes().map_err(codec)?.to_vec(),
    })
}

fn encode_sign(
    identity: &SignerIdentity,
    request: &ValidatedRequest,
    slot: &SlotKey,
    signature: &[u8; 64],
    preimage_digest: [u8; 32],
) -> Result<Vec<u8>, SigningError> {
    let mut output = Encoder::default();
    output.tag(3).map_err(codec)?;
    output.u64(request.generation).map_err(codec)?;
    encode_context(&mut output, identity.context)?;
    output.u64(request.height).map_err(codec)?;
    output.fixed(&request.round.to_be_bytes()).map_err(codec)?;
    output.tag(request.role.tag()).map_err(codec)?;
    let peer_id = match slot {
        SlotKey::Consensus(..) => &[][..],
        SlotKey::Proof(peer_id) => peer_id.as_slice(),
    };
    output.bytes(peer_id).map_err(codec)?;
    output
        .bytes(request.commitment.as_deref().unwrap_or_default())
        .map_err(codec)?;
    output.u64(request.preimage.len() as u64).map_err(codec)?;
    output.fixed(&preimage_digest).map_err(codec)?;
    output.fixed(signature).map_err(codec)?;
    Ok(output.finish())
}

fn sync_directory(directory: &Path) -> Result<(), SigningError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(storage)
}

fn storage(error: io::Error) -> SigningError {
    SigningError::Storage(error.to_string())
}

fn codec(error: impl std::fmt::Display) -> SigningError {
    corrupt(&error.to_string())
}

fn corrupt(reason: &str) -> SigningError {
    SigningError::Fault(reason.into())
}

fn message_digest(preimage: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(MESSAGE_DOMAIN);
    hasher.update((preimage.len() as u64).to_be_bytes());
    hasher.update(preimage);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;

    use tempfile::TempDir;

    use super::*;
    use crate::consensus::test_fixtures;

    fn identity() -> SignerIdentity {
        SignerIdentity {
            context: test_fixtures::context(),
            generation: 1,
            network_peer_id: vec![3; 38],
        }
    }

    #[test]
    fn missing_journal_in_owned_directory_fails_closed() {
        let directory = TempDir::new().unwrap();
        let store = Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])).unwrap();
        drop(store);
        fs::remove_file(directory.path().join("signatures.log")).unwrap();
        assert!(matches!(
            Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])),
            Err(SigningError::Fault(_))
        ));
    }

    #[test]
    fn truncated_journal_header_fails_closed() {
        let directory = TempDir::new().unwrap();
        let store = Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])).unwrap();
        drop(store);
        let journal = OpenOptions::new()
            .write(true)
            .open(directory.path().join("signatures.log"))
            .unwrap();
        journal.set_len(68).unwrap();
        journal.sync_all().unwrap();
        assert!(matches!(
            Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])),
            Err(SigningError::Fault(_))
        ));
    }

    #[test]
    fn failed_append_is_sticky_and_cannot_return_a_signature() {
        let directory = TempDir::new().unwrap();
        let store = Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])).unwrap();
        let request = ValidatedRequest {
            generation: 1,
            height: 1,
            round: 0,
            role: EntryRole::Prevote,
            commitment: None,
            preimage: b"test-only-preimage".to_vec(),
        };
        store.inner.lock().unwrap().journal =
            File::open(directory.path().join("signatures.log")).unwrap();
        assert!(matches!(
            store.sign(request.clone()),
            Err(SigningError::Storage(_))
        ));
        assert!(matches!(
            store.sign(request.clone()),
            Err(SigningError::Fault(_))
        ));
        assert!(matches!(
            store.fence_generation(1),
            Err(SigningError::Fault(_))
        ));
        drop(store);
        let reopened =
            Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])).unwrap();
        assert!(reopened.sign(request).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_lock_is_close_on_exec() {
        let directory = TempDir::new().unwrap();
        let store = Store::open(directory.path(), &identity(), PrivateKey::from([11; 32])).unwrap();
        let flags = unsafe { libc::fcntl(store._ownership.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
