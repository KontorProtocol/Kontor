use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize;
use bitcoin::key::Secp256k1;
use bitcoin::{
    Address, Block as BitcoinBlock, BlockHash, Network, OutPoint, Transaction, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::super::super::super::{ANCHOR_HEIGHT, decode_block, hash_file};
use super::super::super::replay_identity::SourceIdentity;
use super::super::super::sequence_inputs::BlockInput;
use super::super::run::Settings;
use super::super::work::ApiInput;
use super::super::{Action, Event, Schedule};
use crate::block::filter_map;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRef {
    pub(super) name: String,
    pub(super) sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BlockRef {
    pub(super) hash: BlockHash,
    pub(super) parent: BlockHash,
    pub(super) input: FileRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventRef {
    pub(super) event: Event,
    pub(super) consensus_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) before: String,
    pub(super) state: FileRef,
    pub(super) api_result: Option<FileRef>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EncodedRequest {
    pub(super) ordinal: usize,
    pub(super) commit: String,
    pub(super) reveal: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) schema_version: u32,
    pub(super) source: SourceIdentity,
    pub(super) binary_sha256: String,
    pub(super) settings: Settings,
    pub(super) schedule: Schedule,
    pub(super) bitcoin_version: u64,
    pub(super) initial_consensus_height: u64,
    pub(super) anchor_hash: BlockHash,
    pub(super) canonical_signer: String,
    pub(super) api_signer: String,
    pub(super) snapshot: FileRef,
    pub(super) initial: FileRef,
    pub(super) chain: FileRef,
    pub(super) requests: FileRef,
    pub(super) blocks: Vec<BlockRef>,
    pub(super) events: Vec<EventRef>,
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid timed archive digest"
    );
    Ok(())
}

impl Manifest {
    pub(super) fn anchor(&self, event: &Event) -> Result<BlockHash> {
        let height = match event.action {
            Action::Block { block } => {
                self.schedule
                    .blocks
                    .get(block)
                    .context("missing event block")?
                    .height
                    - 1
            }
            Action::Batch { anchor_height, .. } | Action::Simulation { anchor_height, .. } => {
                anchor_height
            }
        };
        if height == ANCHOR_HEIGHT {
            return Ok(self.anchor_hash);
        }
        let index = usize::try_from(
            height
                .checked_sub(ANCHOR_HEIGHT + 1)
                .context("invalid event anchor")?,
        )?;
        Ok(self.blocks.get(index).context("missing anchor block")?.hash)
    }

    pub(super) fn inventory(&self) -> Result<BTreeMap<String, String>> {
        ensure!(self.schema_version == 3, "unsupported timed archive schema");
        ensure!(
            self.settings.validate()? == self.schedule,
            "timed schedule differs from settings"
        );
        ensure!(
            self.blocks.len() == self.schedule.blocks.len()
                && self.events.len() == self.schedule.events.len()
        );
        let canonical: XOnlyPublicKey = self.canonical_signer.parse()?;
        let api: XOnlyPublicKey = self.api_signer.parse()?;
        ensure!(
            canonical != api
                && canonical.to_string() == self.canonical_signer
                && api.to_string() == self.api_signer
        );
        digest(&self.binary_sha256)?;
        let mut files = BTreeMap::new();
        let mut add = |file: &FileRef, expected: &str| -> Result<()> {
            ensure!(
                file.name == expected,
                "timed archive file role differs: {expected}"
            );
            digest(&file.sha256)?;
            ensure!(
                files
                    .insert(file.name.clone(), file.sha256.clone())
                    .is_none(),
                "duplicate timed archive file"
            );
            Ok(())
        };
        add(&self.snapshot, "snapshot.db")?;
        add(&self.initial, "initial.json")?;
        add(&self.chain, "chain.json")?;
        add(&self.requests, "api-inputs.json")?;
        let mut parent = self.anchor_hash;
        for (ordinal, block) in self.blocks.iter().enumerate() {
            ensure!(block.parent == parent, "timed block parent differs");
            add(&block.input, &format!("block-{ordinal:03}.bin"))?;
            parent = block.hash;
        }
        let mut previous = &self.initial.sha256;
        let mut consensus = self.initial_consensus_height;
        for (ordinal, (record, event)) in self.events.iter().zip(&self.schedule.events).enumerate()
        {
            ensure!(
                record.event == *event && record.before == *previous,
                "timed event or checkpoint predecessor differs"
            );
            if !matches!(event.action, Action::Simulation { .. }) {
                consensus = consensus
                    .checked_add(1)
                    .context("consensus height overflow")?;
            }
            ensure!(
                record.consensus_height == consensus && record.anchor_hash == self.anchor(event)?,
                "timed event consensus or anchor differs"
            );
            add(&record.state, &format!("event-{ordinal:06}.json"))?;
            match (&event.action, &record.api_result) {
                (Action::Simulation { request, .. }, Some(file)) => {
                    add(file, &format!("api-result-{request:06}.json"))?;
                    ensure!(
                        record.state.sha256 == record.before,
                        "simulation checkpoint changes database"
                    );
                }
                (Action::Simulation { .. }, None) | (_, Some(_)) => {
                    return Err(anyhow!("timed API result association differs"));
                }
                (_, None) => {}
            }
            previous = &record.state.sha256;
        }
        Ok(files)
    }
}

pub(super) struct Inputs {
    pub(super) chain: Vec<BitcoinBlock>,
    pub(super) blocks: Vec<BlockInput>,
    pub(super) requests: Vec<ApiInput>,
}

pub(super) struct Saved {
    pub(super) root: PathBuf,
    pub(super) manifest: Manifest,
    pub(super) digest: Option<String>,
}

impl Saved {
    pub(super) fn load(path: &Path, expected: &str) -> Result<Self> {
        digest(expected)?;
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_file(),
            "manifest must be a regular file"
        );
        let path = path.canonicalize()?;
        ensure!(path.file_name().and_then(|name| name.to_str()) == Some("manifest.json"));
        ensure!(
            fs::metadata(&path)?.len() <= 16 * 1024 * 1024,
            "timed manifest exceeds bound"
        );
        ensure!(hash_file(&path)? == expected, "timed manifest hash differs");
        let saved = Self {
            root: path
                .parent()
                .context("missing archive directory")?
                .to_path_buf(),
            manifest: serde_json::from_slice(&fs::read(&path)?)?,
            digest: Some(expected.to_owned()),
        };
        saved.verify()?;
        Ok(saved)
    }

    pub(super) fn verify(&self) -> Result<()> {
        let files = self.manifest.inventory()?;
        let mut expected: BTreeSet<_> = files.keys().cloned().collect();
        if self.digest.is_some() {
            expected.insert("manifest.json".into());
        }
        let mut actual = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "timed archive has a non-regular file"
            );
            actual.insert(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("non-UTF-8 archive file"))?,
            );
        }
        ensure!(actual == expected, "timed archive inventory differs");
        for (name, expected) in files {
            ensure!(
                hash_file(&self.root.join(&name))? == expected,
                "timed archive bytes differ: {name}"
            );
        }
        if let Some(expected) = &self.digest {
            ensure!(
                hash_file(&self.root.join("manifest.json"))? == *expected,
                "timed manifest changed"
            );
        }
        Ok(())
    }

    pub(super) fn bytes(&self, file: &FileRef) -> Result<Vec<u8>> {
        Ok(fs::read(self.root.join(&file.name))?)
    }

    pub(super) fn inputs(&self) -> Result<Inputs> {
        self.verify()?;
        let encoded: Vec<String> = serde_json::from_slice(&self.bytes(&self.manifest.chain)?)?;
        ensure!(encoded.len() == usize::try_from(ANCHOR_HEIGHT)?);
        let chain = encoded
            .iter()
            .map(|bytes| Ok(deserialize::<BitcoinBlock>(&hex::decode(bytes)?)?))
            .collect::<Result<Vec<_>>>()?;
        let mut parent = genesis_block(Network::Regtest).block_hash();
        let mut unspent = BTreeMap::new();
        for block in &chain {
            ensure!(
                block.check_merkle_root() && block.header.prev_blockhash == parent,
                "timed setup chain differs"
            );
            parent = block.block_hash();
            for tx in &block.txdata {
                for input in &tx.input {
                    unspent.remove(&input.previous_output);
                }
                for (index, output) in tx.output.iter().enumerate() {
                    unspent.insert(
                        OutPoint {
                            txid: tx.compute_txid(),
                            vout: u32::try_from(index)?,
                        },
                        output.clone(),
                    );
                }
            }
        }
        ensure!(parent == self.manifest.anchor_hash);
        let canonical: XOnlyPublicKey = self.manifest.canonical_signer.parse()?;
        let api: XOnlyPublicKey = self.manifest.api_signer.parse()?;
        let canonical_script =
            Address::p2tr(&Secp256k1::new(), canonical, None, Network::Regtest).script_pubkey();
        let api_script =
            Address::p2tr(&Secp256k1::new(), api, None, Network::Regtest).script_pubkey();
        let mut seen = BTreeSet::new();
        let mut blocks = Vec::new();
        for (index, record) in self.manifest.blocks.iter().enumerate() {
            let declared = &self.manifest.schedule.blocks[index];
            let raw = self.bytes(&record.input)?;
            let block: BitcoinBlock = deserialize(&raw)?;
            ensure!(block.block_hash() == record.hash && block.check_merkle_root());
            ensure!(block.txdata.len() == declared.transactions().len() * 2 + 1);
            let decoded = decode_block(&raw, declared.height, record.hash, record.parent)?;
            ensure!(decoded.transactions.len() == declared.transactions().len());
            let mut funding = Vec::new();
            let mut instructions = Vec::new();
            for (position, tx) in decoded.transactions.iter().enumerate() {
                ensure!(seen.insert(tx.txid) && tx.inputs.len() == 1);
                let commit = &block.txdata[position * 2 + 1];
                ensure!(commit.input.len() == 1);
                let outpoint = commit.input[0].previous_output;
                let output = unspent
                    .remove(&outpoint)
                    .context("reused or unknown initial canonical funding")?;
                ensure!(output.script_pubkey == canonical_script);
                funding.push((outpoint, output));
                instructions.extend(tx.inputs[0].insts.ops.clone());
            }
            blocks.push(BlockInput::decode_group(
                raw,
                declared.height,
                record.parent,
                &funding,
                &instructions,
                canonical,
            )?);
        }
        let encoded: Vec<EncodedRequest> =
            serde_json::from_slice(&self.bytes(&self.manifest.requests)?)?;
        let count = self
            .manifest
            .schedule
            .events
            .iter()
            .filter(|event| matches!(event.action, Action::Simulation { .. }))
            .count();
        ensure!(encoded.len() == count);
        let mut requests = Vec::new();
        let mut api_funding = None;
        for (index, encoded) in encoded.into_iter().enumerate() {
            ensure!(encoded.ordinal == index, "API occurrence differs");
            let commit: Transaction = deserialize(&hex::decode(encoded.commit)?)?;
            let reveal: Transaction = deserialize(&hex::decode(encoded.reveal)?)?;
            ensure!(commit.input.len() == 1 && reveal.input.len() == 1);
            let funding = commit.input[0].previous_output;
            ensure!(
                api_funding.is_none_or(|expected| expected == funding),
                "API funding changed"
            );
            api_funding = Some(funding);
            ensure!(
                unspent
                    .get(&funding)
                    .is_some_and(|out| out.script_pubkey == api_script),
                "API funding is not independent and initially unspent"
            );
            ensure!(
                reveal.input[0].previous_output.txid == commit.compute_txid()
                    && !seen.contains(&reveal.compute_txid())
            );
            let tx = filter_map((0, reveal.clone())).context("missing API input")?;
            ensure!(
                tx.inputs.len() == 1
                    && tx.inputs[0].x_only_pubkey == api
                    && tx.inputs[0].insts.aggregate.is_none()
            );
            ensure!(
                tx.inputs[0].insts.ops.len() == self.manifest.settings.mixed.simulation_operations
            );
            requests.push(ApiInput { commit, reveal });
        }
        Ok(Inputs {
            chain,
            blocks,
            requests,
        })
    }
}
