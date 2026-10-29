use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::consensus::serialize;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Block, Network, OutPoint, Psbt, Transaction, TxOut};
use blst::min_sig::{AggregateSignature, SecretKey};
use indexer_types::{
    AggregateInfo, AggregateSigner, CommitSource, Input, Inst, InstKind, Insts, Reveal,
    RevealOutput, RevealParticipant, SignerRef,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::super::{ANCHOR_HEIGHT, GAS_LIMIT};
use super::many;
use super::mixed::{MixedLayout, MixedWorkload};
use crate::api::compose::compose;
use crate::bitcoin_client::Client;
use crate::bls::{KONTOR_BLS_DST, RegistrationProof, taproot_derivation_path};
use crate::database::types::Identity;
use crate::reg_tester::derive_taproot_keypair_from_seed;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::api as staking;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};
use crate::test_utils::bls_test::derive_test_key;
use crate::test_utils::{participant_tap_script, sign_key_spend, sign_script_spend};

pub(super) fn secondary_key() -> Result<Keypair> {
    derive_taproot_keypair_from_seed(&[113; 64], &taproot_derivation_path(Network::Regtest))
}

pub(super) fn address(key: &Keypair) -> Address {
    Address::p2tr(
        &Secp256k1::new(),
        key.x_only_public_key().0,
        None,
        Network::Regtest,
    )
}

pub(super) struct ShapeSigners {
    keys: [Keypair; 2],
    identities: [Identity; 2],
    bls: [SecretKey; 2],
    nonces: [u64; 2],
    aggregate: bool,
}

impl ShapeSigners {
    pub(super) async fn prepare(
        runtime: &mut Runtime,
        primary: Keypair,
        aggregate: bool,
    ) -> Result<Self> {
        let keys = [primary, secondary_key()?];
        let identities = [
            runtime
                .get_or_create_identity(&keys[0].x_only_public_key().0.to_string())
                .await?,
            runtime
                .get_or_create_identity(&keys[1].x_only_public_key().0.to_string())
                .await?,
        ];
        ensure!(identities[0] != identities[1]);
        let secondary = HolderRef::from(&Signer::Id(identities[1].clone()));
        ensure!(
            token::balance(runtime, secondary.clone())
                .await?
                .unwrap_or_default()
                == Decimal::default()
        );
        ensure!(
            staking::get_stake(runtime, &secondary.to_string())
                .await?
                .is_none()
        );
        token::issue_to(
            runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            secondary,
            Decimal::from("100"),
        )
        .await??;
        let bls = [derive_test_key(114), derive_test_key(115)];
        let conn = runtime.get_storage_conn();
        let mut nonces = [0; 2];
        for (index, identity) in identities.iter().enumerate() {
            ensure!(identity.next_nonce(&conn).await? == 0);
            if aggregate {
                let proof = RegistrationProof::new(&keys[index], &bls[index].to_bytes())?;
                runtime
                    .register_bls_key(
                        &Signer::Id(identity.clone()),
                        &proof.bls_pubkey,
                        &proof.schnorr_sig,
                        &proof.bls_sig,
                    )
                    .await?;
                // Different nonzero starting nonces catch accidental reuse of an
                // operation index as every signer's global nonce.
                nonces[index] = identity
                    .advance_nonce(&conn, [6, 18][index], ANCHOR_HEIGHT)
                    .await?;
            }
        }
        Ok(Self {
            keys,
            identities,
            bls,
            nonces,
            aggregate,
        })
    }

    pub(super) fn layout(&self) -> MixedLayout {
        let signers = self.identities.each_ref().map(|id| id.signer_id());
        if self.aggregate {
            MixedLayout::Aggregate { signers }
        } else {
            MixedLayout::TwoInputs { signers }
        }
    }

    fn groups(&self, mut ops: Vec<Inst>) -> Result<Vec<Insts>> {
        ensure!(ops.len() == 100);
        if !self.aggregate {
            let second = ops.split_off(50);
            ops.push(Inst {
                gas_limit: GAS_LIMIT,
                kind: InstKind::Sponsor,
            });
            return Ok(vec![Insts::direct(ops), Insts::direct(second)]);
        }
        let mut nonces = self.nonces;
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        for (index, op) in ops.iter().enumerate() {
            let actor = index % 2;
            let signer = AggregateSigner {
                identity: SignerRef::SignerId(self.identities[actor].signer_id()),
                nonce: nonces[actor],
                sponsored: true,
            };
            nonces[actor] = nonces[actor]
                .checked_add(1)
                .context("fixture nonce overflow")?;
            signatures.push(self.bls[actor].sign(
                &op.aggregate_signing_message(&signer.identity, signer.nonce, signer.sponsored)?,
                KONTOR_BLS_DST,
                &[],
            ));
            signers.push(signer);
        }
        let refs: Vec<_> = signatures.iter().collect();
        let signature = AggregateSignature::aggregate(&refs, true)
            .map_err(|e| anyhow!("aggregate fixture: {e:?}"))?
            .to_signature()
            .to_bytes()
            .to_vec();
        Ok(vec![Insts {
            ops,
            aggregate: Some(AggregateInfo { signers, signature }),
        }])
    }

    pub(super) fn check_inputs(&self, inputs: &[Input], ops: Vec<Inst>) -> Result<()> {
        let expected = self.groups(ops)?;
        ensure!(inputs.len() == expected.len());
        for (index, (input, expected)) in inputs.iter().zip(expected).enumerate() {
            ensure!(
                input.input_index == u32::try_from(index)?
                    && input.x_only_pubkey == self.keys[index].x_only_public_key().0
                    && input.insts == expected
            );
        }
        Ok(())
    }

    pub(super) async fn block(
        &self,
        client: &Client,
        funding: Vec<(OutPoint, TxOut)>,
        ops: Vec<Inst>,
    ) -> Result<(Block, Vec<Transaction>)> {
        let groups = self.groups(ops)?;
        ensure!(funding.len() == groups.len());
        let participants = groups
            .into_iter()
            .enumerate()
            .map(|(index, commit_insts)| RevealParticipant {
                x_only_public_key: self.keys[index].x_only_public_key().0.to_string(),
                commit_insts,
                output: None,
                commit_source: CommitSource::build_resolved(
                    &address(&self.keys[index]),
                    [funding[index].clone()],
                ),
            })
            .collect();
        let (commits, output) = compose(
            Reveal {
                sat_per_vbyte: Some(2),
                participants,
                extra_inputs: Vec::new(),
                extra_outputs: vec![RevealOutput::Change {
                    script_pubkey: hex::encode(address(&self.keys[0]).script_pubkey().as_bytes()),
                }],
            },
            Network::Regtest,
            client,
        )
        .await?;
        ensure!(commits.len() == funding.len());
        let mut ordered: Vec<_> = commits
            .into_iter()
            .map(|commit| commit.transaction)
            .collect();
        let secp = Secp256k1::new();
        for (index, commit) in ordered.iter_mut().enumerate() {
            ensure!(commit.input.len() == 1 && commit.input[0].previous_output == funding[index].0);
            sign_key_spend(
                &secp,
                commit,
                &[funding[index].1.clone()],
                &self.keys[index],
                0,
                None,
            )?;
            submit(client, commit).await?;
        }
        let mut reveal = output.transaction;
        let psbt = Psbt::deserialize(&hex::decode(output.psbt_hex)?)?;
        let prevouts: Vec<_> = ordered.iter().map(|tx| tx.output[0].clone()).collect();
        ensure!(reveal.input.len() == ordered.len());
        for (index, commit) in ordered.iter().enumerate() {
            ensure!(
                reveal.input[index].previous_output
                    == OutPoint {
                        txid: commit.compute_txid(),
                        vout: 0
                    }
            );
            let (script, _) = participant_tap_script(&psbt.inputs[index])?;
            let spend = TaprootBuilder::new()
                .add_leaf(0, script.clone())?
                .finalize(&secp, self.keys[index].x_only_public_key().0)
                .map_err(|e| anyhow!("taproot fixture: {e:?}"))?;
            sign_script_spend(
                &secp,
                &spend,
                &script,
                &mut reveal,
                &prevouts,
                &self.keys[index],
                index,
            )?;
        }
        submit(client, &reveal).await?;
        ordered.push(reveal.clone());
        let block = many::mine(client, &address(&self.keys[0]), &ordered).await?;
        ensure!(block.txdata[1..] == ordered && block.weight().to_wu() <= 4_000_000);
        let bytes = serialize(&block);
        eprintln!(
            "workload_signer_shape={}",
            json!({
                "aggregate": self.aggregate, "signers": self.identities.each_ref().map(|id| id.signer_id()),
                "initial_nonces": self.nonces, "publisher_pays_all": true,
                "inputs": reveal.input.len(), "executable_operations": 100,
                "instructions_per_input": if self.aggregate { vec![100] } else { vec![51, 50] },
                "bitcoin_transactions": block.txdata.len(), "block_bytes": bytes.len(),
                "block_weight": block.weight().to_wu(), "raw_block_sha256": hex::encode(Sha256::digest(bytes)),
            })
        );
        Ok((block, vec![reveal]))
    }

    pub(super) async fn check(&self, runtime: &mut Runtime, mixed: &MixedWorkload) -> Result<()> {
        let secondary = self.identities[1].signer_id();
        let (transferred, staked) = mixed.signer_effects(self.layout(), secondary)?;
        ensure!(
            token::balance(runtime, HolderRef::SignerId(secondary)).await?
                == Some(sub_decimal(
                    sub_decimal(Decimal::from("100"), transferred)?,
                    staked
                )?)
        );
        for (index, id) in self.identities.iter().enumerate() {
            ensure!(
                id.next_nonce(&runtime.get_storage_conn()).await?
                    == self.nonces[index] + if self.aggregate { 50 } else { 0 }
            );
        }
        Ok(())
    }
}

async fn submit(client: &Client, transaction: &Transaction) -> Result<()> {
    let raw = hex::encode(serialize(transaction));
    let verdict = client
        .test_mempool_accept(std::slice::from_ref(&raw))
        .await?;
    ensure!(
        verdict.len() == 1 && verdict[0].allowed,
        "signed shape rejected: {verdict:?}"
    );
    client.send_raw_transaction(&raw).await?;
    Ok(())
}
