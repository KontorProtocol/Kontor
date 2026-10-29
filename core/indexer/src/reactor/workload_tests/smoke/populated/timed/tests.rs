use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::{Result, ensure};
use bitcoin::key::Secp256k1;
use bitcoin::{Address, BlockHash, Network, OutPoint};
use indexer_types::{ContractAddress, Inst, InstKind};
use serde_json::json;
use tempfile::TempDir;

use super::{Action, Profile, Schedule, Spec};
use crate::bitcoin_client::client::RegtestRpc;
use crate::bls::taproot_derivation_path;
use crate::reactor::workload_tests::smoke::populated::{sequence_funding, sequence_inputs};
use crate::reactor::workload_tests::smoke::{
    ANCHOR_HEIGHT, BitcoinProcess, FUNDING_SEED, GAS_LIMIT,
};
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};

#[test]
fn workload_timed_schedule_preserves_rates_and_boundary_order() -> Result<()> {
    for (profile, batches, simulations, transactions, batch_transactions) in [
        (Profile::Representative, 20, 60, 250, 10),
        (Profile::Stress, 40, 600, 1_300, 20),
    ] {
        let schedule = Schedule::new(Spec {
            profile,
            fresh_backlog: 0,
            intervals: 2,
        })?;
        ensure!(schedule.funding_counts()? == [transactions, transactions]);
        ensure!(schedule.required_before(600)? == batches + simulations);
        let boundary = schedule.required_before(600)?;
        ensure!(matches!(
            schedule.event(boundary)?.action,
            Action::Block { block: 0 }
        ));
        ensure!(matches!(
            schedule.event(boundary + 1)?.action,
            Action::Batch {
                block: 1,
                anchor_height: 102,
                ..
            }
        ));
        ensure!(matches!(
            schedule.event(boundary + 2)?.action,
            Action::Simulation {
                anchor_height: 102,
                ..
            }
        ));
        let mut seen = BTreeSet::new();
        for event in &schedule.events {
            ensure!(
                event
                    .depends_on
                    .is_none_or(|previous| previous < event.ordinal)
            );
            if let Action::Batch {
                transactions,
                anchor_height,
                block,
            } = &event.action
            {
                ensure!(transactions.len() == batch_transactions);
                ensure!(*anchor_height + 1 == schedule.blocks[*block].height);
                ensure!(
                    transactions
                        .clone()
                        .all(|transaction| seen.insert(transaction))
                );
            }
        }
        ensure!(seen.len() == 2 * batches * batch_transactions);
        ensure!(
            schedule
                .events
                .iter()
                .filter(|event| event.action.canonical())
                .count()
                == 2 * (batches + 1)
        );
        ensure!(schedule.required_before(1_200)? == schedule.events.len() - 1);
        ensure!(schedule.required_before(1_201).is_err());
        ensure!(schedule.event(schedule.events.len()).is_err());
        let encoded = serde_json::to_vec(&schedule)?;
        let decoded: Schedule = serde_json::from_slice(&encoded)?;
        decoded.validate()?;
        ensure!(decoded == schedule);
    }
    Ok(())
}

#[test]
fn workload_timed_schedule_rejects_missing_reordered_or_reanchored_work() -> Result<()> {
    let original = Schedule::new(Spec {
        profile: Profile::Stress,
        fresh_backlog: 6,
        intervals: 2,
    })?;
    ensure!(original.funding_counts()? == [500, 500, 500, 500, 500, 500, 1_300, 1_300]);
    for block in 0..6 {
        ensure!(original.event(block)?.action == Action::Block { block });
        ensure!(original.event(block)?.at_seconds == 0);
    }
    ensure!(matches!(
        original.event(6)?.action,
        Action::Batch {
            block: 6,
            anchor_height: 107,
            ..
        }
    ));
    ensure!(original.required_before(600)? == 6 + 40 + 600);
    for change in 0..8 {
        let mut invalid = original.clone();
        match change {
            0 => {
                invalid.events.remove(6);
            }
            1 => invalid.events.swap(5, 6),
            2 => invalid.events[6].at_seconds += 1,
            3 => invalid.events[6].depends_on = None,
            4 => {
                if let Action::Batch { anchor_height, .. } = &mut invalid.events[6].action {
                    *anchor_height -= 1;
                }
            }
            5 => invalid.blocks[6].confirmations.end -= 1,
            6 => invalid.blocks[6].fresh.start -= 1,
            7 => invalid.events.push(invalid.events[6].clone()),
            _ => unreachable!(),
        }
        ensure!(
            invalid.validate().is_err(),
            "accepted schedule mutation {change}"
        );
    }
    let six_historical = Schedule::new(Spec {
        profile: Profile::Stress,
        fresh_backlog: 0,
        intervals: 6,
    })?;
    ensure!(six_historical.horizon_seconds == 3_600);
    ensure!(
        six_historical
            .events
            .iter()
            .filter(|event| matches!(event.action, Action::Batch { .. }))
            .count()
            == 240
    );
    ensure!(six_historical.funding_counts()? == [1_300; 6]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; timed input admission and ordering only, no execution or performance qualification"]
async fn workload_timed_inputs_preserve_additive_transaction_budgets() -> Result<()> {
    for spec in [
        Spec {
            profile: Profile::Representative,
            fresh_backlog: 0,
            intervals: 2,
        },
        Spec {
            profile: Profile::Stress,
            fresh_backlog: 6,
            intervals: 2,
        },
        Spec {
            profile: Profile::Stress,
            fresh_backlog: 0,
            intervals: 6,
        },
    ] {
        let schedule = Schedule::new(spec)?;
        let counts = schedule.funding_counts()?;
        let directory = TempDir::new()?;
        let (child, client) = workload_bitcoin(directory.path()).await?;
        let mut bitcoin = BitcoinProcess(child);
        let key = derive_taproot_keypair_from_seed(
            &FUNDING_SEED,
            &taproot_derivation_path(Network::Regtest),
        )?;
        let address = Address::p2tr(
            &Secp256k1::new(),
            key.x_only_public_key().0,
            None,
            Network::Regtest,
        );
        let mined = client
            .generate_to_address(ANCHOR_HEIGHT - 1, &address.to_string())
            .await?;
        let first = client.get_block(&BlockHash::from_str(&mined[0])?).await?;
        let funding = (
            OutPoint {
                txid: first.txdata[0].compute_txid(),
                vout: 0,
            },
            first.txdata[0].output[0].clone(),
        );
        let funding =
            sequence_funding::prepare_groups(&client, &key, &address, funding, &counts).await?;
        let contract = ContractAddress {
            name: "mixedcounter".into(),
            height: ANCHOR_HEIGHT,
            tx_index: 7,
        };
        let instructions: Vec<Vec<Inst>> = schedule
            .blocks
            .iter()
            .map(|block| {
                block
                    .transactions()
                    .flat_map(|transaction| {
                        [
                            "increment()".to_string(),
                            format!("fill-blob({transaction})"),
                        ]
                        .map(|expr| Inst {
                            gas_limit: GAS_LIMIT,
                            kind: InstKind::Call {
                                contract: contract.clone(),
                                expr,
                            },
                        })
                    })
                    .collect()
            })
            .collect();
        let inputs =
            sequence_inputs::generate_groups(&client, &key, &address, &funding, &instructions)
                .await?;
        let mut executed = BTreeSet::new();
        let mut confirmed = BTreeSet::new();
        let mut tip = ANCHOR_HEIGHT;
        for event in &schedule.events {
            match &event.action {
                Action::Batch {
                    block,
                    anchor_height,
                    transactions,
                } => {
                    ensure!(*anchor_height == tip);
                    let block_start = schedule.blocks[*block].transactions().start;
                    for transaction in transactions.clone() {
                        let reveal = &inputs[*block].reveals[transaction - block_start];
                        ensure!(executed.insert(reveal.compute_txid()));
                    }
                }
                Action::Block { block } => {
                    let expected = &schedule.blocks[*block];
                    let input = &inputs[*block];
                    ensure!(input.block.height == tip + 1 && input.block.height == expected.height);
                    for (ordinal, reveal) in expected.transactions().zip(&input.reveals) {
                        let txid = reveal.compute_txid();
                        if expected.confirmations.contains(&ordinal) {
                            ensure!(executed.contains(&txid));
                        } else {
                            ensure!(expected.fresh.contains(&ordinal) && executed.insert(txid));
                        }
                        ensure!(confirmed.insert(txid));
                    }
                    tip += 1;
                }
                Action::Simulation { anchor_height, .. } => ensure!(*anchor_height == tip),
            }
        }
        ensure!(executed == confirmed && executed.len() == counts.iter().sum::<usize>());
        eprintln!(
            "workload_timed_inputs={}",
            json!({
                "schedule": schedule,
                "unique_transactions": executed.len(),
                "scope": "real Bitcoin funding/block admission and input ordering, no Kontor execution or timing",
            })
        );
        bitcoin.0.kill().await?;
    }
    Ok(())
}
