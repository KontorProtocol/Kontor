use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use indexer_types::{ContractAddress, Inst, InstKind, OpStatus, ResultRow};
use sha2::{Digest, Sha256};

use super::super::{ANCHOR_HEIGHT, GAS_LIMIT, SMOKE_HEIGHT, test_provenance};
use super::oracle::PaidEffects;
use crate::bls::taproot_derivation_path;
use crate::database::queries::{get_contract_id_from_address, get_contract_signer_id};
use crate::reg_tester::derive_taproot_keypair_from_seed;
use crate::runtime::numerics::{add_decimal, mul_decimal};
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime, TransactionContext, from_wave_expr, to_wave_expr};

const BLOB_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub(super) enum MixedLayout {
    Single {
        payer: u64,
        operations_per_transaction: usize,
    },
    TwoInputs {
        signers: [u64; 2],
    },
    Aggregate {
        signers: [u64; 2],
    },
}

impl MixedLayout {
    pub(super) fn payer(self) -> u64 {
        match self {
            Self::Single { payer, .. } => payer,
            Self::TwoInputs { signers } | Self::Aggregate { signers } => signers[0],
        }
    }

    pub(super) fn signer(self, index: usize) -> u64 {
        match self {
            Self::Single { payer, .. } => payer,
            Self::TwoInputs { signers } => signers[index / 50],
            Self::Aggregate { signers } => signers[index % 2],
        }
    }

    fn position(self, index: usize) -> Result<(u32, u32, u32)> {
        let (tx, input, op) = match self {
            Self::Single {
                operations_per_transaction,
                ..
            } => {
                ensure!(operations_per_transaction > 0);
                (
                    index / operations_per_transaction,
                    0,
                    index % operations_per_transaction,
                )
            }
            Self::TwoInputs { .. } => (0, index / 50, index % 50),
            Self::Aggregate { .. } => (0, 0, index),
        };
        Ok((
            u32::try_from(tx)?,
            u32::try_from(input)?,
            u32::try_from(op)?,
        ))
    }
}

pub(super) struct MixedWorkload {
    counter: ContractAddress,
    failed: ContractAddress,
    proxy: ContractAddress,
    crypto: ContractAddress,
    recipient: u64,
    rounds: usize,
}

impl MixedWorkload {
    pub(super) async fn prepare(runtime: &mut Runtime, payer: u64, rounds: usize) -> Result<Self> {
        ensure!(matches!(rounds, 5 | 50));
        ensure!(
            staking::get_stake(runtime, &HolderRef::SignerId(payer).to_string())
                .await?
                .is_none(),
            "mixed payer must start without a bond"
        );
        let core = Signer::Core(Box::new(Signer::Nobody));
        runtime
            .set_context(
                ANCHOR_HEIGHT,
                Some(TransactionContext::builder().tx_index(7).build()),
                None,
                None,
            )
            .await;
        let [counter, failed, proxy, crypto] =
            ["mixedcounter", "mixedfailed", "mixedproxy", "mixedcrypto"].map(|name| {
                ContractAddress {
                    name: name.into(),
                    height: ANCHOR_HEIGHT,
                    tx_index: 7,
                }
            });
        let counter_bytes =
            include_bytes!("../../../../../../../test-contracts/binaries/counter.wasm.br");
        let proxy_bytes =
            include_bytes!("../../../../../../../test-contracts/binaries/proxy.wasm.br");
        let crypto_bytes =
            include_bytes!("../../../../../../../test-contracts/binaries/crypto.wasm.br");
        for (address, bytes) in [
            (&counter, counter_bytes.as_slice()),
            (&failed, counter_bytes.as_slice()),
            (&proxy, proxy_bytes.as_slice()),
            (&crypto, crypto_bytes.as_slice()),
        ] {
            runtime
                .publish(
                    &core,
                    runtime.core_payment(),
                    &address.name,
                    bytes,
                    &test_provenance()?,
                )
                .await?;
        }
        runtime
            .execute(
                Some(&core),
                Some(runtime.core_payment()),
                &proxy,
                &format!("set-contract-address({})", to_wave_expr(counter.clone())),
            )
            .await?;
        let recipient_key = derive_taproot_keypair_from_seed(
            &[97; 64],
            &taproot_derivation_path(Network::Regtest),
        )?
        .x_only_public_key()
        .0
        .to_string();
        let recipient = runtime
            .get_or_create_identity(&recipient_key)
            .await?
            .signer_id();
        ensure!(
            token::balance(runtime, HolderRef::SignerId(recipient))
                .await?
                .unwrap_or_default()
                == Decimal::default()
        );
        Ok(Self {
            counter,
            failed,
            proxy,
            crypto,
            recipient,
            rounds,
        })
    }

    pub(super) fn instructions(&self) -> Vec<Inst> {
        let mut result = Vec::new();
        for round in 0..self.rounds {
            for slot in 0..20 {
                let (contract, expr) = match slot {
                    0..=7 => (
                        token_address(),
                        token::wave::transfer_call_expr(
                            HolderRef::SignerId(self.recipient),
                            Decimal::from("0.001"),
                        ),
                    ),
                    8 => (self.counter.clone(), "increment()".into()),
                    9 => (self.counter.clone(), format!("fill-blob({BLOB_BYTES})")),
                    10 => (self.counter.clone(), "get-blob()".into()),
                    11..=12 => (
                        self.failed.clone(),
                        "set-blob-then-fail(\"must roll back\")".into(),
                    ),
                    13..=15 => (self.proxy.clone(), "increment()".into()),
                    16..=17 => (
                        staking_address(),
                        staking::wave::add_stake_call_expr(Decimal::from("0.001")),
                    ),
                    18..=19 => (
                        self.crypto.clone(),
                        format!("set-hash(\"round-{round}-slot-{slot}\")"),
                    ),
                    _ => unreachable!(),
                };
                result.push(Inst {
                    gas_limit: GAS_LIMIT,
                    kind: InstKind::Call { contract, expr },
                });
            }
        }
        result
    }

    pub(super) fn signer_effects(
        &self,
        layout: MixedLayout,
        signer: u64,
    ) -> Result<(Decimal, Decimal)> {
        let indices = (0..self.rounds * 20).filter(|index| layout.signer(*index) == signer);
        let transfers = indices.clone().filter(|index| index % 20 <= 7).count();
        let stakes = indices
            .filter(|index| matches!(index % 20, 16..=17))
            .count();
        Ok((
            mul_decimal(
                Decimal::from("0.001"),
                Decimal::try_from(u64::try_from(transfers)?)?,
            )?,
            mul_decimal(
                Decimal::from("0.001"),
                Decimal::try_from(u64::try_from(stakes)?)?,
            )?,
        ))
    }

    pub(super) fn effects(&self, layout: MixedLayout) -> Result<PaidEffects> {
        let (transferred, payer_staked) = self.signer_effects(layout, layout.payer())?;
        Ok(PaidEffects {
            transferred,
            payer_staked,
            staked: mul_decimal(
                Decimal::from("0.001"),
                Decimal::try_from((self.rounds * 2) as u64)?,
            )?,
        })
    }

    pub(super) async fn check(
        &self,
        runtime: &mut Runtime,
        all: &[&ResultRow],
        roots: &[&ResultRow],
        layout: MixedLayout,
    ) -> Result<()> {
        let payer = layout.payer();
        ensure!(roots.len() == self.rounds * 20 && all.len() == self.rounds * 25);
        let conn = runtime.get_storage_conn();
        let staking_id = get_contract_id_from_address(&conn, &staking_address())
            .await?
            .context("missing staking contract")?;
        let staking_signer = get_contract_signer_id(&conn, staking_id)
            .await?
            .context("missing staking signer")?;
        let mut expected_stakes = BTreeMap::<u64, Decimal>::new();
        for (index, root) in roots.iter().enumerate() {
            let signer = layout.signer(index);
            let (tx_index, input_index, op_index) = layout.position(index)?;
            let slot = index % 20;
            let round = index / 20;
            let nested = matches!(slot, 13..=17);
            ensure!(
                root.height == SMOKE_HEIGHT
                    && root.tx_index == Some(tx_index)
                    && root.input_index == Some(input_index)
                    && root.op_index == Some(op_index)
                    && root.result_index == u32::from(nested)
                    && root.signer_id == signer
                    && root.payer_signer_id == Some(payer)
                    && root.gas > 0
                    && root.gas <= GAS_LIMIT
            );
            ensure!(
                root.status
                    == if matches!(slot, 11..=12) {
                        OpStatus::ContractErr
                    } else {
                        OpStatus::Ok
                    }
            );
            let value = root
                .value
                .as_deref()
                .context("mixed root omitted return value")?;
            match slot {
                0..=7 => {
                    ensure!(
                        root.contract == token_address().to_string() && root.func == "transfer"
                    );
                    let transfer = token::wave::transfer_parse_return_expr(value)?;
                    ensure!(
                        transfer.src == HolderRef::SignerId(signer)
                            && transfer.dst == HolderRef::SignerId(self.recipient)
                            && transfer.amt == Decimal::from("0.001")
                    );
                }
                8..=10 => {
                    ensure!(root.contract == self.counter.to_string());
                    ensure!(root.func == ["increment", "fill-blob", "get-blob"][slot - 8]);
                    ensure!(
                        value
                            == if slot == 10 {
                                to_wave_expr("a".repeat(BLOB_BYTES))
                            } else {
                                String::new()
                            }
                    );
                }
                11..=12 => {
                    ensure!(
                        root.contract == self.failed.to_string()
                            && root.func == "set-blob-then-fail"
                    );
                    ensure!(value == "err(message(\"deliberate failure after write\"))");
                }
                13..=15 => ensure!(
                    root.contract == self.proxy.to_string()
                        && root.func == "fallback"
                        && value.is_empty()
                ),
                16..=17 => {
                    ensure!(
                        root.contract == staking_address().to_string() && root.func == "add-stake"
                    );
                    let expected_stake = expected_stakes.entry(signer).or_default();
                    *expected_stake = add_decimal(*expected_stake, Decimal::from("0.001"))?;
                    let stake = staking::wave::add_stake_parse_return_expr(value)?;
                    ensure!(stake.stake == *expected_stake && stake.withdrawal_height.is_none());
                }
                18..=19 => {
                    ensure!(root.contract == self.crypto.to_string() && root.func == "set-hash");
                    let expected =
                        Sha256::digest(format!("round-{round}-slot-{slot}").as_bytes()).to_vec();
                    ensure!(from_wave_expr::<Vec<u8>>(value) == expected);
                }
                _ => unreachable!(),
            }
            if nested {
                let children: Vec<_> = all
                    .iter()
                    .filter(|row| {
                        row.txid == root.txid
                            && row.input_index == root.input_index
                            && row.op_index == root.op_index
                            && row.result_index == 0
                    })
                    .collect();
                ensure!(children.len() == 1);
                let child = children[0];
                ensure!(
                    child.status == OpStatus::Ok
                        && child.signer_id == signer
                        && child.payer_signer_id.is_none()
                        && child.height == root.height
                        && child.tx_index == root.tx_index
                        && child.input_index == root.input_index
                        && child.gas > 0
                        && child.gas <= root.gas
                );
                ensure!(
                    child.contract
                        == if slot <= 15 {
                            self.counter.to_string()
                        } else {
                            token_address().to_string()
                        }
                );
                ensure!(child.func == if slot <= 15 { "increment" } else { "transfer" });
                let value = child
                    .value
                    .as_deref()
                    .context("missing nested return value")?;
                if slot <= 15 {
                    ensure!(value.is_empty());
                } else {
                    let transfer = token::wave::transfer_parse_return_expr(value)?;
                    ensure!(
                        transfer.src == HolderRef::SignerId(signer)
                            && transfer.dst == HolderRef::SignerId(staking_signer)
                            && transfer.amt == Decimal::from("0.001")
                    );
                }
            }
        }
        ensure!(
            from_wave_expr::<u64>(&runtime.execute_system_view(&self.counter, "get()").await?)
                == (self.rounds * 4) as u64
        );
        ensure!(
            from_wave_expr::<String>(
                &runtime
                    .execute_system_view(&self.counter, "get-blob()")
                    .await?
            ) == "a".repeat(BLOB_BYTES)
        );
        ensure!(
            from_wave_expr::<String>(
                &runtime
                    .execute_system_view(&self.failed, "get-blob()")
                    .await?
            )
            .is_empty()
        );

        ensure!(
            from_wave_expr::<Option<Vec<u8>>>(
                &runtime
                    .execute_system_view(&self.crypto, "get-hash()")
                    .await?
            ) == Some(
                Sha256::digest(format!("round-{}-slot-19", self.rounds - 1).as_bytes()).to_vec()
            )
        );
        ensure!(
            token::balance(runtime, HolderRef::SignerId(self.recipient)).await?
                == Some(mul_decimal(
                    Decimal::from("0.001"),
                    Decimal::try_from((self.rounds * 8) as u64)?
                )?)
        );
        for (signer, expected_stake) in expected_stakes {
            let stake = staking::get_stake(runtime, &HolderRef::SignerId(signer).to_string())
                .await?
                .context("missing mixed signer bond")?;
            ensure!(stake.stake == expected_stake && stake.withdrawal_height.is_none());
        }
        Ok(())
    }
}
