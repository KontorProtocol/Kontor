use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use num_bigint::BigUint;

use super::model::{Manifest, Numeric, Report, Status, UsageKind};

pub(super) fn ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(super) fn manifest(value: &Manifest) -> Result<()> {
    let (source, snapshot, input, execution) = (
        &value.source,
        &value.snapshot,
        &value.input,
        &value.execution,
    );
    ensure!(
        matches!(
            (value.schema_version, execution.effective_retain_blocks),
            (1, None) | (2, Some(7))
        ),
        "unsupported manifest version or retention"
    );
    ensure!(
        value.kind.0 == "smoke" && value.case_id.0 == "paid-success-failure-success-v1",
        "unsupported workload"
    );
    // These are the frozen format's historical inputs, not the current engine policy.
    ensure!(
        source.wasmtime_revision.0 == "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
            && source.engine.0 == "pulley"
            && source.pulley_stack_bytes == 524288
            && source.native_fiber_bytes == 2097152
            && matches!(source.profile.0.as_str(), "dev" | "release"),
        "frozen engine identity differs"
    );
    ensure!(
        ordered(&source.features),
        "source features must be sorted and unique"
    );
    ensure!(
        execution.executor.0 == "RuntimeExecutor"
            && execution.component_cache.0 == "cold"
            && execution.network.0 == "regtest"
            && execution.prune_enabled
            && execution.retain_blocks == 6
            && execution.gas_to_fuel_multiplier == 1000
            && execution.execution_price.text == "0.000000001"
            && execution.storage_gas_per_byte == 1
            && execution.independent_resets == 2
            && execution.timing_claim.0 == "none",
        "execution settings differ"
    );
    let ids: Vec<_> = value.artifacts.iter().map(|a| a.id.0.as_str()).collect();
    ensure!(
        ids == [
            "error_test",
            "filestorage",
            "nft",
            "staking",
            "system",
            "token"
        ],
        "artifact inventory differs"
    );
    let mut addresses = BTreeSet::new();
    for artifact in &value.artifacts {
        ensure!(
            !artifact.addresses.is_empty() && ordered(&artifact.addresses),
            "artifact addresses must be sorted and unique"
        );
        for address in &artifact.addresses {
            ensure!(addresses.insert(address), "duplicate artifact address");
        }
    }
    ensure!(
        snapshot.anchor_height.checked_add(1) == Some(input.height),
        "block does not follow snapshot"
    );
    ensure!(
        execution.starting_block_height > 0
            && execution.starting_block_height <= snapshot.anchor_height,
        "invalid indexed history start"
    );
    ensure!(
        input.previous_hash == snapshot.anchor_hash
            && input.bitcoin_validation.accepted_block_hash == input.block_hash
            && input.bitcoin_validation.network.0 == "regtest",
        "Bitcoin block identity differs"
    );
    let retention = execution
        .effective_retain_blocks
        .unwrap_or(execution.retain_blocks);
    ensure!(
        input
            .height
            .checked_sub(retention)
            .is_some_and(|h| snapshot.prune_watermark < h),
        "no new pruning band"
    );
    let decision = &value.decision;
    ensure!(
        decision.consensus_height > 0
            && decision.block_height == input.height
            && decision.block_hash == input.block_hash
            && decision.certificate_hex.is_empty()
            && decision.value_kind.0 == "block",
        "decision differs"
    );
    ensure!(
        input.kontor_input_count == 1 && input.operation_count == 3,
        "input count differs"
    );
    ensure!(
        input.raw_txids.len() >= 3
            && input.raw_txids.iter().collect::<BTreeSet<_>>().len() == input.raw_txids.len(),
        "raw transaction inventory differs"
    );
    let [first, middle, last] = &input.operations;
    ensure!(
        input.kontor_txids == [first.txid.clone()]
            && first.contract == last.contract
            && first.contract != middle.contract,
        "expected one reveal and A/B/A contracts"
    );
    ensure!(
        value.artifacts[0].addresses.iter().collect::<BTreeSet<_>>()
            == BTreeSet::from([&first.contract, &middle.contract]),
        "smoke artifact differs"
    );
    for (index, (operation, expression)) in input
        .operations
        .iter()
        .zip([
            "write-result-payload(1)",
            "scan-compound(false)",
            "write-result-payload(2)",
        ])
        .enumerate()
    {
        ensure!(
            operation.expression.0 == expression
                && operation.op_index as usize == index
                && operation.gas_limit == 100000,
            "operation order or expression differs"
        );
        ensure!(
            operation.txid == first.txid
                && operation.tx_index == first.tx_index
                && operation.input_index == first.input_index,
            "operations must share one reveal input"
        );
        ensure!(
            operation.tx_index > 0
                && input.raw_txids.get(operation.tx_index as usize) == Some(&operation.txid),
            "original Bitcoin transaction index differs"
        );
    }
    Ok(())
}

pub(super) fn report(value: &Report) -> Result<()> {
    ensure!(value.schema_version == 1, "unsupported report version");
    ensure!(
        ordered(&value.receipts.iter().map(|r| r.id).collect::<Vec<_>>())
            && value.receipts.iter().all(|r| r.height == value.height),
        "receipt identity/order differs"
    );
    ensure!(
        !value.table_counts.is_empty()
            && ordered(
                &value
                    .table_counts
                    .iter()
                    .map(|r| &r.table)
                    .collect::<Vec<_>>()
            ),
        "table inventory differs"
    );
    let accounts = &value.accounts;
    ensure!(
        accounts.total_supply.floor.text == "0",
        "total supply cannot have a floor"
    );
    for account in [
        &accounts.payer,
        &accounts.burner,
        &accounts.core,
        &accounts.ordering_pool,
        &accounts.storage_pool,
        &accounts.total_supply,
    ] {
        ensure!(
            account.balance.units >= account.floor.units,
            "account below collateral floor"
        );
    }
    let mut block_seen = false;
    let mut txids = BTreeSet::new();
    let mut positions = Vec::new();
    for usage in &value.usage {
        ensure!(usage.height == value.height, "usage outside report height");
        match usage.kind {
            UsageKind::Transaction => {
                ensure!(
                    !block_seen && usage.txid.is_some() && usage.tx_index.is_some(),
                    "transaction usage ordering or identity differs"
                );
                ensure!(txids.insert(&usage.txid), "duplicate transaction usage");
                positions.push(usage.tx_index);
            }
            UsageKind::Block => {
                ensure!(
                    !block_seen
                        && usage.txid.is_none()
                        && usage.tx_index.is_none()
                        && usage.user_fuel == 0
                        && usage.deposit_fuel == 0,
                    "invalid maintenance usage"
                );
                block_seen = true;
            }
        }
    }
    ensure!(
        ordered(&positions),
        "usage positions must be sorted and unique"
    );
    let mut keys = Vec::new();
    for version in &value.state_versions {
        ensure!(
            version.depositor.is_none() == version.deposited_gas.is_none()
                && version.height <= value.height,
            "invalid state version"
        );
        for bytes in [&version.path_hex, &version.value_hex] {
            ensure!(
                bytes.len() % 2 == 0
                    && bytes
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid hex bytes"
            );
        }
        keys.push((&version.contract, &version.path_hex, version.height));
    }
    ensure!(ordered(&keys), "state versions must be sorted and unique");
    Ok(())
}

pub(super) fn reports(
    manifest: &Manifest,
    before: &Report,
    after: &Report,
    numeric: &Numeric,
) -> Result<()> {
    report(before)?;
    report(after)?;
    let (snapshot, input) = (&manifest.snapshot, &manifest.input);
    ensure!(
        before.height == snapshot.anchor_height
            && before.block_hash == snapshot.anchor_hash
            && before.checkpoint == snapshot.checkpoint
            && before.prune_watermark == snapshot.prune_watermark,
        "reset report differs from snapshot anchor"
    );
    ensure!(
        after.height == input.height && after.block_hash == input.block_hash,
        "result report describes a different block"
    );
    ensure!(
        input.height.checked_sub(
            manifest
                .execution
                .effective_retain_blocks
                .unwrap_or(manifest.execution.retain_blocks)
        ) == Some(after.prune_watermark),
        "pruning watermark differs"
    );
    ensure!(
        before
            .table_counts
            .iter()
            .map(|r| &r.table)
            .eq(after.table_counts.iter().map(|r| &r.table)),
        "persistent schema table set changed"
    );
    for (index, (a, b)) in [
        (&before.contract_views.a, &after.contract_views.a),
        (&before.contract_views.b, &after.contract_views.b),
    ]
    .iter()
    .enumerate()
    {
        ensure!(
            a.address == input.operations[index].contract
                && b.address == a.address
                && a.storage_state == [0; 4]
                && b.storage_state == if index == 0 { [1, 0, 0, 1] } else { [0; 4] },
            "contract view identity or state differs"
        );
    }
    ensure!(
        after
            .usage
            .iter()
            .filter(|u| u.kind == UsageKind::Block)
            .count()
            == 1,
        "missing block lifecycle usage"
    );
    check_numeric(manifest, after, numeric)?;
    let (first, last) = (&numeric.operations[0], &numeric.operations[2]);
    ensure!(
        before.accounts.payer.balance == first.payer_before
            && after.accounts.payer.balance == last.payer_after
            && before.accounts.burner.balance == first.burner_before
            && after.accounts.burner.balance == last.burner_after
            && before.accounts.payer.floor == first.floor_before
            && after.accounts.payer.floor == last.floor_after,
        "numeric account boundary differs"
    );
    let prior: BTreeMap<_, _> = before
        .state_versions
        .iter()
        .map(|r| ((&r.contract, &r.path_hex, r.height), r))
        .collect();
    let next: BTreeMap<_, _> = after
        .state_versions
        .iter()
        .map(|r| ((&r.contract, &r.path_hex, r.height), r))
        .collect();
    let removed: Vec<_> = prior
        .keys()
        .filter(|key| !next.contains_key(*key))
        .collect();
    ensure!(!removed.is_empty(), "smoke lacks useful pruning");
    for key in removed {
        ensure!(
            key.2 <= after.prune_watermark,
            "removed state inside retention window"
        );
        let latest = prior
            .iter()
            .filter(|(candidate, _)| {
                candidate.0 == key.0
                    && candidate.1 == key.1
                    && key.2 < candidate.2
                    && candidate.2 <= after.prune_watermark
            })
            .max_by_key(|(key, _)| key.2);
        ensure!(
            latest.is_some_and(|(key, row)| !row.deleted && next.get(key) == Some(row)),
            "pruning lost retained live successor"
        );
    }
    Ok(())
}

fn check_numeric(manifest: &Manifest, report: &Report, numeric: &Numeric) -> Result<()> {
    let input = &manifest.input;
    ensure!(
        numeric.schema_version == 1
            && numeric.snapshot_sha256 == manifest.snapshot.database.sha256
            && numeric.raw_block_sha256 == input.raw_block.sha256
            && numeric.source_commit == manifest.source.kontor_commit,
        "numeric source/snapshot/block differs"
    );
    let txid = &input.kontor_txids[0];
    ensure!(
        report
            .receipts
            .iter()
            .all(|r| r.txid.as_ref().is_none_or(|id| id == txid)),
        "receipt belongs to unplanned transaction"
    );
    let receipts: Vec<_> = report
        .receipts
        .iter()
        .filter(|r| r.txid.as_ref() == Some(txid))
        .collect();
    ensure!(receipts.len() == 3, "paid roots missing or duplicated");
    let signer = receipts[0].signer_id;
    let values = [Some("\"é\\n\""), None, Some("\"é\\né\\n\"")];
    for (i, ((expected, actual), receipt)) in input
        .operations
        .iter()
        .zip(&numeric.operations)
        .zip(&receipts)
        .enumerate()
    {
        ensure!(
            actual.txid == expected.txid
                && actual.tx_index == expected.tx_index
                && actual.input_index == expected.input_index
                && actual.op_index == expected.op_index
                && actual.contract == expected.contract
                && actual.expression == expected.expression,
            "numeric operation identity differs"
        );
        // Receipts use the persisted filtered transaction slot, not the raw block index.
        ensure!(
            receipt.tx_index == Some(0),
            "persisted receipt transaction position differs"
        );
        ensure!(
            receipt.txid.as_ref() == Some(&expected.txid)
                && receipt.input_index == Some(expected.input_index)
                && receipt.op_index == Some(expected.op_index)
                && receipt.contract == expected.contract,
            "paid roots reordered or substituted"
        );
        ensure!(
            receipt.signer_id == signer && receipt.payer_signer_id == Some(signer),
            "smoke roots use different payer"
        );
        let status = if i == 1 { Status::Other } else { Status::Ok };
        ensure!(
            actual.status == status
                && receipt.status == status
                && actual.value.as_deref() == values[i]
                && receipt.value == actual.value,
            "smoke outcome/value differs"
        );
        ensure!(
            receipt.func.0 == expected.expression.0.split('(').next().unwrap()
                && receipt.result_index == 0,
            "receipt function/result index differs"
        );
        ensure!(
            actual.gas > 0 && actual.gas == receipt.gas && actual.gas <= expected.gas_limit,
            "gas differs or exceeds limit"
        );
        let multiplier = manifest.execution.gas_to_fuel_multiplier;
        let gross = u128::from(actual.user_fuel) + u128::from(actual.deposit_fuel);
        ensure!(
            u128::from(actual.gas) == gross.div_ceil(u128::from(multiplier)).max(1),
            "gas differs from gross user fuel"
        );
        ensure!(
            actual.storage_state == if i == 1 { [0; 4] } else { [1, 0, 0, 1] },
            "committed state or rollback differs"
        );
        ensure!(
            actual.deposit_fuel.is_multiple_of(multiplier),
            "fractional deposit reservation"
        );
        let reserved = actual.deposit_fuel / multiplier;
        ensure!(
            actual.reserved_deposit_gas == reserved && reserved <= actual.gas,
            "invalid deposit reservation"
        );
        let fee = BigUint::from(actual.gas - reserved) * &manifest.execution.execution_price.units;
        ensure!(
            actual.execution_fee.units == fee
                && actual.payer_before.units == &actual.payer_after.units + &fee
                && actual.burner_after.units == &actual.burner_before.units + &fee
                && actual.payer_after.units >= actual.floor_after.units,
            "numeric fee or collateral differs"
        );
        if i > 0 {
            let previous = &numeric.operations[i - 1];
            ensure!(
                actual.payer_before == previous.payer_after
                    && actual.burner_before == previous.burner_after
                    && actual.floor_before == previous.floor_after,
                "numeric check lost prior effects"
            );
        }
        if i == 1 {
            ensure!(
                actual
                    .error_message
                    .as_ref()
                    .is_some_and(|s| s.contains("row scan requires direct scalar leaves"))
                    && reserved > 0
                    && actual.floor_before == actual.floor_after,
                "wrong deterministic failure or reservation cleanup"
            );
        } else {
            ensure!(
                actual.error_message.is_none(),
                "successful operation has an error"
            );
        }
    }
    let usage: Vec<_> = report
        .usage
        .iter()
        .filter(|u| u.kind == UsageKind::Transaction)
        .collect();
    ensure!(
        usage.len() == 1
            && usage[0].txid.as_ref() == Some(txid)
            && usage[0].tx_index == Some(input.operations[0].tx_index),
        "missing reveal usage or position differs"
    );
    for (expected, actual) in [
        (
            numeric
                .operations
                .iter()
                .map(|o| u128::from(o.user_fuel))
                .sum::<u128>(),
            usage[0].user_fuel,
        ),
        (
            numeric
                .operations
                .iter()
                .map(|o| u128::from(o.system_fuel))
                .sum::<u128>(),
            usage[0].system_fuel,
        ),
        (
            numeric
                .operations
                .iter()
                .map(|o| u128::from(o.deposit_fuel))
                .sum::<u128>(),
            usage[0].deposit_fuel,
        ),
    ] {
        ensure!(
            expected == u128::from(actual),
            "numeric fuel differs from transaction usage"
        );
    }
    Ok(())
}
