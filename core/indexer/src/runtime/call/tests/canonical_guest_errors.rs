use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use anyhow::{Result, anyhow, ensure};
use brotli::{CompressorReader, Decompressor};
use indexer_types::Payment;
use libsql::params;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use wasm_encoder::{CodeSection, Function, Instruction, Module as EncodedModule, RawSection};
use wasmparser::{
    BinaryReader, CodeSectionReader, ExternalKind, Operator, Parser, Payload, TypeRef, Validator,
};
use wasmtime::Error as WasmtimeError;
use wasmtime::component::ResourceTable;

use super::{balance, funded};
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, Linkers, MAX_UNTRUSTED_GAS_LIMIT, Runtime,
    TransactionContext, native_provenance, to_wave_expr,
};
use crate::test_utils::test_runtime;

const BORROW_ERROR: &str = "borrow handles still remain at the end of the call";
const ORIGINAL_RAW_SHA256: &str =
    "b45d937af90aa9d68d19e0908f9862030b24a620a02966cbc73dce170ab471e0";
const ORIGINAL_COMPRESSED_SHA256: &str =
    "8610f85f6abdd1bdeb0d32c0916cf154493535299d2c4d8fa0e053f0ee2df875";

#[derive(Clone, Copy)]
enum Fault {
    UnreleasedBorrow,
    DoubleDrop,
    WrongType,
}

impl Fault {
    fn message(self) -> &'static str {
        match self {
            Self::UnreleasedBorrow => BORROW_ERROR,
            Self::DoubleDrop => "unknown handle index 1",
            Self::WrongType => {
                "handle index 1 used with the wrong type, expected guest-defined resource but found a different guest-defined resource"
            }
        }
    }
}

fn inject_resource_fault(bytes: &[u8], fault: Fault) -> Result<Vec<u8>> {
    ensure!(
        hex::encode(Sha256::digest(bytes)) == ORIGINAL_RAW_SHA256,
        "original error-test fixture changed"
    );
    let mut encoded = EncodedModule::new();
    let mut imported_functions = 0;
    let mut view = None;
    let mut proc = None;
    let mut patched_view = false;
    let mut patched_proc = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        match &payload {
            Payload::Version { .. } | Payload::CodeSectionEntry(_) | Payload::End(_) => continue,
            Payload::ImportSection(imports) => {
                for import in imports.clone().into_imports() {
                    if matches!(import?.ty, TypeRef::Func(_)) {
                        imported_functions += 1;
                    }
                }
            }
            Payload::ExportSection(exports) => {
                for export in exports.clone() {
                    let export = export?;
                    if export.name == "succeed" {
                        ensure!(export.kind == ExternalKind::Func);
                        view = Some(export.index);
                    } else if export.name == "chain-probe" {
                        ensure!(export.kind == ExternalKind::Func);
                        proc = Some(export.index);
                    }
                }
            }
            Payload::CodeSectionStart {
                unchecked_range, ..
            } => {
                let start = usize::try_from(unchecked_range.start)?;
                let end = usize::try_from(unchecked_range.end)?;
                let reader = CodeSectionReader::new(BinaryReader::new(
                    &bytes[start..end],
                    unchecked_range.start,
                ))?;
                let mut section = CodeSection::new();
                for (index, body) in reader.into_iter().enumerate() {
                    let body = body?;
                    let function_index = imported_functions + u32::try_from(index)?;
                    if Some(function_index) == view {
                        let mut replacement = Function::new([]);
                        // The pinned raw module imports proc/view resource drops at 0/3.
                        match fault {
                            Fault::UnreleasedBorrow => {}
                            Fault::DoubleDrop => {
                                replacement.instruction(&Instruction::LocalGet(0));
                                replacement.instruction(&Instruction::Call(3));
                                replacement.instruction(&Instruction::LocalGet(0));
                                replacement.instruction(&Instruction::Call(3));
                            }
                            Fault::WrongType => {
                                replacement.instruction(&Instruction::LocalGet(0));
                                replacement.instruction(&Instruction::Call(0));
                            }
                        }
                        replacement.instruction(&Instruction::I64Const(42));
                        replacement.instruction(&Instruction::End);
                        section.function(&replacement);
                        patched_view = true;
                    } else if Some(function_index) == proc {
                        let range = body.range();
                        let mut original = bytes
                            [usize::try_from(range.start)?..usize::try_from(range.end)?]
                            .to_vec();
                        let mut operators = body.get_operators_reader()?;
                        let mut drop_call = None;
                        while !operators.eof() {
                            let (operator, offset) = operators.read_with_offset()?;
                            if matches!(operator, Operator::Call { function_index: 59 }) {
                                ensure!(drop_call.is_none(), "unexpected duplicate proc drop");
                                drop_call = Some(offset);
                            }
                        }
                        let offset = usize::try_from(
                            drop_call.ok_or_else(|| anyhow!("missing proc drop"))? - range.start,
                        )?;
                        // Call 59 wraps proc-context drop, call 62 wraps view-context
                        // drop. The raw hash pins these indices and one-byte LEBs.
                        ensure!(original.get(offset..offset + 2) == Some(&[0x10, 0x3b][..]));
                        match fault {
                            Fault::UnreleasedBorrow => {
                                original[offset..offset + 2].copy_from_slice(&[0x1a, 0x01]);
                            }
                            Fault::DoubleDrop => {
                                original.splice(offset + 2..offset + 2, [0x20, 0x00, 0x10, 0x3b]);
                            }
                            Fault::WrongType => {
                                original[offset..offset + 2].copy_from_slice(&[0x10, 0x3e]);
                            }
                        }
                        section.raw(&original);
                        patched_proc = true;
                    } else {
                        let range = body.range();
                        section.raw(
                            &bytes[usize::try_from(range.start)?..usize::try_from(range.end)?],
                        );
                    }
                }
                encoded.section(&section);
                continue;
            }
            _ => {}
        }
        if let Some((id, range)) = payload.as_section() {
            encoded.section(&RawSection {
                id,
                data: &bytes[usize::try_from(range.start)?..usize::try_from(range.end)?],
            });
        }
    }
    ensure!(patched_view && patched_proc, "missing target export body");
    let altered = encoded.finish();
    Validator::new().validate_all(&altered)?;
    Ok(altered)
}

fn published_fixture_bytes(fault: Fault) -> Result<Vec<u8>> {
    let compressed = include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br");
    ensure!(
        hex::encode(Sha256::digest(compressed)) == ORIGINAL_COMPRESSED_SHA256,
        "compressed error-test fixture changed"
    );
    let mut raw = Vec::new();
    Decompressor::new(compressed.as_slice(), 4096).read_to_end(&mut raw)?;
    let altered = inject_resource_fault(&raw, fault)?;
    eprintln!(
        "CE1 patched raw SHA256: {}",
        hex::encode(Sha256::digest(&altered))
    );
    let mut encoded = Vec::new();
    CompressorReader::new(altered.as_slice(), 4096, 5, 22).read_to_end(&mut encoded)?;
    Ok(encoded)
}

fn payment(actor: &Signer) -> Payment {
    Payment {
        signer_id: actor.signer_id().unwrap(),
        gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
    }
}

fn assert_call_tables_released(tables: &Arc<StdMutex<Vec<Weak<AsyncMutex<ResourceTable>>>>>) {
    let mut tables = tables.lock().unwrap();
    assert!(!tables.is_empty(), "no child Store observed");
    for table in tables.drain(..) {
        assert!(
            table.upgrade().is_none(),
            "call-owned resource table retained"
        );
    }
}

async fn publish_fault_chain(
    runtime: &mut Runtime,
    actor: &Signer,
    fault: Fault,
) -> Result<Vec<ContractAddress>> {
    let fault = published_fixture_bytes(fault)?;
    let proxy = include_bytes!("../../../../../../test-contracts/binaries/proxy.wasm.br");
    let mut chain: Vec<ContractAddress> = Vec::new();
    for (index, (name, bytes)) in [
        ("ce1-fault", fault.as_slice()),
        ("ce1-proxy", proxy.as_slice()),
        ("ce1-outer", proxy.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let index = u32::try_from(index)?;
        runtime
            .set_context(
                1,
                Some(TransactionContext::builder().tx_index(index).build()),
                None,
                None,
            )
            .await;
        runtime
            .publish(actor, payment(actor), name, bytes, &native_provenance()?)
            .await?;
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: index,
        };
        if let Some(child) = chain.last() {
            runtime
                .execute_api(
                    Some(actor),
                    &address,
                    &format!("set-contract-address({})", to_wave_expr(child.clone())),
                )
                .await?;
        }
        chain.push(address);
    }
    runtime.set_context(1, None, None, None).await;
    Ok(chain)
}

async fn assert_one_other_receipt(runtime: &Runtime, root_id: u64, before: u64) -> Result<u64> {
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT contract_id, status, gas FROM contract_results WHERE id > ? ORDER BY id",
            params![before],
        )
        .await?;
    let receipt = rows.next().await?.expect("one failed root receipt");
    assert_eq!(receipt.get::<u64>(0)?, root_id);
    assert_eq!(receipt.get::<String>(1)?, "Other");
    let gas = receipt.get::<u64>(2)?;
    assert!(gas > 0);
    assert!(rows.next().await?.is_none());
    Ok(gas)
}

async fn verify_published_resource_fault(fault: Fault) -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let actor = funded(&mut runtime).await?;
    let chain = publish_fault_chain(&mut runtime, &actor, fault).await?;
    let fault_id = runtime.storage.contract_id(&chain[0]).await?.unwrap();
    let outer_id = runtime.storage.contract_id(&chain[2]).await?.unwrap();
    let host_failure = Arc::new(AtomicBool::new(false));
    let call_tables: Arc<StdMutex<Vec<Weak<AsyncMutex<ResourceTable>>>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let mut user = runtime.linkers.user.clone();
    let fail = host_failure.clone();
    let observed_tables = call_tables.clone();
    user.allow_shadowing(true)
        .instance("kontor:built-in/testing")?
        .func_wrap_async("host-error", move |store, (): ()| {
            let fail = fail.clone();
            observed_tables
                .lock()
                .unwrap()
                .push(Arc::downgrade(&store.data().table));
            Box::new(async move {
                if fail.load(Ordering::SeqCst) {
                    Err(WasmtimeError::from_anyhow(anyhow!(fault.message())))
                } else {
                    Ok((String::new(),))
                }
            })
        })?;
    runtime.linkers = Arc::new(Linkers {
        user,
        native: runtime.linkers.native.clone(),
    });
    let conn = runtime.get_storage_conn();
    let mut view_fuel = None;
    for _ in 0..2 {
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        let before: u64 = rows.next().await?.unwrap().get(0)?;
        let usage_before = runtime.start_usage();
        let result = runtime.execute(None, None, &chain[0], "succeed()").await;
        assert!(
            matches!(result, Err(ExecutionError::Deterministic(ref error))
            if error.root_cause().to_string() == fault.message()),
            "{result:?}"
        );
        let fuel = runtime.finish_usage(usage_before)?.system_fuel;
        assert!(fuel > 0);
        if let Some(expected) = view_fuel {
            assert_eq!(fuel, expected);
        } else {
            view_fuel = Some(fuel);
        }
        let mut rows = conn
            .query("SELECT COUNT(*) FROM contract_results", ())
            .await?;
        assert_eq!(rows.next().await?.unwrap().get::<u64>(0)?, before);
        assert_eq!(
            runtime
                .execute(None, None, &chain[0], "storage-state()")
                .await?,
            "[0, 0, 0, 0]"
        );
        assert!(runtime.stack.is_empty().await);
        assert!(runtime.storage.savepoint_stack.is_empty().await);
    }
    for (target, root_id) in [(&chain[0], fault_id), (&chain[2], outer_id)] {
        let mut previous = None;
        for _ in 0..2 {
            let mut rows = conn
                .query("SELECT COALESCE(MAX(id), 0) FROM contract_results", ())
                .await?;
            let receipt_before: u64 = rows.next().await?.unwrap().get(0)?;
            let payer_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
            let burner_before = balance(&mut runtime, HolderRef::Burner).await?;
            let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
            let supply_before = token::total_supply(&mut runtime).await?;
            let usage_before = runtime.start_usage();
            let result = runtime
                .execute(
                    Some(&actor),
                    Some(payment(&actor)),
                    target,
                    "chain-probe(false)",
                )
                .await;
            assert!(
                matches!(result, Err(ExecutionError::Deterministic(ref error))
                if error.chain().any(|cause| cause.to_string() == fault.message())),
                "{result:?}"
            );
            let usage = runtime.finish_usage(usage_before)?;
            let user_fuel = usage.user_fuel;
            assert!(user_fuel > 0);
            assert_call_tables_released(&call_tables);
            let gas = assert_one_other_receipt(&runtime, root_id, receipt_before).await?;
            let paid = sub_decimal(
                payer_before,
                balance(&mut runtime, HolderRef::from(&actor)).await?,
            )?;
            let burned = sub_decimal(
                balance(&mut runtime, HolderRef::Burner).await?,
                burner_before,
            )?;
            assert_eq!(paid, burned);
            assert!(paid > Decimal::default());
            let reserved = usage.deposit_fuel / runtime.gas_to_fuel_multiplier;
            assert!(gas >= reserved);
            assert_eq!(paid, runtime.pricing.execution_fee(gas - reserved)?);
            assert_eq!(
                sub_decimal(supply_before, token::total_supply(&mut runtime).await?)?,
                burned
            );
            assert_eq!(
                token::floor(&mut runtime, HolderRef::from(&actor)).await?,
                floor_before
            );
            assert_eq!(
                runtime
                    .execute(None, None, &chain[0], "storage-state()")
                    .await?,
                "[0, 0, 0, 0]"
            );
            assert!(runtime.stack.is_empty().await);
            assert!(runtime.storage.savepoint_stack.is_empty().await);
            let observation = (user_fuel, gas, paid.to_string());
            if let Some(expected) = &previous {
                assert_eq!(&observation, expected);
            } else {
                previous = Some(observation);
            }
        }
    }
    host_failure.store(true, Ordering::SeqCst);
    let mut rows = conn
        .query("SELECT COALESCE(MAX(id), 0) FROM contract_results", ())
        .await?;
    let receipt_before: u64 = rows.next().await?.unwrap().get(0)?;
    let payer_before = balance(&mut runtime, HolderRef::from(&actor)).await?;
    let burner_before = balance(&mut runtime, HolderRef::Burner).await?;
    let floor_before = token::floor(&mut runtime, HolderRef::from(&actor)).await?;
    let supply_before = token::total_supply(&mut runtime).await?;
    let result = runtime
        .execute(
            Some(&actor),
            Some(payment(&actor)),
            &chain[0],
            "chain-probe(false)",
        )
        .await;
    assert!(
        matches!(result, Err(ExecutionError::NonDeterministic(ref error))
        if error.chain().any(|cause| cause.to_string() == fault.message())),
        "{result:?}"
    );
    assert_call_tables_released(&call_tables);
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM contract_results WHERE id > ?",
            params![receipt_before],
        )
        .await?;
    assert_eq!(rows.next().await?.unwrap().get::<u64>(0)?, 0);
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actor)).await?,
        payer_before
    );
    assert_eq!(
        balance(&mut runtime, HolderRef::Burner).await?,
        burner_before
    );
    assert_eq!(
        token::floor(&mut runtime, HolderRef::from(&actor)).await?,
        floor_before
    );
    assert_eq!(token::total_supply(&mut runtime).await?, supply_before);
    assert_eq!(
        runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    host_failure.store(false, Ordering::SeqCst);
    assert_eq!(
        runtime
            .execute(None, None, &chain[0], "storage-state()")
            .await?,
        "[0, 0, 0, 0]"
    );
    Ok(())
}

#[tokio::test]
async fn published_unreleased_borrow_settles_paid_and_nested_calls() -> Result<()> {
    verify_published_resource_fault(Fault::UnreleasedBorrow).await
}

#[tokio::test]
async fn published_double_drop_settles_paid_and_nested_calls() -> Result<()> {
    verify_published_resource_fault(Fault::DoubleDrop).await
}

#[tokio::test]
async fn published_wrong_resource_type_settles_paid_and_nested_calls() -> Result<()> {
    verify_published_resource_fault(Fault::WrongType).await
}
