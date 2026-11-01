use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result};

use super::bundle_session::{BundleSession, infrastructure};
use super::numerics::string_to_decimal;
use super::staking::api::wave::{get_sigma_min_call_expr, get_sigma_min_parse_return_expr};
use super::staking::{self, api};
use super::wit::Signer;
use super::{
    ContractAddress, Decimal, GenesisParameters, GenesisValidator, Runtime, TransactionContext,
};
use crate::protocol::operations::{GenesisEnvelope, InitializationStep, InitializeCall};
use crate::protocol::v1::native::{NATIVE_CONTRACTS, native_provenance};

struct Initialization {
    genesis: GenesisParameters,
    next: AtomicUsize,
    needs_floor: AtomicBool,
    needs_validators: AtomicBool,
}

#[derive(Clone, Copy)]
enum Step {
    Prepare,
    Publish(usize),
    Validate(usize),
    ReadFloor,
    WriteFloor,
    Validators,
}

impl Step {
    fn commits(self) -> bool {
        !matches!(self, Self::Validate(_) | Self::ReadFloor)
    }

    async fn run(self, runtime: &mut Runtime, initialization: &Initialization) -> Result<()> {
        let core = Signer::Core(Box::new(Signer::Nobody));
        match self {
            Self::Prepare => {
                runtime
                    .set_context(0, Some(TransactionContext::builder().build()), None, None)
                    .await;
                let progress = runtime.storage.native_bootstrap_progress().await?;
                runtime
                    .result_id_counter
                    .restore(progress.next_result_index)
                    .await;
                initialization
                    .needs_validators
                    .store(!progress.validators_initialized, Ordering::SeqCst);
                runtime.storage.create_core_signer().await?;
            }
            Self::Publish(index) => {
                let (name, bytes) = NATIVE_CONTRACTS[index];
                let payment = runtime.core_payment();
                runtime
                    .publish(&core, payment, name, bytes, &native_provenance()?)
                    .await?;
            }
            Self::Validate(index) => {
                let address = ContractAddress {
                    name: NATIVE_CONTRACTS[index].0.into(),
                    height: 0,
                    tx_index: 0,
                };
                let id = runtime
                    .storage
                    .contract_id(&address)
                    .await?
                    .with_context(|| {
                        format!(
                            "native contract missing after publication: {}",
                            address.name
                        )
                    })?;
                let component = runtime.load_component(id).await?;
                runtime.linkers.native.instantiate_pre(&component)?;
            }
            Self::ReadFloor => {
                let result = runtime
                    .execute_system_view(&staking::address(), &get_sigma_min_call_expr())
                    .await?;
                initialization.needs_floor.store(
                    get_sigma_min_parse_return_expr(&result) == Decimal::default(),
                    Ordering::SeqCst,
                );
            }
            Self::WriteFloor => {
                if initialization.needs_floor.load(Ordering::SeqCst) {
                    api::set_sigma_min(runtime, &core, initialization.genesis.sigma_min).await??;
                }
            }
            Self::Validators => {
                if initialization.needs_validators.load(Ordering::SeqCst)
                    && !initialization.genesis.validators.is_empty()
                {
                    let validators = initialization
                        .genesis
                        .validators
                        .iter()
                        .cloned()
                        .map(Into::into)
                        .collect();
                    api::set_genesis_set(runtime, &core, validators).await?;
                }
            }
        }
        Ok(())
    }
}

fn decode_genesis((floor, validators): GenesisEnvelope) -> Result<GenesisParameters> {
    Ok(GenesisParameters {
        sigma_min: string_to_decimal(&floor).context("invalid genesis sigma_min")?,
        validators: validators
            .into_iter()
            .map(|(x_only_pubkey, stake, ed25519_pubkey)| {
                Ok(GenesisValidator {
                    x_only_pubkey,
                    stake: string_to_decimal(&stake).context("invalid genesis validator stake")?,
                    ed25519_pubkey,
                })
            })
            .collect::<Result<_>>()?,
    })
}

impl BundleSession {
    pub(crate) fn initializer(self: &Arc<Self>) -> InitializeCall {
        let expected = self.clone();
        Arc::new(move |opaque, genesis| {
            expected.verify_operation_owner(opaque)?;
            let initialization = Arc::new(Initialization {
                genesis: decode_genesis(genesis).map_err(infrastructure)?,
                next: AtomicUsize::new(0),
                needs_floor: AtomicBool::new(false),
                needs_validators: AtomicBool::new(false),
            });
            let steps = std::iter::once(Step::Prepare)
                .chain(
                    (0..NATIVE_CONTRACTS.len()).flat_map(|i| [Step::Publish(i), Step::Validate(i)]),
                )
                .chain([Step::ReadFloor, Step::WriteFloor, Step::Validators]);
            Ok(steps
                .enumerate()
                .map(|(index, step)| -> InitializationStep {
                    let session = expected.clone();
                    let initialization = initialization.clone();
                    (
                        step.commits(),
                        Box::new(move |opaque, selection| {
                            Box::pin(async move {
                                session.verify_operation_owner(opaque)?;
                                let mut runtime = session.runtime.lock().await;
                                runtime
                                    .verify_bundle_operation(&selection, 7)
                                    .map_err(infrastructure)?;
                                if selection.3 != (7, 0, None, index as u64) {
                                    return Err((
                                        2,
                                        "initialization step does not match selection".into(),
                                    ));
                                }
                                if initialization.next.load(Ordering::SeqCst) != index {
                                    return Err((
                                        2,
                                        "initialization steps are out of order".into(),
                                    ));
                                }
                                let mut runtime =
                                    runtime.bind_selection(&selection).map_err(infrastructure)?;
                                if runtime.storage.savepoint_stack.is_empty().await {
                                    return Err((
                                        2,
                                        "initialization requires an open canonical unit".into(),
                                    ));
                                }
                                step.run(&mut runtime, &initialization)
                                    .await
                                    .map_err(infrastructure)?;
                                initialization.next.store(index + 1, Ordering::SeqCst);
                                Ok(())
                            })
                        }),
                    )
                })
                .collect())
        })
    }
}
