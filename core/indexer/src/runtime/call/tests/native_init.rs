use anyhow::Result;
use indexer_types::Payment;
use stdlib::to_wave_expr;

use super::funded;
use crate::runtime::numerics::sub_decimal;
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, TransactionContext, native_provenance,
};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn native_init_is_private_to_first_publication() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let caller = funded(&mut runtime).await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    staking::set_sigma_min(&mut runtime, &core, Decimal::from("12")).await??;
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::from(&caller),
        Decimal::from("10"),
    )
    .await??;
    let sigma_before = staking::get_sigma_min(&mut runtime).await?;
    let supply_before = token::total_supply(&mut runtime).await?;
    let burner_before = token::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let caller_before = token::balance(&mut runtime, HolderRef::from(&caller))
        .await?
        .expect("funded caller balance");
    let payment = Payment {
        signer_id: caller.signer_id().expect("funded Id signer"),
        gas_limit: 100_000,
    };

    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(7).build()),
            None,
            None,
        )
        .await;
    let result = runtime
        .execute(
            Some(&caller),
            Some(payment.clone()),
            &staking_address(),
            "init()",
        )
        .await;
    assert!(matches!(result, Err(ExecutionError::Deterministic(_))));
    assert_eq!(staking::get_sigma_min(&mut runtime).await?, sigma_before);

    let core_payment = runtime.core_payment();
    let result = runtime
        .execute(
            Some(&core),
            Some(core_payment),
            &staking_address(),
            "init()",
        )
        .await;
    assert!(matches!(result, Err(ExecutionError::Deterministic(_))));
    assert_eq!(staking::get_sigma_min(&mut runtime).await?, sigma_before);

    let result = runtime
        .execute(
            Some(&caller),
            Some(payment.clone()),
            &token_address(),
            "init()",
        )
        .await;
    assert!(matches!(result, Err(ExecutionError::Deterministic(_))));
    let fee = sub_decimal(
        token::balance(&mut runtime, HolderRef::Burner)
            .await?
            .unwrap_or_default(),
        burner_before,
    )?;
    assert_eq!(
        sub_decimal(supply_before, token::total_supply(&mut runtime).await?)?,
        fee
    );
    assert_eq!(
        sub_decimal(
            caller_before,
            token::balance(&mut runtime, HolderRef::from(&caller))
                .await?
                .expect("funded caller balance"),
        )?,
        fee,
    );

    let proxy_bytes = include_bytes!("../../../../../../test-contracts/binaries/proxy.wasm.br");
    runtime
        .publish(
            &caller,
            payment.clone(),
            "native-init-proxy",
            proxy_bytes,
            &native_provenance()?,
        )
        .await?;
    let proxy = ContractAddress {
        name: "native-init-proxy".into(),
        height: 1,
        tx_index: 7,
    };
    runtime
        .execute(
            Some(&caller),
            Some(payment.clone()),
            &proxy,
            &format!("set-contract-address({})", to_wave_expr(staking_address())),
        )
        .await?;
    let result = runtime
        .execute(
            Some(&caller),
            Some(payment),
            &proxy,
            &format!("fallback({})", to_wave_expr("init()".to_string())),
        )
        .await;
    let error = match result {
        Err(ExecutionError::Deterministic(error)) => error,
        other => panic!("nested native init was not rejected: {other:?}"),
    };
    assert!(
        format!("{error:#}").contains("native init is only available during first publication"),
        "nested rejection came from another path: {error:#}"
    );
    assert_eq!(staking::get_sigma_min(&mut runtime).await?, sigma_before);
    Ok(())
}
