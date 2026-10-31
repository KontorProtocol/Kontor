use anyhow::Result;

use super::OwnedTestRuntime;
use crate::runtime::token::api as token_api;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, ExecutionError};

struct Settlement {
    payer: Decimal,
    burner: Decimal,
    receipts: Vec<(String, u64)>,
}

async fn settlement(runtime: &OwnedTestRuntime, signer: &Signer) -> Result<Settlement> {
    let signer = signer.clone();
    runtime
        .session
        .run(false, move |runtime| {
            Box::pin(async move {
                let payer = token_api::balance(runtime, HolderRef::from(&signer))
                    .await?
                    .unwrap_or_default();
                let burner = token_api::balance(runtime, HolderRef::Burner)
                    .await?
                    .unwrap_or_default();
                let mut rows = runtime
                    .get_storage_conn()
                    .query(
                        "SELECT status, gas FROM contract_results
                         WHERE func = 'trap-out-of-fuel' ORDER BY id",
                        (),
                    )
                    .await?;
                let mut receipts = Vec::new();
                while let Some(row) = rows.next().await? {
                    receipts.push((row.get(0)?, row.get(1)?));
                }
                Ok(Settlement {
                    payer,
                    burner,
                    receipts,
                })
            })
        })
        .await
}

#[tokio::test]
async fn deterministic_failure_keeps_public_test_api_settlement() -> Result<()> {
    let (runtime, _directory, _name) = OwnedTestRuntime::new(100_000).await?;
    let signer = runtime.identity().await?;
    runtime
        .load_contracts(
            &signer,
            &[(
                "error-test",
                include_bytes!("../../../../test-contracts/binaries/error_test.wasm.br"),
            )],
        )
        .await?;
    let address = ContractAddress {
        name: "error-test".into(),
        height: 1,
        tx_index: 0,
    };

    for api in [false, true] {
        let before = settlement(&runtime, &signer).await?;
        let error = runtime
            .execute(Some(&signer), &address, "trap-out-of-fuel()", api)
            .await
            .expect_err("guest must exhaust its fuel");
        assert!(matches!(
            error.downcast_ref::<ExecutionError>(),
            Some(ExecutionError::Deterministic(_))
        ));
        let after = settlement(&runtime, &signer).await?;
        assert_eq!(after.receipts.len(), before.receipts.len() + 1);
        assert_eq!(after.receipts[..before.receipts.len()], before.receipts);
        let (status, gas) = after.receipts.last().expect("failure receipt persisted");
        assert_eq!(status, "OutOfFuel");
        assert!(*gas > 0);
        assert!(after.payer < before.payer);
        assert!(after.burner > before.burner);
    }
    Ok(())
}
