use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use libsql::{AuthAction, AuthContext, Authorization, Connection};
use stdlib::to_wave_expr;

use crate::database::queries::{get_checkpoint_latest, get_identity};
use crate::runtime::stack::CallFrame;
use crate::runtime::token::{address, api};
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::kontor::built_in::error::Error as WitError;
use crate::runtime::wit::{Holder, Signer};
use crate::runtime::{Decimal, ExecutionError, TransactionContext};
use crate::test_utils::test_runtime;

const PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

async fn row_counts(conn: &Connection) -> Result<Vec<i64>> {
    let mut counts = Vec::new();
    for table in [
        "signers",
        "x_only_pubkeys",
        "nonces",
        "contract_state",
        "contract_results",
    ] {
        let mut rows = conn
            .query(&format!("SELECT COUNT(*) FROM {table}"), ())
            .await?;
        counts.push(rows.next().await?.expect("count row").get(0)?);
    }
    Ok(counts)
}

#[tokio::test]
async fn holder_database_faults_abort_real_view_and_proc_calls() -> Result<()> {
    for (is_proc, fail_insert) in [(false, false), (true, false), (true, true)] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        runtime
            .set_context(1, Some(TransactionContext::builder().build()), None, None)
            .await;
        let conn = runtime.get_storage_conn();
        runtime.storage.savepoint().await?;
        let savepoint = runtime.storage.savepoint_stack.peek().await;
        let before = row_counts(&conn).await?;
        let checkpoint = get_checkpoint_latest(&conn).await?;
        let result_index = runtime.result_id_counter.get().await;
        let denials = Arc::new(AtomicUsize::new(0));
        let observed = denials.clone();
        conn.authorizer(Some(Arc::new(move |context: &AuthContext<'_>| {
            let reject = match context.action {
                AuthAction::Read {
                    table_name: "x_only_pubkeys",
                    ..
                } => !fail_insert,
                // Fail after the signer and public-key rows were inserted, proving rollback.
                AuthAction::Insert {
                    table_name: "nonces",
                } => fail_insert,
                _ => false,
            };
            if reject {
                observed.fetch_add(1, Ordering::SeqCst);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        })))?;
        let reference = to_wave_expr(HolderRef::XOnlyPubkey(PUBKEY.into()));
        let expr = if is_proc {
            format!(
                "issue-to({reference}, {})",
                to_wave_expr(Decimal::from("1"))
            )
        } else {
            format!("balance({reference})")
        };
        let core = Signer::Core(Box::new(Signer::Nobody));
        let result = runtime
            .execute_api(is_proc.then_some(&core), &address(), &expr)
            .await;
        conn.authorizer(None)?;
        assert!(
            denials.load(Ordering::SeqCst) > 0,
            "fault must reach identity SQL"
        );
        assert!(
            matches!(result, Err(ExecutionError::NonDeterministic(_))),
            "proc={is_proc} insert={fail_insert}: {result:?}"
        );
        assert!(runtime.stack.is_empty().await);
        assert_eq!(runtime.storage.savepoint_stack.peek().await, savepoint);
        assert_eq!(runtime.result_id_counter.get().await, result_index);
        assert_eq!(row_counts(&conn).await?, before);
        assert_eq!(get_checkpoint_latest(&conn).await?, checkpoint);
        assert!(get_identity(&conn, PUBKEY).await?.is_none());
        runtime.storage.rollback().await?;
        assert!(conn.is_autocommit());
        assert_eq!(row_counts(&conn).await?, before);

        // With the fault removed, a missing identity is still an ordinary view miss.
        assert_eq!(
            api::balance(&mut runtime, HolderRef::XOnlyPubkey(PUBKEY.into())).await?,
            None
        );
        api::issue_to(
            &mut runtime,
            &core,
            HolderRef::XOnlyPubkey(PUBKEY.into()),
            Decimal::from("1"),
        )
        .await??;
        assert_eq!(
            api::balance(&mut runtime, HolderRef::XOnlyPubkey(PUBKEY.into())).await?,
            Some(Decimal::from("1"))
        );
    }
    Ok(())
}

#[tokio::test]
async fn holder_validation_errors_keep_their_original_text() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    runtime
        .stack
        .push(CallFrame {
            contract_id: 1,
            is_proc: false,
            depositor: None,
        })
        .await?;
    for (reference, expected) in [
        (
            HolderRef::XOnlyPubkey("invalid".into()),
            "invalid x-only-pubkey: malformed public key".to_owned(),
        ),
        (
            HolderRef::XOnlyPubkey(PUBKEY.into()),
            format!(
                "identity resolution failed: deterministic error: signer not found for x-only-pubkey {PUBKEY} (view context — signer creation requires a proc context)"
            ),
        ),
    ] {
        let result = Holder::from_holder_ref(reference, &runtime).await?;
        let Err(WitError::Validation(message)) = result else {
            panic!("expected the existing validation outcome");
        };
        assert_eq!(message, expected);
    }
    runtime.stack.pop().await;
    Ok(())
}
