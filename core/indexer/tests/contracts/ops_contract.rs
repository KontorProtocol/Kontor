use anyhow::bail;
use bitcoin::consensus::encode::deserialize_hex;
use indexer::reg_tester::InstructionResult;
use indexer_types::{Inst, InstKind, Op, OpKind, OpMetadata, Payment};
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_get_ops_from_api() -> Result<()> {
    let name = "test-token";
    let bytes = runtime.contract_reader.read(name).await?.unwrap();

    let mut rt = runtime.reg_tester().unwrap();
    let mut ident = rt.identity().await?;
    let InstructionResult { reveal_tx_hex, .. } = rt
        .instruction(
            &mut ident,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Publish {
                    name: name.to_string(),
                    bytes: bytes.clone(),
                    provenance: sample_provenance(),
                },
            },
        )
        .await?;

    let reveal_tx = deserialize_hex::<bitcoin::Transaction>(&reveal_tx_hex)?;

    let ops = rt.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].op().expect("op must be materialized"),
        &Op {
            metadata: OpMetadata {
                previous_output: reveal_tx.input[0].previous_output,
                input_index: 0,
                op_index: 0,
                signer_id: rt
                    .get_signer_id(&ident.x_only_public_key().to_string())
                    .await?
                    .expect("signer must be registered"),
                payment: Payment {
                    signer_id: rt
                        .get_signer_id(&ident.x_only_public_key().to_string())
                        .await?
                        .expect("signer must be registered"),
                    gas_limit: 10_000,
                },
            },
            kind: OpKind::Publish {
                name: name.to_string(),
                bytes,
                provenance: sample_provenance(),
            },
        }
    );
    let result = ops[0].result();
    assert!(result.is_some());
    if let Some(result) = result {
        assert!(
            result.contract.starts_with("test-token_"),
            "contract address should start with test-token_, got: {}",
            result.contract
        );
        // Publish ops now carry the new contract's address as their
        // result value — init returns a `contract` resource that the
        // host drains to a `contract-address` record at the WAVE
        // boundary. See project_contract_resource_publish_return.
        let value = result
            .value
            .as_ref()
            .expect("publish must surface an address");
        assert!(
            value.contains("name: \"test-token\""),
            "publish result value should be the new contract's address record; got: {value}"
        );
        assert!(result.gas > 0);
    } else {
        bail!("Unexpected result event: {:?}", result);
    }

    assert_eq!(
        ops,
        rt.transaction_inspect(&reveal_tx.compute_txid()).await?
    );

    Ok(())
}
