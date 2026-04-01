use testlib::*;

use bitcoin::{
    Amount, OutPoint, Transaction, TxIn, TxOut, absolute::LockTime,
    consensus::serialize as serialize_tx, key::Secp256k1, transaction::Version,
};

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_bitcoin_client() -> Result<()> {
    let rt = runtime.reg_tester().unwrap();
    let client = rt.bitcoin_client().await;
    let info = client.get_blockchain_info().await?;
    let hash = client.get_block_hash(info.blocks).await?;
    let block = client.get_block(&hash).await?;

    let txids: Vec<_> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

    let txs = client.get_raw_transactions(txids.as_slice()).await?;

    assert!(!txs.is_empty(), "Expected at least one transaction");
    for result in txs {
        let tx = result?;
        assert!(!tx.input.is_empty(), "Transaction should have inputs");
    }

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_get_raw_mempool_sequence() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let client = rt.bitcoin_client().await;
    let mut ident = rt.identity().await?;

    // Build and submit several transactions to the mempool without mining
    let secp = Secp256k1::new();
    let mut expected_txids = Vec::new();
    for _ in 0..3 {
        let value = ident.next_funding_utxo.1.value - Amount::from_sat(1000);
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: ident.next_funding_utxo.0,
                ..Default::default()
            }],
            output: vec![TxOut {
                value,
                script_pubkey: ident.address.script_pubkey(),
            }],
        };
        indexer::test_utils::sign_key_spend(
            &secp,
            &mut tx,
            std::slice::from_ref(&ident.next_funding_utxo.1),
            &ident.keypair,
            0,
            None,
        )?;

        let raw_tx = hex::encode(serialize_tx(&tx));
        let txids = rt.send_to_mempool(&[raw_tx]).await?;
        expected_txids.push(txids[0]);

        // Chain: point to the unconfirmed output for the next iteration
        ident.next_funding_utxo = (
            OutPoint {
                txid: txids[0],
                vout: 0,
            },
            tx.output[0].clone(),
        );
    }

    let result = client.get_raw_mempool_sequence().await?;

    assert!(result.mempool_sequence > 0);
    for txid in &expected_txids {
        assert!(
            result.txids.contains(txid),
            "Expected txid {} not found in mempool",
            txid
        );
    }

    Ok(())
}
