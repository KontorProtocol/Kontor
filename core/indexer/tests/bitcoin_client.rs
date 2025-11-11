use testlib::*;

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
async fn test_bitcoin_client() -> Result<()> {
    let client = reg_tester.bitcoin_client().await;
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
