use bitcoin::Txid;
use indexer::{
    bitcoin_follower::{events::Event, reconciler::handle_new_mempool_transactions},
    block::HasTxid,
    test_utils::MockTransaction,
};
use indexmap::IndexMap;

#[test]
fn test_empty_initial_state() {
    let mut mempool_cache: IndexMap<Txid, MockTransaction> = IndexMap::new();
    let tx1 = MockTransaction::new(1);
    let tx2 = MockTransaction::new(2);
    let txs = vec![tx1.clone(), tx2.clone()];

    let result = handle_new_mempool_transactions(&mut mempool_cache, txs);

    assert_eq!(
        result,
        vec![Event::MempoolInsert(vec![tx1.clone(), tx2.clone()])]
    );
    assert_eq!(mempool_cache.len(), 2);
    assert!(mempool_cache.contains_key(&tx1.txid()));
    assert!(mempool_cache.contains_key(&tx2.txid()));
}

#[test]
fn test_adding_and_removing_transactions() {
    let tx1 = MockTransaction::new(1);
    let tx2 = MockTransaction::new(2);
    let tx3 = MockTransaction::new(3);
    let tx4 = MockTransaction::new(4);
    let tx5 = MockTransaction::new(5);

    let mut mempool_cache: IndexMap<Txid, MockTransaction> = IndexMap::from([
        (tx1.txid(), tx1.clone()),
        (tx3.txid(), tx3.clone()),
        (tx5.txid(), tx5.clone()),
    ]);
    let txs = vec![tx2.clone(), tx4.clone(), tx5.clone()];

    let result = handle_new_mempool_transactions(&mut mempool_cache, txs);

    assert_eq!(
        result,
        vec![
            Event::MempoolRemove(vec![tx1.txid(), tx3.txid()]),
            Event::MempoolInsert(vec![tx2.clone(), tx4.clone()])
        ]
    );
    assert_eq!(mempool_cache.len(), 3);
    assert!(mempool_cache.contains_key(&tx2.txid()));
    assert!(mempool_cache.contains_key(&tx4.txid()));
    assert!(mempool_cache.contains_key(&tx5.txid()));
}

#[test]
fn test_no_changes() {
    let tx1 = MockTransaction::new(1);
    let mut mempool_cache: IndexMap<Txid, MockTransaction> =
        IndexMap::from([(tx1.txid(), tx1.clone())]);
    let txs = vec![tx1.clone()];

    let result = handle_new_mempool_transactions(&mut mempool_cache, txs);

    assert_eq!(result, vec![]);
    assert_eq!(mempool_cache.len(), 1);
    assert!(mempool_cache.contains_key(&tx1.txid()));
}

#[test]
fn test_empty_new_transactions() {
    let tx1 = MockTransaction::new(1);
    let mut mempool_cache: IndexMap<Txid, MockTransaction> =
        IndexMap::from([(tx1.txid(), tx1.clone())]);
    let txs = vec![];

    let result = handle_new_mempool_transactions(&mut mempool_cache, txs);

    assert_eq!(result, vec![Event::MempoolRemove(vec![tx1.txid()])]);
    assert!(mempool_cache.is_empty());
}

#[test]
fn test_duplicate_transactions() {
    let mut mempool_cache: IndexMap<Txid, MockTransaction> = IndexMap::new();
    let tx1 = MockTransaction::new(1);
    let txs = vec![tx1.clone(), tx1.clone()]; // Duplicate transactions

    let result = handle_new_mempool_transactions(&mut mempool_cache, txs);

    assert_eq!(result, vec![Event::MempoolInsert(vec![tx1.clone()])]);
    assert_eq!(mempool_cache.len(), 1);
    assert!(mempool_cache.contains_key(&tx1.txid()));
}
