use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bitcoin::{self, BlockHash, hashes::Hash};

use indexer::{bitcoin_follower::rpc::run_orderer, block::Block};

use proptest::prelude::*;

fn gen_block(height: u64) -> Block {
    Block {
        height,

        // only height is relevant for orderer, using dummy values for the rest
        hash: BlockHash::from_byte_array([0x11; 32]),
        prev_hash: BlockHash::from_byte_array([0x11; 32]),
        transactions: vec![],
    }
}

fn arb_vec_numbers(max: u64) -> impl Strategy<Value = Vec<u64>> {
    (1..(max + 1))
        .prop_map(|l| (1..(l + 1)).collect::<Vec<u64>>())
        .prop_shuffle()
}

fn arb_vec_blocks(max: u64) -> impl Strategy<Value = Vec<Block>> {
    arb_vec_numbers(max).prop_map(|v| v.into_iter().map(gen_block).collect())
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        timeout: 300,
        .. ProptestConfig::default()
    })]

    #[test]
    // test_orderer by sending ranges of 1-10 blocks with heights 1-11 in shuffled order
    fn test_orderer(v in arb_vec_blocks(10)) {
        let cancel_token = CancellationToken::new();
        let (tx_in, rx_in) = mpsc::channel(100);
        let (tx_out, mut rx_out) = mpsc::channel(100);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let orderer = run_orderer(1, rx_in, tx_out, cancel_token.clone());

            let len = v.len();
            for b in v {
                // target_height set high above the blocks received
                let _ = tx_in.send((100, b)).await;
            }

            for i in 0..len {
                let (target_height, block) = rx_out.recv().await.unwrap();
                assert_eq!(target_height, 100);
                assert_eq!(block.height, (i as u64) + 1);
            }

            assert!(!orderer.is_finished());
            cancel_token.cancel();
            let _ = orderer.await;
        })
    }
}
