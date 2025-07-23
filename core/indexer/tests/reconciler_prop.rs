use anyhow::anyhow;
use proptest::test_runner::FileFailurePersistence;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use proptest::prelude::*;

use indexer::{
    bitcoin_follower::{
        events::{Event, ZmqEvent},
        reconciler,
    },
    block::Block,
    test_utils::{MockBlockchain, MockTransaction, gen_random_blocks, new_random_blockchain},
};

#[derive(Debug)]
enum Segment {
    RpcSeries(usize),
    AppendBlocks(usize),
    ZmqConnection(bool),
    ZmqSeries((usize, usize)), // (series length, rewind/overlap at start)
}

fn gen_segment() -> impl Strategy<Value = Segment> {
    prop_oneof![
        1 => (1..4usize).prop_map(Segment::RpcSeries),
        2 => (1..4usize, 0..2usize).prop_map(Segment::ZmqSeries),
        1 => (1..2usize).prop_map(Segment::AppendBlocks),
        1 => prop::bool::ANY.prop_map(Segment::ZmqConnection),
    ]
}

fn gen_segment_vec() -> impl Strategy<Value = Vec<Segment>> {
    prop::collection::vec(gen_segment(), 1..10)
}

#[derive(Debug)]
enum Step {
    RpcEvent((u64, Block<MockTransaction>)),
    AppendBlocks(Vec<Block<MockTransaction>>),
    ZmqEvent(ZmqEvent<MockTransaction>),
}

fn create_steps(segs: Vec<Segment>) -> (Vec<Step>, MockBlockchain) {
    let initial_blocks = new_random_blockchain(5);
    let mut blocks = initial_blocks.clone();
    let mut stream = vec![];
    let mut height = 0;
    let mut connected = false;
    let mut caughtup = false;
    for seg in segs.iter() {
        match seg {
            Segment::RpcSeries(n) => {
                for _i in 0..*n {
                    if height < blocks.len() {
                        stream.push(Step::RpcEvent((
                            blocks.len() as u64,
                            blocks[height].clone(),
                        )));
                        height += 1;
                    }
                    if height == blocks.len() {
                        caughtup = true;
                    }
                }
            }
            Segment::ZmqSeries((n, rewind)) => {
                let mut h = height.saturating_sub(*rewind);
                for _i in 0..*n {
                    if h < blocks.len() {
                        stream.push(Step::ZmqEvent(ZmqEvent::BlockConnected(blocks[h].clone())));
                        h += 1;
                    }
                }
                if connected && caughtup && h > height {
                    // unless we're connected and caught-up we expect
                    // the blocks to be discarded so we don't tick up
                    // the model height.
                    height = h;
                }
            }
            Segment::AppendBlocks(n) => {
                let cnt = blocks.len();
                let more_blocks =
                    gen_random_blocks(cnt as u64, (cnt + n) as u64, Some(blocks[cnt - 1].hash));
                blocks.extend(more_blocks.iter().cloned());
                stream.push(Step::AppendBlocks(more_blocks));
            }
            Segment::ZmqConnection(conn) => {
                if *conn {
                    stream.push(Step::ZmqEvent(ZmqEvent::Connected));
                } else {
                    stream.push(Step::ZmqEvent(ZmqEvent::Disconnected(anyhow!(
                        "mock error"
                    ))));
                }
                connected = *conn;
            }
        }
    }
    (stream, MockBlockchain::new(initial_blocks))
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(
            FileFailurePersistence::WithSource("regressions"),
        )),
        .. ProptestConfig::default()
    })]

    /**
    TEST DESIGN

    The test generates a valid blockchain which will be exposed to the Reconciler as
    series of sequential blocks either arriving via RPC or ZMQ, with the latter potentially
    rewinding / repeating some blocks already received by RPC. It will intersperse events
    changing the ZMQ connection status, or growing the underlying blockchain.

    MockBlockchain implements BlockFetcher and BlockchainInfo info, and the info shared
    by the latter will be kept in sync with the blockchain blocks are sent from.


    TEST DATA AND MODEL NOTES
     - We avoid producing gaps or overlaps in blocks collected by RPC; if we did those
       would get passed through and lead to gaps or repetition in emitted `BlockInsert`
       events.
     - There's no feedback from the Reconciler to the stream of events. Specifically
       the `start` signal on the BlockFetcher is ignored, meaning the height of the
       blocks received via RPC may not correspond to those requested if the BlockFetcher
       is re-started.
    */
    #[test]
    fn test_reconciler(vec in gen_segment_vec()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cancel_token = CancellationToken::new();
            let (_rpc_tx, rpc_rx) = mpsc::channel(1);
            let (_zmq_tx, zmq_rx) = mpsc::unbounded_channel::<ZmqEvent<MockTransaction>>();

            let (steps, mut mock) = create_steps(vec);

            let mut rec = reconciler::Reconciler::new(
                cancel_token.clone(),
                mock.clone(),
                mock.clone(),
                rpc_rx,
                zmq_rx,
            );

            let mut events = vec![];
            for step in steps {
                match step {
                    Step::RpcEvent((target, block)) => {
                        let mut res = rec.handle_rpc_event((target, block)).await.unwrap();
                        events.append(&mut res);
                    },
                    Step::ZmqEvent(e) => {
                        let mut res = rec.handle_zmq_event(e).await.unwrap();
                        events.append(&mut res);
                    },
                    Step::AppendBlocks(blocks) => {
                        mock.append_blocks(blocks);
                    },
                }
            }

            // verify that blocks are emitted in sequence and match the mock blockchain
            let mock_blocks = mock.blocks();
            let mut expected_height = 1;
            for event in events {
                if let Event::BlockInsert((_target_height, block)) = event {
                    assert_eq!(block.height, expected_height);
                    assert_eq!(block.hash, mock_blocks[block.height as usize - 1].hash);
                    expected_height = block.height + 1;
                }
            }
        })
    }
}
