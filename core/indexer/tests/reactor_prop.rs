use anyhow::Result;
use indexer_types::Block;
use once_cell::sync::Lazy;
use proptest::test_runner::FileFailurePersistence;
use tempfile::TempDir;
use tokio::time::{Duration, timeout};

use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

use bitcoin::BlockHash;

use proptest::prelude::*;

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event},
    },
    database::{self, queries},
    reactor,
    test_utils::{await_block_at_height, gen_random_block, new_mock_block_hash, new_test_db},
};

#[derive(Debug)]
enum Segment {
    Series(usize),
    ImplicitRollback(usize), // the next block will have mismatching height/hash
    ExplicitRollback(usize), // send the BlockRemove event
}

#[derive(Debug)]
struct StartMsg {
    // StartMessage without the event channel
    start_height: u64,
    last_hash: Option<BlockHash>,
}

#[derive(Debug)]
struct Step {
    event: Event,
    expect_start: Option<StartMsg>,
}

struct Database {
    reader: database::Reader,
    writer: database::Writer,
    _temp_dir: (TempDir, String),
}

struct DatabaseFactory {
    database: Arc<Mutex<Option<Database>>>,
}

impl DatabaseFactory {
    pub fn new() -> Self {
        Self {
            database: Mutex::new(None).into(),
        }
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn get_database(&mut self) -> Arc<Mutex<Option<Database>>> {
        let mut db = self.database.lock().unwrap();
        if db.is_none() {
            *db = Some(new_db_wrapper().await);
        }
        self.database.clone()
    }
}

// setup shared database used across all test runs; the mutex will force tests to run
// in sequence, which is still faster than creating a new database for each run.
static SHARED_DATABASE: Lazy<Arc<Mutex<DatabaseFactory>>> =
    Lazy::new(|| Mutex::new(DatabaseFactory::new()).into());

async fn new_db_wrapper() -> Database {
    let (reader, writer, _temp_dir) = new_db().await.unwrap();
    Database {
        reader,
        writer,
        _temp_dir,
    }
}

async fn new_db() -> Result<(database::Reader, database::Writer, (TempDir, String))> {
    // unable to parse Config object with clap due to conflict with proptest flags.
    let (reader, writer, _temp_dir) = new_test_db().await?;
    Ok((reader, writer, _temp_dir))
}

fn gen_segment() -> impl Strategy<Value = Segment> {
    prop_oneof![
        2 => (1..8usize).prop_map(Segment::Series),
        1 => (1..4usize).prop_map(Segment::ImplicitRollback),
        1 => (1..4usize).prop_map(Segment::ExplicitRollback),
    ]
}

fn gen_segment_vec() -> impl Strategy<Value = Vec<Segment>> {
    prop::collection::vec(gen_segment(), 1..6)
}

fn create_steps(segs: Vec<Segment>) -> (Vec<Step>, Vec<Block>) {
    let mut stream = vec![];
    let mut model = vec![];
    let mut height = 0;
    let mut prev_hash = None;
    let mut implicit_rollback = false;
    for seg in segs.iter() {
        match seg {
            Segment::Series(n) => {
                for _i in 0..*n {
                    height += 1;
                    let b = gen_random_block(height, prev_hash);

                    if implicit_rollback {
                        // model updates on the first block after implicit rollback
                        model.truncate(height as usize - 1);

                        // BlockInsert will have a mismatching hash and
                        // will trigger a rollback and a StartMessage
                        stream.push(Step {
                            event: Event::BlockInsert((height, b.clone())),
                            expect_start: Some(StartMsg {
                                start_height: height,
                                last_hash: prev_hash,
                            }),
                        });
                        implicit_rollback = false;

                        // After the StartMessage was sent the Reactor will
                        // be waiting for the requested block to be re-sent.
                    }
                    stream.push(Step {
                        event: Event::BlockInsert((height, b.clone())),
                        expect_start: None,
                    });

                    prev_hash = Some(b.hash);
                    model.push(b);
                }
            }
            Segment::ImplicitRollback(n) => {
                if height > 0 {
                    // rollback has no effect if height is already 0
                    let depth = *n as u64;
                    if depth < height {
                        height -= depth;
                        let i = height as usize;
                        prev_hash = Some(model[i - 1].hash);
                    } else {
                        height = 0;
                        prev_hash = None;
                    }
                    implicit_rollback = true; // update the model on the next block
                }
            }
            Segment::ExplicitRollback(n) => {
                if height > 0 && !implicit_rollback {
                    // ignore "duplicate" rollback (it's not really duplicate as the depth
                    // may differ, but for simplicity we'll ignore that.
                    let depth = *n as u64;
                    if depth < height {
                        height -= depth;

                        let i = height as usize;
                        let hash = model[i].hash;

                        model.truncate(i);
                        prev_hash = Some(model[i - 1].hash);
                        stream.push(Step {
                            event: Event::BlockRemove(BlockId::Hash(hash)),
                            expect_start: Some(StartMsg {
                                start_height: height + 1,
                                last_hash: prev_hash,
                            }),
                        });
                    } else {
                        // no-op; rollbacks to a non-existant block will be ignored
                    }
                } else {
                    // no-op; rollbacks to a non-existant block will be ignored
                }
            }
        }
    }
    (stream, model)
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(
            FileFailurePersistence::WithSource("regressions"),
        )),
        cases: 100,
        timeout: 10000,
        .. ProptestConfig::default()
    })]

    /**
    TEST DESIGN

    The property tests creates a vector of Segments, each being either a unbroken
    Series of sequential blocks, or some kind of rollback.

    The Segments are then converted into a vector of Steps and a model.
    Each Step consists of an Event sent to the Reactor with an optional expectation of a
    StartMessage.

    The model is the expected state of the database at the end of the test.


    TEST DATA AND MODEL NOTES
     - In the event of an ImplicitRollback (triggered by unexpected height pr prev_hash mismatch, as
       opposed to a BlockRemove message) the Reactor will throw away the triggering block and
       re-request it with a StartMessage. We thus have to send it twice in order for the Reactor to
       persist it.
     - An ImplicitRollback at the end of the test won't take effect since the Reactor will only
       know about it once the next block arrives.
     - An ExplicitRollback past the initial block (to a non-existant block/hash) will be
       ignored.

    */
    #[test]
    fn test_reactor_rollbacks(vec in gen_segment_vec()) {
        let rt = tokio::runtime::Runtime::new().unwrap();

        // we need to allow the lock for the shared database to be held throughout a
        // test run to force sequential execution of the test runs.
        #[allow(clippy::await_holding_lock)]
        rt.block_on(async {
            let db_mutex = (*SHARED_DATABASE).lock().unwrap().get_database().await;
            let mut db_binding = db_mutex.lock().unwrap();
            let db = db_binding.as_mut().unwrap();

            // wipe blocks from earlier runs
            let conn = &db.writer.connection();
            queries::rollback_to_height(conn, 0).await.unwrap();

            let cancel_token = CancellationToken::new();
            let (ctrl, mut ctrl_rx) = CtrlChannel::create();

            let handle = reactor::run(
                1,
                cancel_token.clone(),
                db.reader.clone(),
                db.writer.clone(),
                ctrl,
                None,
                None,
                None,
            );

            let start = ctrl_rx.recv().await.unwrap();
            assert_eq!(start.start_height, 1);
            let mut event_tx = start.event_tx;

            let (steps, model) = create_steps(vec);

            // inject events
            for step in steps {
                event_tx.send(step.event).await.unwrap();

                if let Some(expect) = step.expect_start {
                    let start = timeout(
                        Duration::from_millis(2000),
                        ctrl_rx.recv(),
                        ).await.unwrap().unwrap();
                    assert_eq!(start.start_height, expect.start_height);
                    // model does not take into account native block
                    if start.last_hash != Some(new_mock_block_hash(0)) {
                        assert_eq!(start.last_hash, expect.last_hash);
                    }

                    event_tx = start.event_tx;
                }
            }

            // compare against model
            let conn = &*db.reader.connection().await.unwrap();
            for expected_block in model.clone() {
                let block = await_block_at_height(conn, expected_block.height as i64).await;
                assert_eq!(block.hash, expected_block.hash);
            }

            match queries::select_block_latest(conn).await.unwrap() {
                Some(row) => assert_eq!(row.height as usize, model.len()),
                None => assert_eq!(model.len(), 0),
            }

            assert!(!handle.is_finished());
            cancel_token.cancel();
            let _ = handle.await;
        })
    }
}
