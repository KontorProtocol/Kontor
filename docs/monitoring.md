# Node observations and metrics

Use `/api/protocol` for exact cross-node comparisons and `/metrics` for operational
trends. Neither endpoint changes consensus, queries Bitcoin on demand, or grants
signing authority. Both remain reachable while the normal API readiness gate is
closed. Network access control belongs to the deployment.

## Comparing checkpoints

The protocol response reads protocol selection, certified progress, indexed
Bitcoin tip, and checkpoint in one deferred database transaction. Heights are
decimal strings and hashes are full hexadecimal strings:

```json
{
  "observation": {
    "bitcoin_tip": { "height": "1234", "hash": "<full block hash>" },
    "checkpoint": { "height": "1232", "hash": "<full checkpoint hash>" }
  }
}
```

This is an excerpt of the response inside the usual `result` envelope. Checkpoint
height is independent of tip height because checkpoints are sparse. Missing rows
are null. Without authentic initialized canonical history, `observation` itself
is null. A checkpoint can change when Bitcoin rollback and certified replay
replace its history.

For a configured chain, collect `ready` observations at the same
`certified.closed_height`. Compare the complete `certified`, `canonical`, and
`observation` values, including their hashes. Group by the completed position,
never by the decision or checkpoint hash being tested. Different completed
positions indicate lag or non-overlapping samples, not divergence. Missing
checkpoints do not prove equality. `recovering` and `unsupported` responses are
diagnostic only. Agreement says nothing about whether the nodes are at the
network tip.

The endpoint exposes the current snapshot, not a retained history of observations.
A comparator should record its samples and report when no overlapping ready
position is available. It must not silently compare different positions or
interpret lack of comparable evidence as healthy agreement.

## Application metrics

The response uses Prometheus text format 0.0.4 and `Cache-Control: no-store`.
Numeric heights are trends, subject to Prometheus floating-point precision.
Use protocol response strings for exact identifiers. Scrapes combine independently
sampled observations, not a transactionally consistent proof.

| Family | Type | Meaning and update boundary |
| --- | --- | --- |
| `kontor_authenticated_consensus_height` | Gauge | Latest observed committed authenticated decision, including non-batch decisions. |
| `kontor_closed_consensus_height` | Gauge | Latest observed completed closure. Planning pages do not advance it. |
| `kontor_indexed_bitcoin_height` | Gauge | Latest observed committed indexed tip, including backward movement on rollback. |
| `kontor_protocol_state{state}` | Gauge | One active state: `unknown`, `uninitialized`, `history_unavailable`, `recovering`, `unsupported`, or `ready`. |
| `kontor_state_observation_valid` | Gauge | Last durable state read succeeded. This does not mean ready or caught up. |
| `kontor_state_observation_timestamp_seconds` | Gauge | Unix time of that successful observation. Absent after invalidation. |
| `kontor_closure_active` | Gauge | An unfinished closure is observed locally. |
| `kontor_closure_elapsed_seconds` | Gauge | Monotonic elapsed time this process has observed that closure unfinished. No historical start time is inferred on restart. |
| `kontor_closure_stage{stage}` | Gauge | One active activity: `idle`, `preparing`, `reconcile`, `activate`, `rollback`, `execute`, `replay`, `finality`, or `observe`. Activity does not assert commitment. |
| `kontor_closure_stage_elapsed_seconds` | Gauge | Monotonic duration of the currently awaited work; absent while idle. |
| `kontor_last_stage_completed_timestamp_seconds` | Gauge | Unix time of a successfully settled closure step, including a planning page or closure completion. |
| `kontor_reactor_heartbeat_timestamp_seconds` | Gauge | Unix time the reactor last serviced its event loop or completed a step. A background task never refreshes it. |
| `kontor_closure_step_duration_seconds{stage,outcome}` | Histogram | Observed step duration. Outcomes: `success`, `error`, `abandoned`. Abandonment means the future was dropped, not proof of SQL rollback. |
| `kontor_rollback_total` | Counter | Successfully returned rollback steps. |
| `kontor_rollback_depth_blocks` | Histogram | Difference between pre-step tip and completed rollback target, in Bitcoin blocks. |
| `kontor_recovery_duration_seconds` | Histogram | Successfully completed startup certified recovery, after executor initialization and before consensus startup. |
| `kontor_observation_errors_total{source}` | Counter | Failed diagnostic reads or collections; sources are `state` and `engine`. |

State is loaded at startup, after decision admission, and after settled closure
steps. A diagnostic read failure invalidates its cache and logs/counts the error;
it never makes committed execution retry. A durable commit with lost
acknowledgement still follows the existing ownership fencing rules. Restart
reloads database truth. Metrics may lag a durable commit.

A healthy quiet reactor services its existing two-second fee timer. A stalled
reactor leaves heartbeat unchanged while monotonic stage and closure ages keep
growing on scrapes. No database query, RPC, or consensus control command runs in
the scrape handler.

Existing families remain: `index_current_block_height` and
`index_current_consensus_height` preserve their prior update points;
`items_indexed_total` counts execution work including replay, not unique
transactions; `index_pending_blocks` counts buffered Bitcoin blocks;
`index_deferred_decisions` is boolean presence, not a queue length.

## Bitcoin backend freshness

These gauges reuse the most recent successful follower RPC observation:

| Family | Meaning |
| --- | --- |
| `kontor_bitcoin_observation_valid` | Observation is at most 30 seconds old, matches the configured network, and headers are not below blocks. |
| `kontor_bitcoin_observation_age_seconds` | Monotonic sample age. |
| `kontor_bitcoin_backend_height` | Last observed block height, even when stale. |
| `kontor_bitcoin_headers_height` | Last observed header height, even when stale. |
| `kontor_bitcoin_initial_block_download` | Last observed IBD flag. A fresh IBD observation is valid data, not readiness. |
| `kontor_bitcoin_lag_valid` | A fresh matching backend and an indexed tip exist, with indexed height no greater than backend blocks. |
| `kontor_bitcoin_lag_blocks` | Backend blocks minus indexed height. Absent when invalid. |

Absent backend data does not create a synthetic height zero. If the index is
temporarily ahead of the backend during a reorg, lag is invalid instead of being
clamped to zero or underflowing. Readiness still uses its existing additional
IBD, header-distance, reactor and shutdown checks.

## Managed consensus metrics

The managed engine exposes a registry-only handle across its standard-library
facade. It retains no engine owner, signing authority, or control thread. A
node-local diagnostics worker collects approximately every five seconds. There
can be only one collection in flight, including across engine replacement and
cancelled waiters. Collection does not use the engine's fatal-operation wrapper.

Output is capped at 1 MiB during encoding. Synchronous registry export shares
short-lived locks with metric updates; the size cap is not a deadline. A blocked
export retains the one worker slot instead of spawning timed-out replacements.
Its detached thread does not hold Tokio runtime shutdown open. Engine stop
invalidates samples immediately; old-generation results cannot populate the new
cache. Errors and caught diagnostic panics affect metric availability, not the
engine control protocol. Counters and histograms are copied, never re-added, and
reset naturally when the engine generation changes.

`kontor_engine_metrics_available` reports whether a current-generation sample
exists. `kontor_engine_metrics_age_seconds` measures its age. Alert on sample age
as well as availability: an old successful sample can remain while collection
is stalled. Unsupported/legacy runtimes report unavailable, not zero peers.

Only these pinned families are exposed (counter names below include the
Prometheus `_total` suffix):

* `malachitebft_core_consensus_`: gauges `height`, `round`, `connected_peers`,
  `queue_heights`, `queue_size`, `node_safety_failure`; histograms
  `consensus_time`, `time_per_block`, `time_per_step`, `consensus_round`; counters
  `rebroadcast_timeouts_total`, `dropped_future_round_votes_total`,
  `dropped_future_round_proposals_total`, `dropped_capped_proposals_total`,
  `dropped_capped_proposed_values_total`, `dropped_buffered_messages_total`.
* `malachitebft_sync_`: gauges `sync_queue_heights`, `sync_queue_size`;
  histograms `value_client_latency`, `value_server_latency`; counters
  `value_requests_sent_total`, `value_requests_received_total`,
  `value_responses_sent_total`, `value_responses_received_total`,
  `value_request_timeouts_total`, `value_local_transient_errors_total`.

The round gauge and finalization-round histogram measure different things.
`node_safety_failure` covers the engine's WAL safety-hang indication. No guessed
WAL metric names are added. Per-peer libp2p and sync-scoring families are excluded.
Selected families permit only deployment moniker, fixed step/reason labels and
histogram buckets. Invalid selected families invalidate the whole engine sample.
OpenMetrics counter metadata is normalized to Prometheus names; its EOF marker
is removed. Family and series duplicates are rejected.

Example operational queries (choose alert durations and thresholds in infra):

```promql
time() - kontor_reactor_heartbeat_timestamp_seconds
kontor_authenticated_consensus_height - kontor_closed_consensus_height
kontor_bitcoin_lag_blocks and on(instance) (kontor_bitcoin_lag_valid == 1)
rate(kontor_observation_errors_total[5m])
```

Do not use these floating-point metrics to compare checkpoint hashes. The
infrastructure comparator and notification routing are separate deployment work.
