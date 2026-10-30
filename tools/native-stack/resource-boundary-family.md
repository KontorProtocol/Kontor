# Pulley boundary family, source review gate

This slice covers the eight `pulley_{plain,wide}_{paid,view,system,core}`
cases and the dependent `deepest_frame_host_call` case. It does not qualify
the other twenty cases, the six cells, macOS guard, memory profiles, or the
full S2 claim. The v1 and v2 evidence formats and archived chain capture remain
separate.

## Source and process matrix

The published `stack-probe` fixture uses one non-tail plain recursion helper
for the paid, view, Core, and leaf-host paths. Its leaf export calls the real
`kontor:built-in/testing.host-error` import at depth zero. The test linker
shadows that import with a pending async host function, as the existing
distinct-contract chain test does. The worker test requires the guest task to
remain unfinished while a second Tokio task progresses, then releases the
host import and checks the resumed result. The leaf export and its frame shape
must be frozen before depth discovery.

Development discovery runs one production-capacity observed child for each of
the eight boundary cases and the leaf host call on Linux ARM64 development,
nine children total. The leaf call has its own adjacent stack boundary. A
typed stack overflow is a failed calibration attempt. The transcript records
whether it occurred before host import or after the pending import was
released. Each successful leaf attempt must enter the host import, suspend,
allow another Tokio task to progress, and resume after release.
Each child starts at zero, doubles from 1024 up to 32768, then bisects the
first typed stack-overflow interval. It emits every calibration attempt,
including worker phases, full state reset, and Store teardown. The validator
reconstructs the exact search from the raw transcript. Discovery is not a
candidate binding. After independent source and evidence review, copy its
nine adjacent depth pairs and capture SHA-256 into
`resource-boundary-depths-v1.json`, rebuild from that committed source, and
never rediscover in final or later cells.

For each of the eight cases and both stack configurations, final capture runs
one `target_observed` and one `probe_off_control` child. Each child replays
the frozen last success and first failure three times in the fixed order
`success, failure, failure, success, success, failure`. These 32 fresh
children supply 192 target attempts per cell. The leaf case adds one observed
and one probe-off child per configuration. Each leaf child repeats both a
successful suspended call at its own last-success depth and a typed failure
at the adjacent first-failure depth. The failure phase must agree across
repeats, configurations, and process roles. Final capture is 36 children
and 208 target attempts per cell. The observed child is independent
of discovery and supplies the fresh-process control; a third observed child
is not part of this gate.

Each child has its own process identity, complete raw log, terminal marker,
allowlisted environment, binary and source identity, two measured Tokio
workers, blocking-pool and caller stack records, phase and canonical
conversion trace, and per-attempt timing. The canonical input conversion and
successful output conversion must occur inside that attempt's operation
interval. Each observed attempt requires its
own Store table to die before its lease releases. Probe-off attempts cannot
claim teardown evidence. Full SQLite rows plus logical schema, canonical
balance transitions, including debit, burn, and supply conservation, fuel,
receipts, typed traps, and rollback must match
across repeats, probe states, and reduced/production configurations. Frozen
depths and semantic outputs must match across nodes in the eventual six-cell
gate. No local hardware or timing values enter protocol semantic equality.
Raw balance strings and their source digest remain bound to each child log.
The boundary validator accepts only bounded decimal spellings supported by
the pinned formatter, converts them exactly to fixed form for semantic
comparison, and checks the 18-place, 256-bit WIT Decimal domain without
floating-point arithmetic. Existing v1 and v2 accounting rules are unchanged.

The resource boundary manifest intentionally begins with null depths and
`pending_discovery`. The final capture driver fails closed until all nine
depths and the reviewed discovery hash are pinned. Existing source and guard
capture rules remain mandatory. Discovery supplies candidate depths, not evidence
that a later runtime has the same boundary. Unchanged fixture and case definitions
permit reuse of those inputs; every final binary must independently pass both
endpoints in every required cell. A changed fixture or case definition requires
new discovery. A failed final endpoint requires investigation and, when necessary,
new common candidate depths, never separate accepted depths per cell.
The v1 case contract records `adjacent_leaf_boundary: true` instead of
borrowing `pulley_plain_paid` depth. At the reviewed `5bdf08fe` source baseline,
this amended the generated v1 manifest hash to
`4434676b208b9d9059dbc77a8a5976367ea1c647cc36c43bd0cbf1fba3a56fba`
while retaining all 41 case IDs and the approved resource amendment bytes.
Later source commits regenerate the manifest hash from their exact inputs.
The historical a355 chain archive remains unchanged. The v1 validator
requires the leaf observation to equal the reviewed frozen leaf depth.

Final capture takes the complete archived nine-case discovery and its pinned
SHA-256. It replays validation of each raw discovery transcript against the
source commit's manifest, checks the archived selected binary bytes against
the historical control and Cargo artifact, and checks each adjacent pair
against the frozen values,
and verifies the discovery commit precedes the final commit. Fixture source, WIT
and binary identities, case IDs, shapes, modes, repetitions and leaf requirements
must remain unchanged. Historical dependency evidence is checked against its
historical manifest. Current manifests and the suite registry must regenerate
exactly, but need not have the historical runtime or harness hashes.
The final control still requires the exact clean final source commit and its
own Cargo binary. Fresh captures in all six cells must satisfy all current outcome,
fuel, state, receipt, cleanup and leaf-failure-phase assertions. Reusing candidate
depths does not reuse historical execution as final qualification or waive source
review of implementation changes.

## Bounded pilot after source review

The development pilot runs plain-paid, wide-paid, and leaf discovery in three
production children, then their frozen-in-pilot depths in twelve independent
replay children, two configurations by two roles by three cases. The replay
driver takes the archived pilot discovery capture and its exact SHA-256,
copies the complete archive, and verifies source, binary, manifest, and
depth parity. The pilot is diagnostic and never supplies final binding.

Each discovery child has at most 21 target attempts. The eight boundary replay
children have six each, while the four leaf replay children have four each.
The pilot has at most 127 target attempts in fifteen children. Full nine-case
discovery has at most 189. Final capture has 208 per cell, or 1248
across six cells, plus fixture setup and observation queries. The existing
600-second per-child timeout is a failure bound, not a runtime estimate.
Pilot outputs record whole-child wall time, per-attempt time, and matched
compiler and blocking-decode events. Use measured startup, compilation, and
per-attempt costs to project six-cell runtime with an explicit margin before
scheduling full capture. Fail immediately on an impossible cost or a failed
child.

After an exact clean source commit, use the repository's pinned test-contract
build and Cargo artifact capture, then run the guard/source control for the
same binary. The capture commands are:

```sh
python3 tools/native-stack/capture_resource_boundary.py \
  --phase pilot_discovery \
  --control-capture CONTROL/resource-control-capture.json \
  --control-sha256 CONTROL_SHA256 \
  --evidence-dir PILOT_DISCOVERY
python3 tools/native-stack/capture_resource_boundary.py \
  --phase pilot_replay \
  --pilot-discovery-capture PILOT_DISCOVERY/resource-boundary-capture.json \
  --pilot-discovery-sha256 PILOT_DISCOVERY_SHA256 \
  --control-capture CONTROL/resource-control-capture.json \
  --control-sha256 CONTROL_SHA256 \
  --evidence-dir PILOT_REPLAY
python3 tools/native-stack/capture_resource_boundary.py \
  --phase final --cell Linux-ARM64/dev \
  --reviewed-discovery-capture DISCOVERY/resource-boundary-capture.json \
  --reviewed-discovery-sha256 REVIEWED_DISCOVERY_SHA256 \
  --control-capture FINAL_CONTROL/resource-control-capture.json \
  --control-sha256 FINAL_CONTROL_SHA256 \
  --evidence-dir FINAL_EVIDENCE
```

No pilot or final capture runs before the source, schema, and validator review
is complete.
