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
the eight boundary cases on Linux ARM64 development, eight children total.
Each child starts at zero, doubles from 1024 up to 32768, then bisects the
first typed stack-overflow interval. It emits every calibration attempt,
including worker phases, full state reset, and Store teardown. The validator
reconstructs the exact search from the raw transcript. Discovery is not a
candidate binding. After independent source and evidence review, copy its
eight adjacent depth pairs and capture SHA-256 into
`resource-boundary-depths-v1.json`, rebuild from that committed source, and
never rediscover in final or later cells.

For each of the eight cases and both stack configurations, final capture runs
one `target_observed` and one `probe_off_control` child. Each child replays
the frozen last success and first failure three times in the fixed order
`success, failure, failure, success, success, failure`. These 32 fresh
children supply 192 target attempts per cell. The leaf case adds one observed
and one probe-off child per configuration, two repeated suspended host calls
per child at the frozen plain-paid last-success depth. Final capture is 36
children and 200 target attempts per cell. The observed child is independent
of discovery and supplies the fresh-process control; a third observed child
is not part of this gate.

Each child has its own process identity, complete raw log, terminal marker,
allowlisted environment, binary and source identity, two measured Tokio
workers, blocking-pool and caller stack records, phase and canonical
conversion trace, and per-attempt timing. Each observed attempt requires its
own Store table to die before its lease releases. Probe-off attempts cannot
claim teardown evidence. Full SQLite rows plus logical schema, canonical
balance transitions, fuel, receipts, typed traps, and rollback must match
across repeats, probe states, and reduced/production configurations. Frozen
depths and semantic outputs must match across nodes in the eventual six-cell
gate. No local hardware or timing values enter protocol semantic equality.

The resource boundary manifest intentionally begins with null depths and
`pending_discovery`. The final capture driver fails closed until all eight
depths and the reviewed discovery hash are pinned. Existing source and guard
capture rules remain mandatory. A fixture or runtime frame-path edit after
discovery requires new reviewed discovery and a fresh final binary.

## Bounded pilot after source review

The development pilot runs plain-paid and wide-paid discovery in two
production children, then their frozen-in-pilot depths in eight independent
replay children, two configurations by two roles by two shapes. The replay
driver takes the archived pilot discovery capture and its exact SHA-256,
copies the complete archive, and verifies source, binary, manifest, and
depth parity. The pilot is diagnostic and never supplies final binding.

Each discovery child has at most 21 target attempts. Each replay child has
six, so the pilot has at most 90 target attempts in ten children. The full
eight-case discovery has at most 168. Final capture has 200 per cell, or 1200
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
```

No pilot or final capture runs before the source, schema, and validator review
is complete.
