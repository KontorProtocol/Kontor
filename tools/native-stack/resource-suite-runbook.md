# S2 six-cell resource run

This run uses one clean source commit for all six final cells. Each cell builds
its own dev or release test executable, captures the host guard control, and
runs all 16 case groups. The final comparison revalidates the archived
executable, Cargo build record, guard control, raw process logs, Store closure,
receipts, fuel, rollback, target, and group semantic signatures. The result
remains `qualification_status: missing` until production memory profiles and
phase review are complete.

The pending-host group also runs the frozen `suspended_64` profile in each
cell's production target child. Its warm baseline is measured after publishing
the real distinct-contract paid chain. One paid reactor root retains 64 nested
invocation Stores while its leaf host import is pending. The child measures
mapped, resident, private, and node-accounted memory at that point, then resumes
the root and checks three full semantic results, 64 Store lifecycles per call,
rollback, and after-cleanup memory. The source-only plan fixes zero deliberate
guest occupancy, warm cache state, and separate private-growth, mapping,
resident, and node-accounted allowances. This six-cell capacity evidence does
not replace the Linux ARM64 reference-host overlap and service measurements.

## Select and freeze the nine Pulley depths

Start from a clean Linux ARM64 development checkout whose boundary manifest
says `pending_discovery`. Use a fresh output directory outside the checkout:

```sh
S2_BASE=/tmp/kontor-s2-discovery
S2_SOURCE_SHA=$(git rev-parse HEAD)
python3 tools/native-stack/build_resource_test.py \
  --profile dev --output-dir "$S2_BASE/build"
python3 tools/native-stack/capture_resource_control.py \
  --cargo-artifacts "$S2_BASE/build/cargo-artifacts.jsonl" \
  --metadata "$S2_BASE/build/cargo-metadata.json" \
  --build-attestation "$S2_BASE/build/resource-build-attestation.json" \
  --source-sha "$S2_SOURCE_SHA" \
  --evidence-dir "$S2_BASE/control" > "$S2_BASE/control-result.json"
S2_CONTROL_SHA=$(jq -er '.sha256' "$S2_BASE/control-result.json")
python3 tools/native-stack/capture_resource_boundary.py \
  --phase discovery --cell Linux-ARM64/dev \
  --control-capture "$S2_BASE/control/resource-control-capture.json" \
  --control-sha256 "$S2_CONTROL_SHA" \
  --evidence-dir "$S2_BASE/discovery"
S2_DISCOVERY_SHA=$(sha256sum "$S2_BASE/discovery/resource-boundary-capture.json" | awk '{print $1}')
jq --arg sha "$S2_DISCOVERY_SHA" \
  '{discovery_capture_sha256: $sha, cases: .discovered_depths}' \
  "$S2_BASE/discovery/resource-boundary-capture.json" \
  > "$S2_BASE/candidate-depths.json"
jq -e '(.cases | length) == 9 and ([.cases[] | .first_failure == (.last_success + 1)] | all)' \
  "$S2_BASE/candidate-depths.json"
```

The coordinator reviews the nine production observed last-success and
first-failure pairs against the full raw logs and three ordered repeats. A
pilot replay can check the same depths before the final freeze. After that
review, copy the complete candidate record into
`resource-boundary-depths-v1.json`, regenerate the v1, v2, boundary, and suite
registry manifests in that order, and commit the frozen source. The final Git
diff from reviewed discovery must contain exactly the depth record, boundary
manifest, and generated suite registry. The suite registry may change only its
boundary manifest digest and boundary discovery status. The final
boundary capture requires the reviewed discovery directory and its exact
capture SHA-256. Its validator reads the older source and manifest from Git,
so CI checkout needs full history.

## Auxiliary Store counts

The current v2 manifest already freezes 90 observed trial counts. These counts
are keyed by case, role, worker configuration, and repeat. The selection rule
for a pilot source is to validate a Linux ARM64 development v2 capture with
`--pilot`, then extract each observed trial's `role_counts[index].created`
for `pre_observation`, `post_observation`, `rollback_observation`, and
`target_native_auxiliary`. Compare all 90 entries with the callsite citations
in `resource_manifest_v2.py` before replacing a `pilot_pending` table with
frozen counts. The final source must set `auxiliary_count_status: frozen` and
reject any missing key or changed measured count. Current source has already
completed that freeze; it must not be silently recalculated from a later
capture. The source table still needs its reviewed pilot archive retained as
phase evidence.

At a `pilot_pending` source revision, build and capture a guard control at
that same revision as above, then use the exact pinned phase10 bundle:

```sh
S2_HISTORICAL=/path/to/resource-chain-capture.json
python3 tools/native-stack/capture_resource_chain_v2.py \
  --cell Linux-ARM64/dev \
  --control-capture "$S2_BASE/control/resource-control-capture.json" \
  --control-sha256 "$S2_CONTROL_SHA" \
  --historical-bundle "$S2_HISTORICAL" \
  --evidence-dir "$S2_BASE/chain-pilot" --pilot
jq '.runs | [to_entries[] | .value as $run |
    select($run.process_role | endswith("observed")) |
    range(0; 3) as $index |
    {key: "\($run.case_id)/\($run.process_role)/\($run.configuration)/\($index)",
     value: ($run.role_counts[$index].created |
       {pre_observation, post_observation, rollback_observation,
        target_native_auxiliary})}] | from_entries' \
  "$S2_BASE/chain-pilot/resource-chain-v2-capture.json" \
  > "$S2_BASE/candidate-auxiliary-counts.json"
jq -e 'keys | length == 90' "$S2_BASE/candidate-auxiliary-counts.json"
```

## Final six-cell capture and comparison

The existing `native-stack.yml` workflow dispatches the S2 reusable workflow
on a candidate branch. Its `discovery` stage runs on Linux ARM64 dev,
an independent `guard` stage for macOS ARM64 dev and release, and a `final`
stage with Linux X64, Linux ARM64, and macOS ARM64 in dev and release profiles.
The discovery stage uploads a candidate archive. The guard stage archives each
macOS guard fault transcript, Cargo closure, and test executable before the
boundary depths are frozen. The final stage accepts the discovery run ID only
after its capture SHA-256 is frozen in the source. The historical phase10 chain
capture is included as a deterministic gzip fixture under `fixtures/`. It came
from Linux ARM64 dev source `b760345fab4f36ca85f35e1ff53e42b156f6e66a`.
Its compressed bytes are pinned in the v2 manifest. The final workflow expands
it and verifies the 14,018,873 byte raw capture against SHA-256
`9d325af8461ca482104886c8add17c6a790405411c0454ce90b1b840bb9f0534`
before running any chain case. This fixture is historical comparison evidence,
not a current-source qualification result.

```sh
S2_REF=$(git branch --show-current)
gh workflow run native-stack.yml --ref "$S2_REF" -f stage=discovery
gh workflow run native-stack.yml --ref "$S2_REF" -f stage=guard
# Review and freeze all nine depths in a new source commit.
gh workflow run native-stack.yml --ref "$S2_REF" -f stage=final \
  -f reviewed_discovery_run_id="$DISCOVERY_RUN_ID"
```

Push each committed candidate revision before dispatch. Record and inspect the
run's `headSha` so discovery, guard, and final archives are attributed to their
intended source commits. The reviewed discovery archive must remain available
until the final run finishes.

The final workflow captures macOS guard faults on the macOS runners. It then
downloads all six archives, checks one common source revision and archived
binary per cell, replays every group validator against its archived logs, and
compares semantic signatures across cells. A missing artifact, host/profile
mismatch, changed binary, source drift, different receipt/fuel/rollback result,
or changed boundary outcome fails the run. Final acceptance still requires
production-only memory profiles, a reviewed workload plan, and phase review.
