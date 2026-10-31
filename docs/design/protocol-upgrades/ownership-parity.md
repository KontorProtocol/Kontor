# Ownership comparison against the S2 baseline

This test is prepared for the OWNERSHIP-1 acceptance check. It has not yet been
run against the final qualified and merged S2 source.

The selected-executor preparation branch adapts this fixture's call sites to
explicit executor selection and raw-input admission. Those adaptations belong
to the later K2a comparison. For OWNERSHIP-1 acceptance, use the unchanged fixture
on the S2 baseline and the ownership branch, before integrating K2a. Do not use
the adapted selected-executor fixture as the ownership baseline.

Reuse `confirmation_position_tests::parity::retained_executor_matches_baseline`
from `c7554ca8`, with the fixture and comparison source unchanged. Apply the same
test-only files to the final S2 baseline and the ownership candidate. The baseline
must not include the ownership implementation. Record both source revisions and
the test executable hashes with the command logs.

Run the baseline with `KONTOR_EXECUTOR_PARITY_MODE=record` and an absolute,
previously nonexistent `KONTOR_EXECUTOR_PARITY_DIR`. It creates a database seed,
signed transaction, checksummed input record and baseline observations. Run the
ownership candidate with the same directory, `KONTOR_EXECUTOR_PARITY_MODE=compare`
and a new absolute `KONTOR_EXECUTOR_PARITY_OUTPUT` path. In both cases explicitly
select the ignored comparison test through the repository's locked Cargo test
command, using the pinned compiler and the single local build/runtime slot.

The two runs reopen copies of the same seed, including native provenance. They
compare all eleven observation stages, covering recognition, simulation, direct
block execution, batch execution, confirmation, rollback and reconfirmation.
Persistent-state comparison includes every table, typed values and duplicate
rows. Simulation must leave the state unchanged; reconfirmation must not execute
or charge the transaction again. Existing independent ownership tests cover
cancellation, cleanup and commit races, which this non-cancelled fixture does not.

Do not reuse the earlier K2a baseline as the S2 oracle or compare two owned paths
and call that cross-revision acceptance. Passing this comparison does not replace
the affected cross-platform qualification or consolidated phase reviews.
