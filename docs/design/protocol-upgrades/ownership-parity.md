# Ownership comparison against the S2 baseline

The OWNERSHIP-1 comparison passed on 31 October 2026 against the actual merged
S2 implementation, `a94587744cd7bce30d6662fb4b32a7c65ce67912` (PR #613).
The isolated oracle, `213acdecdac67b5cf8587910d9dacbb8f7fd9eb1`, differs from
that merge only by the two shared test files. The ownership candidate was
`ca86da1668ca7fe8898493d9093326a78144574b`.

All eleven observation stages matched exactly, including the full typed table
multisets. Simulation preserved state, and reconfirmation did not execute or
charge the earlier batch transaction again. The baseline test took 62.99 seconds;
the ownership comparison took 28.55 seconds. These durations describe correctness
checks, not a performance comparison.

The retained local evidence is
`/home/wilfred/Documents/Kontor/.build-cache/ownership-final-parity-20261031/`.
It includes the runner, build commands and logs, executable checksums, checksummed
seed and signed transaction, both observation reports and `comparison.json`.
The baseline report SHA-256 is
`a869b5af2850ca04d93bd339374307eb5b89bbd5a63b9fde39b20ef4a9f35704`;
the ownership report SHA-256 is
`9871dd534c29c9f068016f34c2b6bc2daea96f82aa3c4e9b747edc1675a45452`.
Their source fields differ as expected; their complete state observations agree.

This is non-cancelled cross-revision evidence. Cancellation, resource cleanup,
affected platform qualification and consolidated phase reviews remain separate.

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
