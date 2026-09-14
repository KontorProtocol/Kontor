# Memory initialization CoW costs

Measured 2026-09-14 on fresh main `467bf45e7bcc446402ec3a063c336a8d60e15eff`,
with Wasmtime 48.0.2 and the checked-in native contract binaries. The ignored
`contract_memory_init_cow_costs` benchmark changes CoW only in its own fixtures.
The subsequent runtime change disables CoW for all nodes and adds a fixed
initialization-fuel boundary test to the existing Linux/macOS CI matrix.

## Result

Disabling CoW did not meaningfully slow the five measured complete runtime calls.
It increased user-paid execution gas by 24–34% for the three state-changing
operations, but the absolute increase was 7–72 gas at the current gas schedule.
Isolated native instantiation took roughly 0.6–3 microseconds longer.

These results support disabling CoW for fuel determinism, followed by
cross-platform regression checks and validation of existing fuel budgets. They
do not establish the cost for large third-party contracts or measure memory use.
The determinism discussion is tracked in
[Wasmtime #14331](https://github.com/bytecodealliance/wasmtime/issues/14331).

## Full runtime calls

Times are medians of per-call batch averages across 20 paired samples: two
independent runs, each with 10 samples of 50 calls per mode and scenario.
Percentage changes are medians of the paired off/on ratios, so they need not
equal the ratio of the two independently calculated medians. Negative means
CoW off was faster. The interquartile range describes sample spread, not a
confidence interval.

| Operation | CoW on | CoW off | Paired change | Paired change, middle 50% |
| --- | ---: | ---: | ---: | ---: |
| Token balance view | 0.348 ms | 0.344 ms | -1.34% | -1.82% to -0.72% |
| Transfer 1 KOR | 5.932 ms | 5.902 ms | -0.49% | -0.64% to -0.33% |
| Add 1 KOR to an existing stake | 8.030 ms | 7.999 ms | -0.48% | -0.58% to -0.35% |
| Mint NFT and its storage agreement | 11.156 ms | 11.094 ms | -0.54% | -0.65% to -0.41% |
| List 25 NFTs | 13.088 ms | 13.055 ms | -0.18% | -0.33% to -0.10% |

The separate runs' paired changes were respectively -1.34%/-1.19% for balance,
-0.51%/-0.49% for transfer, -0.44%/-0.49% for staking, -0.50%/-0.61% for mint,
and -0.18%/-0.16% for listing. Treat these small differences as evidence against
a substantial slowdown in these workloads, rather than a general speedup claim.

User fees were identical across all samples within each mode:

| Operation | Gas, on → off | Increase | Fee in KOR, on → off | Extra KOR |
| --- | ---: | ---: | ---: | ---: |
| Transfer | 21 → 28 | 33.3% | 0.000000021 → 0.000000028 | 0.000000007 |
| Add stake | 211 → 283 | 34.1% | 0.000000211 → 0.000000283 | 0.000000072 |
| Mint NFT | 273 → 338 | 23.8% | 0.000000273 → 0.000000338 | 0.000000065 |

These are execution fees actually burned by the normal payment path, including
nested calls and gas rounding. They exclude transferred/staked principal and
storage collateral. Current defaults are 1,000 Wasmtime fuel per gas and
0.000000001 KOR per execution gas. Views burn no user tokens in this API path;
that does not mean they consume no fuel or node resources.

## Isolated native instantiation

Each cell summarizes 20 batches of 500 fresh instances. Timing excludes Store
creation/destruction, compilation, and linker resolution. Fuel includes all
instantiation work, not just copying data. Every fuel measurement was identical
within a contract/mode, across both runs.

| Contract | Time, CoW on | Time, CoW off | Fuel, on → off |
| --- | ---: | ---: | ---: |
| Token | 9.94 µs | 10.58 µs | 1 → 6,123 |
| Filestorage | 11.58 µs | 14.53 µs | 1 → 33,076 |
| Staking | 10.27 µs | 12.94 µs | 1 → 32,998 |
| System | 3.29 µs | 6.02 µs | 0 → 679 |
| NFT | 9.21 µs | 11.49 µs | 1 → 31,274 |

An instantiation-only measurement does not include later CoW page faults during
execution. This benchmark does not separately measure those faults, so it cannot
attribute the small full-call speed differences to them. The full runtime path
also performs substantial database and payment work beyond instantiation.

## Method and reproduction

- Apple M2, Linux/aarch64, kernel `7.1.13-401.asahi.fc44.aarch64+16k`,
  Rust `1.98.0 (88d9e12ae 2026-08-18)`, optimized release build.
- Measured processes restricted to performance CPUs 4–7 with `taskset`.
  This was a normal desktop machine, not an otherwise idle dedicated benchmark
  host. Small timing effects should not be generalized to other machines.
- Two independent databases seeded with the same identities and business state
  before switching engine configuration. Each mode gets an engine, matching
  linkers, and fresh compiled-component cache. Only `memory_init_cow` differs.
- Each fixture starts with two funded identities, an existing 10-KOR stake, and
  32 NFTs. Both execution paths are warmed before measurement. Mode order
  alternates between paired samples.
- Each batch runs under an outer database savepoint and is rolled back afterward.
  Transfer balances, stake amounts, NFT totals, and page lengths are checked.
  Setup, rollback, fee reads, and final state queries are outside timed regions;
  inexpensive return-value checks for views remain inside the timed calls.
- Full calls use normal typed APIs, instantiation, storage, nested contract calls,
  and payment settlement. Profiling is off; fee measurements use the burner
  balance. No Bitcoin/consensus/network delay, compilation, or outer block
  commit/fsync is included.
- This is a latency and execution-fee benchmark. It does not measure RSS,
  concurrent throughput, cold compilation, large contracts, or macOS behavior.

From the repository root, build first, then run twice without other Cargo work
running concurrently. The recorded runs invoked the compiled indexer test binary
directly after the smoke build; the filtered Cargo invocation below runs the same
test. CPU numbers are specific to this machine; omit or adapt `taskset` elsewhere.

```sh
cd core
CARGO_BUILD_JOBS=2 cargo test --locked --release --workspace --lib \
  contract_memory_init_cow_costs --no-run
for run in 1 2; do
  RUST_LOG=warn CARGO_BUILD_JOBS=2 KONTOR_COW_SAMPLES=10 KONTOR_COW_CALLS=50 \
    taskset -c 4-7 cargo test --locked --release --workspace --lib \
    contract_memory_init_cow_costs -- --ignored --nocapture \
    > "/tmp/kontor-cow-bench-run${run}.log" 2>&1
done
```

Each `COW_BENCH` line contains a JSON sample. Divide `elapsed_ns` and `burned_kor`
by `calls` for per-call measurements. The `fuel` field is already per instance.
Original local logs are `/tmp/kontor-cow-bench-run1.log` and
`/tmp/kontor-cow-bench-run2.log`; these temporary files are not checked in.
