# Numeric encoding and decoding costs

Measured on 2026-09-10 against main
`6a64d4653b5c9015d9274dea0852a5a9cd3204f7` (#557). Production code is unchanged;
the alternatives below are isolated experiments.

## Conclusion

The 33-byte numeric codec is inexpensive in absolute CPU time. Encoding has
avoidable buffer growth and byte-at-a-time work; a small implementation change
can improve it without changing any encoded bytes. Decoding is already cheap,
particularly for the nonnegative balances and reward amounts used most often.
There is no evidence here that a different numeric representation or more
complex serialization framework is warranted.

## Measurements

Median nanoseconds per operation in a fuel-metered Wasmtime core-module probe:

| Operation | Positive | Negative |
| --- | ---: | ---: |
| Current encode into a new Vec | 133.8 | 316.8 |
| Current encode, reserve 33 bytes first | 130.9 | 292.9 |
| Candidate: build 33 bytes, append together | 89.5 | 96.3 |
| Current encode into reused capacity | 96.4 | 257.6 |
| Candidate append into reused capacity | 61.4 | 67.8 |
| Current decode | 11.4 | 37.9 |
| Candidate: decode/invert whole limbs | 12.8 | 20.4 |

The fresh-buffer candidate reduces encoding time by approximately 33% for
positive inputs and 70% for negative inputs in this experiment. Reusing capacity
is relevant when building a larger key or projection; current storage calls take
ownership of their byte buffer, so it is not a drop-in alternative everywhere.

Native optimized execution of the same numeric probe measured approximately
51/82 ns for current positive/negative encoding, 11 ns for the candidate, and
3–4 ns for decoding. Native results alone would overstate the value of simply
reserving capacity: its Wasm improvement was much smaller.

The actual host `indexer_types::serialize` / `deserialize::<Vec<u8>>` wrappers
were measured separately on a 33-byte payload. They took approximately 92 ns to
serialize and 34 ns to deserialize, including the result allocation. The stored
byte-list frame is 34 bytes: the 33-byte numeric payload plus its length prefix.
This is generic byte-list framing, not another numeric conversion.

These are component costs, not end-to-end storage timings. No database query,
component ABI crossing, async dispatch, deposit accounting, or complete contract
execution is included in the numeric loop. The earlier millisecond-scale reward
measurements cannot establish precisely what fraction belongs to this codec.
Do not present the codec's percentage improvement as a contract speedup.

## What costs time

`KeyElement::encode()` starts with `Vec::new()`. `encode_int256` then pushes a tag,
followed by a 32-byte magnitude. On negative inputs it pushes the inverted bytes
one at a time. A separate native allocation-counting run observed:

| Fresh encoding | Initial allocations | Reallocations | Final capacity |
| --- | ---: | ---: | ---: |
| Positive, current | 1 | 1 | 33 |
| Negative, current | 1 | 3 | 64 |
| Either sign, reserve 33 first | 1 | 0 | 33 |

The arithmetic is four limb byte-order conversions, a zero/sign check and
optional bit inversion. Decimal uses its already-scaled coefficient; encoding
does not divide, rescale, format text or perform arbitrary-precision arithmetic.
Decoding allocates no heap memory within the codec itself; obtaining its input
through the storage ABI still has separate allocation and transfer costs.

The candidate constructs the tag and four big-endian limbs in a stack array,
inverts negative limbs as whole `u64`s, then appends the array to the destination
once. This retains one shared codec, the exact 33-byte format, canonical zero,
numeric ordering, and the ability to append to existing buffers.

The decoder experiment also inverted whole limbs. It improved negative decoding
but slightly regressed the positive case and increased positive-case Wasm fuel.
Keep the current decoder unless a refined candidate improves the actual workload.

## Follow-up recommendation

The subsequent [key-construction investigation](key-construction-costs.md) tests
temporary-buffer removal against complete reward operations. The numeric encoder
proposal below remains unimplemented; a standalone codec speedup does not establish
a meaningful contract speedup.

1. Make the small bulk-append improvement in the shared numeric encoder, with
   byte-for-byte parity and existing ordering/malformed-input tests, pinned
   contract rebuilds, and an end-to-end reward check. No encoding migration is
   needed because bytes stay identical; deployment still updates contract binaries.
2. Investigate temporary buffers at key/projection construction sites separately.
   `KeyPath::push_element` currently encodes into a temporary Vec before copying
   into the new path, and generated covering projections append temporary field
   encodings. Existing `encode_to(&mut Vec<u8>)` can avoid those intermediates.
   These opportunities were inspected but not benchmarked here; path cloning and
   ownership costs remain even after removing the temporary encoding.
3. Leave decoder and host byte-list framing alone for now. Prioritize the query
   work that avoids discarded rows and separate reads over increasingly complex
   optimizations of a few nanoseconds.

General key encoding is not uniformly fixed cost: strings/bytes require scanning
and escaping their contents, tuples encode their fields, and some domain types
still use display-based keys. The numeric results should not be generalized to
arbitrarily long strings or entire paths.

## Method and coverage

- Local aarch64 Linux; rustc 1.98.0; native `opt-level=3`.
- Wasm `opt-level=z`, LTO, one codegen unit, panic abort, then wasm-opt 116 `-Oz`
  with bulk memory and sign extension. This follows the contract optimization
  shape, but uses the local toolchain, not a pinned component build.
- Repository Wasmtime dependency, fuel enabled, threads/relaxed SIMD disabled
  and NaN canonicalization enabled. One export runs a batch so host-call timing
  does not dominate the codec measurement.
- Nine measured repetitions after one warm-up round, rotated case order;
  500,000 operations per native batch and 100,000 per Wasm batch. Small and
  full-width coefficients, positive/negative/mixed-sign cases, black-boxed inputs
  and outputs. Fixture setup and loop overhead are included, not subtracted.
  The Wasm loop baseline was approximately 4 ns per iteration.
- A native global allocator counted allocations in a separate executable, so
  counters did not distort timed runs. No heavy build ran during the measurements.
- Candidate byte parity checked 32,784 combinations of sign, coefficient and
  preexisting buffer prefix, including zero and maximum magnitude. Decoder
  parity additionally checked 31,488 tag/length/fill combinations, including
  malformed and noncanonical representations and trailing input.
- These probes establish local implementation opportunities, not full-contract
  performance or full production validation. No normal CI tests were added.

Probe source (`probe.rs`, `allocations.rs`, `runner.rs`), native/Wasm logs and
compiled probes are retained locally in `/tmp/kontor-codec-probe/`. The runner
was temporarily compiled as an indexer example against existing dependencies;
its temporary source was removed from the repository after measurement.
