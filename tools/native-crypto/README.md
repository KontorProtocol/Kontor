# Native crypto qualification

These patches add opt-in symbol namespaces to the exact crypto versions already
used by Kontor. They do not update the algorithms or dependency versions. The
ordinary node and SDK builds omit `KONTOR_NATIVE_NAMESPACE`. A retained protocol
bundle sets both `KONTOR_PROTOCOL_BUNDLE=1` and an explicit
`KONTOR_NATIVE_NAMESPACE`; missing or invalid namespaces fail the build. The K1
bundle builder will derive that namespace from immutable bundle identity and
record it in the artifact attestation. F2 alone does not implement that builder.

`sources.json` records each published crate archive's SHA-256 and VCS metadata.
The archive hash is authoritative, including for ring's published dirty VCS tree.
All upstream license files remain in the vendors. `kontor-native-build` is owned
Kontor code, not part of the upstream archives.

From the repository root:

```sh
python3 tools/native-crypto/vendor.py
python3 tools/native-crypto/check-helper-lock.py
cargo test --locked --manifest-path core/vendor/kontor-native-build/Cargo.toml -j2
python3 tools/native-crypto/qualify.py --output /absolute/path/to/new-evidence-directory
```

The qualification harness uses Rust 1.99.1 and cached Cargo dependencies. Fetch
the locked dependencies for `core/Cargo.toml`,
`core/vendor/kontor-native-build/Cargo.toml`, and
`tools/native-crypto/object-report/Cargo.toml` before running on a fresh machine.
Builds run serially with two Cargo jobs. It refuses to reuse an evidence directory
so stale archives cannot become acceptance evidence.

The helper is deliberately excluded from the core workspace. Cargo Chef replaces
workspace member sources with skeletons, which would erase the helper API used
by the vendored build scripts. Its separate lock and exact `cc` pin keep its unit
tests on the same dependency versions as the core native build. CI checks that
relationship and runs the real Docker planner and cacher on both Linux node
architectures before merging changes to core sources or the container recipe.

For each of two feature configurations, the harness independently resolves a
facade from the core lock, verifies package identities against that lock, then
builds pristine, patched-default, and patched-namespaced crypto. Builds consume
separate locks and target directories. The first configuration uses portable blst
and low-memory secp; the second uses ordinary platform blst and secp. Both enable
secp recovery, exercising that optional FFI surface too.

The native object reporter compares every loadable code/data section, zero-fill
size, alignment, symbol properties, relocation, and relevant COMDAT selection.
ELF and Mach-O are supported. Crypto symbols and references must carry their
graph's leading namespace; a bare crypto-family reference fails before comparison.
Per-symbol prefix coverage is saved with the evidence. Symbol names alone are normalized; data bytes are
never rewritten. Debug sections, compiler comments, archive member filenames and
timestamps do not affect the loaded image and are excluded. Relocatable section
placement is not a final runtime address, so symbol positions are compared relative
to their sections. Unwind bytes and relocations remain fully compared. Instruction bytes are
compared directly, which is stricter than textual disassembly comparison. Any
remaining difference fails and writes the two reports for inspection. A failed
comparison must be investigated, not bypassed by adding broad exclusions.

Crypto fixtures check the full SHA-256 `abc` vector and RFC 8032 Ed25519 test 1,
BLS signing/aggregation/verification, ECDSA signing/recovery, Schnorr signatures,
and malformed or mismatched inputs. All deterministic public key and signature
bytes must match the pristine build, across both feature configurations. The two
namespaced rlib graphs then link into one executable alongside an ordinary,
unnamespaced node graph. They run 1,200 exercises across four threads, racing
first-use initialization and reversing call order. The third graph makes accidental
binding to the node's crypto copy possible, so undefined-reference checks are
necessary even when the executable links and the vectors pass.

The native inventory comes from the current Cargo artifact messages and current
build-script output directories, before dead stripping. It covers C/assembly
archives and Rust rlibs, including secp's four Rust exports. Namespace ownership
and intersections are checked before linking. Undefined native references must
belong to their own graph. Final live crypto entry points have distinct addresses.

Comparator negative controls:

```sh
RUSTUP_TOOLCHAIN=1.99.1 cargo build --locked --manifest-path tools/native-crypto/object-report/Cargo.toml
python3 tools/native-crypto/test_object_report.py
```

The tests deliberately change instructions, initialized data, zero-fill size,
relocation targets, weak binding, and alignment. A deliberate bare crypto call
links successfully against a default provider but must fail both reference audits.
Cross-format cases use clang to
produce Linux ARM/x86 and macOS ARM/x86 objects without needing SDK headers. These
small cross-format cases qualify the comparator, not the crypto libraries on
those platforms. Real library/platform and SDK/mobile checks are separate gates.

## Updating a vendor

Changing core's `cc` version also requires updating the helper's exact pin and
standalone lock; `check-helper-lock.py` enforces their agreement.

The ordinary reproducible-build CI job also compares the actual SDK Wasm crypto
API with the committed pristine reference identified in `fixtures/sdk-vectors.json`.
`compare-sdk.mjs` checks the reference Wasm hash and pinned Node version before
executing either API. Its report is included in the generated-output artifact.
The native SDK integration test consumes the same independent vectors and error
messages. The fixture covers Kontor's min_sig scheme and EIP-2333 derivation.
Changes to these reference values need an explicit compatibility decision and
evidence from the recorded reference, not replacement with candidate output.

1. Treat a dependency update in a retained protocol as a new bundle identity.
   Do not replace the source artifacts used to reproduce historical bundles.
2. Obtain the published crate archive and verify its checksum against the newly
   resolved Cargo lock. Update the version, archive checksum and VCS metadata in
   `sources.json`. Preserve the original archive's complete license/provenance files.
3. Reapply the namespace patch deliberately. Check every optional Rust FFI module,
   assembly architecture, mutable CPU capability global, and exported Rust callback.
   Update blst's symbol inventory from every supported target, not just the host.
4. Record intentional changes with `vendor.py --refresh-patches`. Review the patch
   against pristine source. `vendor.py --apply` reconstructs the vendor from the
   verified archive plus patch and removes obsolete files. Ordinary `vendor.py`
   verifies without changing the vendor.
5. Run object equivalence and concurrent dual-graph qualification on every shipped
   node target. Run the ordinary node, SDK Wasm/native and mobile checks too. Keep
   logs, source/lock hashes, native inventories and qualification reports with the
   reviewed change. Do not interpret a vector-only pass as compatibility evidence.

F2 merged in PR #604 after both reviews and green PR checks. Its first main-only
container build exposed the helper skeleton problem described above. The
correction adds separate helper qualification and PR-time container coverage.
See the execution ledger for completed evidence and outstanding phase gates.
