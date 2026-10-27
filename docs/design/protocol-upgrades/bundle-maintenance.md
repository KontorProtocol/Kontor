# Independently built protocol bundles

K1 introduces a qualification executable and reusable builder. The production
node still uses its existing P1 execution path. K2a defines the semantic adapter,
K2b extracts P1 and changes the node build, and K7 introduces actual activation.
Passing this qualification does not mean those phases are implemented.

## Build and evidence

Run `RUSTUP_TOOLCHAIN=1.99.1 RUSTC_WRAPPER= ./tools/kontor protocol-bundles` from
the checkout. The command builds the two graphs sequentially with at most two
compiler jobs, links their exact current artifacts into one native executable,
audits ownership, then runs the real VM, crypto and consensus qualification.
Use `--offline` after fetching both manifests to avoid dependency downloads.
Use `--output PATH` to keep evidence elsewhere. Concurrent invocations sharing
an output root are rejected. `--target` must match the supported native host.

The supported targets are Linux ARM64, Linux x86-64 and macOS ARM64. CI uses
release on each, matching the current node tests on macOS. Linux runs in the
root Dockerfile's `protocol-bundle-qualification` target, derived from the same
`builder-base` as the node. The ordinary node image is unchanged by K1.
The development profile is available for local diagnosis.

Evidence lives under `OUTPUT/TARGET/PROFILE`. Only a successful run writes
`qualification.json`. A previous success marker is removed before rebuilding.
Logs and source inventories remain after failure. A leftover `proof-wal`
directory is deliberately not deleted automatically: inspect failed engine
ownership before removing it and rerunning. CI uploads inventories and logs,
including failures; it does not upload build caches or treat a cache hit as
qualification.

The evidence records resolved packages and features, both lockfiles, source
hashes, inherited workspace manifests and Cargo configuration, compiler and
sysroot inputs, build flags, exact staged rlibs and native archives, compiler
plugins, common runtime ownership, final symbol ownership and executable hash.
Source and staged artifact checks run across compilation and qualification.
Git checkouts must match their pinned commit objects, including raw tracked
file contents, symlink targets, executable modes, staged indexes and recursive
submodule identities. Untracked and ignored files are rejected apart from
Cargo's exact administrative markers. This catches edits made before the build,
including files marked assume-unchanged in Git's index.
Verification ignores replacement refs, rejects graft files and rehashes the
pinned commit and reachable tree objects instead of trusting the local object
database's mapping. Git's own corruption checks vary by operation and version.
Registry source files must match the cached crate archive whose SHA256 matches
the lockfile. Keep those archives in Cargo's cache for offline qualification;
missing archives fail verification rather than trusting an edited extraction.
Absolute source paths and platform inputs are recorded. This is an audit of
the actual build, not a claim that different checkouts or platforms produce
byte-identical executables.

## Isolation and common ownership

Each graph has its own Cargo workspace, lock, feature resolution, output path
and compiler metadata. A rustc wrapper adds the graph identity to both target
and host units, including proc macros, while retaining Cargo's unit metadata.
It invokes the exact pinned compiler and rejects a second wrapper. Compiler
plugins are compiler inputs, never node runtime libraries. Bidirectional
wrong-plugin controls require the distinct metadata hashes to reject mixing.

The executable consumes only artifacts emitted by the current Cargo invocation.
The input audit includes Rust and anonymous symbols, not only native helpers.
It rejects cross-graph definitions and references, graph definitions that shadow
common inputs, undeclared imports, global allocators and native symbols without
an owner. Common Rust definitions must appear in the pinned sysroot or the actual
host object files. Platform imports resolve within explicitly allowed runtime
library scopes, with their paths and hashes recorded where files are available.
macOS system libraries may instead reside in the dyld shared cache.

The three optional weak system-libunwind registration imports are named
explicitly. They remain optional only when every reference is weak; making one
strong fails qualification if no owner exists. Darwin uses `nm -m` to retain
the weak-reference attribute, unlike the name-only undefined output. See the
[LLVM nm format documentation](https://www.llvm.org/docs/CommandGuide/llvm-nm.html).

Both graphs share one pinned standard library, allocator and unwind runtime.
The proof boundary carries standard-library values, closures and opaque
`Box<dyn Any + Send>` owners. Tokio values from different graphs cannot cross
that boundary. Wrong-graph opaque owners are rejected. Exported calls contain
panics, including a panic in the host callback. Engine owners are dropped on
control threads, where their graph's destructor can finish joining workers.

## Process resources

Bundles may not subscribe to node control signals or spawn children. A source
check guards maintained Kontor/Malachite call sites; it is a review tripwire,
not a language sandbox. Third-party behavior requires source review. The live
proof verifies node SIGTERM/SIGINT delivery and child exit status with both
engines running and across repeated replacements.

Explicit resident resources are Wasmtime's Unix trap handlers and Rayon pool,
one blst crypto pool per graph, one futures-timer helper per graph and one Tokio
Unix signal registry socket pair per graph. The blst jobs hold crypto inputs,
not node callbacks or state/signing authority. Completion precedes the caller's
return, though final closure cleanup may follow. A stalled crypto job can block
its caller; a timeout must retain ownership rather than free its inputs.

The proof records cold and per-graph crypto, VM and engine counts before checking
repeated use. It requires bounded one-time allocation and no replacement growth.
The blst pool is separate from the VM pool. A future production node with its
own blst copy plus two bundles can retain three pools. These resources stay
resident; bundle unloading is unsupported.

## Changing a retained bundle

1. Preserve the old manifest, lock, source identity and semantics. Add a new
   protocol mapping in the later production phases rather than rewriting history.
2. Assign each retained Wasmtime graph a unique immutable package version and
   native prefix, even when its VM code is otherwise unchanged. Reusing VM code
   requires a new version-only fork release until a separate native namespace
   mechanism has been implemented and reviewed.
3. Resolve and commit the new lock deliberately. Keep F2 native patches and F3
   managed-engine ownership. Do not change blst threading features to make
   resource counts pass. Preserve portable lifting charges.
4. Run the negative controls and real qualification on every shipped node
   platform. Audit both bundle locks using the existing core advisory policy.
5. Obtain independent and Interlink reviews of semantics, native/process
   ownership and integration. Compiler changes require renewed qualification of
   every retained protocol. Historical transaction replay alone is insufficient.

The conflicting itoa patch requirements demonstrate why one unified Cargo
resolution is insufficient. Deliberately different serde_json features, VM
lifting prices and compile-time Tokio types prove that the two graphs remain
distinct. These differences are qualification fixtures, not a definition of P2.
