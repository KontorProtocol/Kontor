# Wasmtime component lifting integration

The workspace pins Wasmtime to `bfdee9ba9a483915dc95432708cf7db8281adbc1` in
`core/Cargo.toml` and `core/Cargo.lock`. The revision is on the
`wilfreddenton/wasmtime` fork pending a patched stable 51 release. Both
`built-in-types` and `indexer` use the workspace dependency. Keep the `wave`,
`component-model-async`, and test-only `call-hook` features when updating it.

The integration branch configures component lifting at 512 fuel per value node,
16 per guest-encoded string byte, and 16 per declared metadata byte. It disables
Wasmtime's separate native allocation allowance for Kontor Stores. These prices
are candidates, not approved protocol constants. Current main has no fixed
paid-operation fuel cap: it uses each committed gas limit multiplied by 1,000.
Views default to 1,000,000 gas and have an operator-configurable limit. This
branch does not impose the 100 million fuel cap used in the earlier trial.

Changing Wasmtime or lifting prices can change fuel exhaustion and transaction
results. Production activation therefore needs a protocol decision covering
prices, paid and view budgets, coordinated node rollout, and replay of any
history produced under older rules. Do not treat a successful build of this
branch as approval to activate it on an existing chain.

After the patch is reapplied to the Wasmtime 51.0.0 release on the fork, update
the Git revision to that immutable fork commit and keep the Git dependency.
Switch to an exact registry version only when an upstream release includes the
required lifting feature. For either update, commit `core/Cargo.lock`, verify
that Wasmtime and Cranelift resolve from one intended source, and run the core
checks and runtime tests on Linux and macOS, including fuel-boundary and
published-contract tests. The Docker `cargo-chef` build must also resolve the
pinned source from a clean cache.
