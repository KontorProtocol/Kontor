# Local Gossipsub PRUNE backport

This directory starts from the published `libp2p-gossipsub 0.49.5` crate
([crates.io package](https://crates.io/crates/libp2p-gossipsub/0.49.5)).
The original `.crate` SHA-256 is
`3573f3d8e30bd62cda336df5c7c1041a1caa40a648376b8e1e274d585c0ed25c`,
matching the former registry entry in the Kontor lockfiles. The package
declares the MIT license. `LICENSE` is copied from the
[upstream release tag](https://github.com/libp2p/rust-libp2p/blob/libp2p-gossipsub-v0.49.5/LICENSE);
the published archive does not include a separate license file.

The only behavior change from the published source is the unknown-topic mesh
guard in `src/behaviour.rs::handle_prune`, copied from
[upstream PR 6707](https://github.com/libp2p/rust-libp2p/pull/6707)
([merge commit](https://github.com/libp2p/rust-libp2p/commit/6c5a10b4102a7a04f56d6cf65ea58eeff929cefa)).
It rejects a PRUNE entry before `remove_peer_from_mesh` can store a backoff
for a topic the node has not joined. The added regression in
`src/behaviour/tests.rs` checks unknown-topic backoff rejection and normal
known-topic PRUNE handling. This addresses
[RUSTSEC-2026-0534](https://github.com/RustSec/advisory-db/blob/main/crates/libp2p-gossipsub/RUSTSEC-2026-0534.md).
[Upstream issue 6715](https://github.com/libp2p/rust-libp2p/issues/6715)
tracks a compatible 0.49 release.
The published manifest omits the upstream workspace-only `quickcheck`
development dependency while its test modules still import it. The local
manifest restores `quickcheck` only for running the focused regression.

`core/.cargo/audit.toml` has an explicit 0534 exception because cargo-audit
matches the retained 0.49.5 version, even when Cargo selects this patched
local source. That exception records a source patch, not acceptance of the
vulnerable registry package. The active networking workspaces patch this
package to this directory; retained historical workspaces remain frozen.

## Removal

1. Confirm that the selected Malachite dependency graph resolves a verified
   upstream Gossipsub release containing the unknown-topic guard. A Malachite
   version change or new libp2p version number alone is insufficient.
2. Remove this directory, its `[patch.crates-io]` entries from the seven
   active networking manifests, and the 0534 exception from
   `core/.cargo/audit.toml`. Update their lockfiles together.
3. Refresh affected source inventories, managed consensus and node build
   identities. Keep retained historical sources and their evidence unchanged.
4. Verify the selected crate in every active networking graph, retain or move
   the unknown/known-topic PRUNE regression to the selected upstream graph,
   rerun all CI lockfile audits and the relevant existing managed qualification.
