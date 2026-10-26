# Kontor network patch

Source: `arc-malachitebft-network` 0.8.2 from crates.io (Malachite v0.8.2).

KontorProtocol/malachite is synchronized to v0.8.2 at
`2b3e1adf19d90e7289ed064501ca4dd74ca3027d`.

Carries the listen-address fix from KontorProtocol/malachite commit
`5ad5a3708fc8397897c43f560b952dbdf8c27c98`: record `NewListenAddr` in
`State.local_node.listen_addr`, so state dumps expose the port selected for
`/tcp/0`. Cluster startup depends on this behavior. All other source is upstream.

Remove this patch when a published upstream release records the resolved address.
