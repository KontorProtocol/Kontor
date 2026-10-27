# Holder resolution failure classification

`Holder::from_holder_ref` returns an outer host result and an inner WIT result.
Malformed references and a missing signer in a view remain inner validation
errors with their existing text. A database read or write failure remains an
outer infrastructure error. It must abort execution, skip contract-result
recording and roll back the operation, even when the guest would handle an
ordinary validation failure and continue.

Previously, identity resolution converted both `ExecutionError` variants into
`Error::Validation`, and the holder host binding returned that error to the
guest. A node-local database fault could therefore produce a different contract
result from its peers. The fix preserves the distinction at both call sites.

## Classification inventory

| Operation | Failure class |
| --- | --- |
| Public-key or transaction-ID parsing in `runtime/wit/resources.rs` | Deterministic validation, unchanged WIT text |
| Missing identity in a view | Deterministic validation, unchanged WIT text |
| Identity lookup or creation SQL | Infrastructure, outer host error |
| Proof decoding in `runtime/wit/resources.rs` | Pure input validation |
| Frontier, file descriptor and challenge construction in `runtime/host_files.rs` | Pure input validation |
| Signer-to-holder conversion | Host failures remain outer errors |

The regression tests invoke the real native token contract. Identity reads fail
in both view and procedure contexts; the write case fails after inserting signer
and public-key rows. Assertions cover infrastructure classification, no result
counter increment or receipt, restored savepoint/call-stack state, unchanged
checkpoint and table counts, absence of a partially created identity, and a
successful call after removing the fault. Separate assertions pin the original
missing-signer and malformed-public-key error text.

This correction is independent of protocol-bundle extraction. The future
StorageV1 adapter must retain this distinction rather than rendering driver
failures as deterministic contract outcomes.
