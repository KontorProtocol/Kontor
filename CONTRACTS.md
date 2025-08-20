# Contracts

This document covers macro usage and patterns when writing native contracts.

## Storage derive behavior

- `#[derive(Storage)]` generates:
  - `Store` + `Wrapper` + `Root`
  - `Clone`
  - `Default` for named structs (can be disabled with `#[storage(no_default)]`): every field is initialized via `Default::default()`. If a field type does not implement `Default`, compilation will fail.

- Opt-out patterns for non-defaultable storage structs:
  - Use `#[storage(no_default)]` with `#[derive(Storage)]` to suppress the generated `Default` impl.
  - Alternatively, use `#[derive(Clone, Store, Wrapper, Root)]` instead of `Storage`.
  - Example: `proxy` uses a `ContractAddress` field that should not have a default; it uses `#[storage(no_default)]`.

- Notes:
  - Do not combine `#[derive(Clone)]` with `#[derive(Storage)]` on the same type (conflicting impls).
  - `Store: Clone` is required for values stored in maps and wrappers; ensure inner types derive `Clone` where needed.
