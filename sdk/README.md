# @kontor/sdk

Types and utilities useful for working with the Kontor indexer.

```bash
# setup
npm ci

# test
npm run test

# test using playwright
npm run test:browser

# regenerate component and API bindings (Rust + podman/docker required)
../tools/kontor build sdk

# build
npm run build
```

Generated output uses the [shared pinned build](../tools/BUILD.md).
`npm run build:rs` is an alias; the regular npm build consumes checked-in output.

## Contract calls and errors

Generated calls return the success value directly. A WIT `result<T, error>`
becomes `Promise<T>` for a view or `Inst<T>` for a write. Awaiting a write submits
it and waits for its outcome. A successful `result<_, error>` resolves to
`undefined`.

```ts
import { ContractError } from "@kontor/sdk";

try {
  const page = await token.balances(null, 100n);
  console.log(page.items);
} catch (error) {
  if (error instanceof ContractError) {
    console.error(error.functionName, error.contract?.toString(), error.data);
  } else {
    throw error;
  }
}
```

When the contract returns `err`, `ContractError.data` preserves its decoded error
variant and payload, and `contract` and `functionName` identify the call. Execution
failures, such as traps or exhausted gas, also throw `ContractError` and may have
no contract-returned `data`. Transport failures continue to throw transport
errors. Only the outer WIT result is unwrapped; ordinary variants named `ok` or
`err` keep their meaning as data.

`simulate()`, `inspect()`, and `(await call.submit()).wait()` retain per-operation
diagnostics. Their `value` is the success value, and `contractError` contains the
structured error when the contract returned `err`. Status and gas remain
available, including all outcomes in a batch. Ordinary `await session.bulk(...)`
returns the tuple of success values or throws on failure. Throwing in JavaScript
does not roll back other operations that already executed on chain.

This changes the generated SDK API. Regenerate bindings and replace
`Result.unwrap(await call)` with `await call`. Move `Result.isErr` / `unwrapErr`
handling around ordinary calls into `try` / `catch`. The contract WIT and on-chain
behavior are unchanged; low-level WIT decoding still preserves result values.

## Token balance pages

Regenerate contract bindings from the current token WIT. `balances` now takes an
exclusive cursor and a page size, resolving to `{ items, next }`.
This replaces the old no-argument, full-list response in the native token and both
test tokens. Update clients alongside the rebuilt contracts.

Use `paginate` to walk items without managing the cursor:

```ts
import { paginate } from "@kontor/sdk";

for await (const balance of paginate((after) => token.balances(after, 100n))) {
  console.log(balance.acc.toRaw(), balance.amt.toString());
}
```

The helper accepts any async page fetcher returning `{ items, next }`. It fetches
only as the iterator is consumed, passes each cursor through unchanged, and stops
when `next` is `null`. `break` stops further page requests. Errors propagate to the
consumer without retrying. Empty pages with a continuation cursor are followed;
an unchanged non-null continuation cursor throws instead of repeating the page.

To start after a saved cursor, pass
`paginate(after => token.balances(after, 100n), { after: savedCursor })`.
For page-based interfaces or saving continuation cursors, use `balances` directly:

```ts
let after: string | null = null;
do {
  const page = await token.balances(after, 100n);
  for (const balance of page.items) {
    console.log(balance.acc.toRaw(), balance.amt.toString());
  }
  after = page.next;
} while (after !== null);
```

Pages contain at most 100 entries. Zero requests return an empty page; invalid
cursors throw a `ContractError`, including with a zero limit. Pass `next` back unchanged:
ordering follows canonical holder storage keys, not balances or numeric signer
IDs. A cursor still works after its holder's row is removed. `next: null` means
there were no more visible entries when that page was read.

Native and decimal tokens exclude core and burner accounts; the integer test
token excludes the burner. Reward pools and stored zero balances remain visible.
Each page reads current state independently. A multi-page walk is not a snapshot
across concurrent transfers, insertions, removals, or chain rollbacks.
