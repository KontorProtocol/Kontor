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

## Token balance pages

Regenerate contract bindings from the current token WIT. `balances` now takes an
exclusive cursor and a page size, returning a `Result` containing `{ items, next }`.
This replaces the old no-argument, full-list response in the native token and both
test tokens. Update clients alongside the rebuilt contracts.

```ts
import { Result } from "@kontor/sdk";

let after: string | null = null;
do {
  const page = Result.unwrap(await token.balances(after, 100n));
  for (const balance of page.items) {
    console.log(balance.acc.toRaw(), balance.amt.toString());
  }
  after = page.next;
} while (after !== null);
```

Pages contain at most 100 entries. Zero requests return an empty page; invalid
cursors return an error, including with a zero limit. Pass `next` back unchanged:
ordering follows canonical holder storage keys, not balances or numeric signer
IDs. A cursor still works after its holder's row is removed. `next: null` means
there were no more visible entries when that page was read.

Native and decimal tokens exclude core and burner accounts; the integer test
token excludes the burner. Reward pools and stored zero balances remain visible.
Each page reads current state independently. A multi-page walk is not a snapshot
across concurrent transfers, insertions, removals, or chain rollbacks.
