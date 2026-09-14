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
