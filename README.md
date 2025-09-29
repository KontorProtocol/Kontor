# Kontor

The Kontor project is split into two workspaces: `core` and `contracts`.

The `core` workspace contains the application and its tests, while `contracts` contains the native contracts. This separation exists because contracts compile to `wasm32-unknown-unknown`. In `cargo`, compile targets can only be set at the workspace level, not at the crate level ([yet](https://github.com/rust-lang/cargo/issues/9406)).

## Getting Started

Install build dependencies:
```bash
brew install binaryen
brew install brotli
```

Add wasm compile target:
```bash
rustup target add wasm32-unknown-unknown
```

Install cargo expand
```
cargo install cargo-expand
```

Set `core` as the working directory:
```bash
cd core
```
Continue with `core` [README.md](core/README.md).
