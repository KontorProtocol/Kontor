cargo build --release

wasm-tools component new target/wasm32-unknown-unknown/release/postcard_ts.wasm -o target/wasm32-unknown-unknown/release/postcard_ts_component.wasm

npx jco transpile target/wasm32-unknown-unknown/release/postcard_ts_component.wasm \
  --name postcard-ts \
  -o ts
