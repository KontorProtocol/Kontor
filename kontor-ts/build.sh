cargo build --release

wasm-tools component new target/wasm32-unknown-unknown/release/kontor_ts.wasm -o target/wasm32-unknown-unknown/release/kontor_ts_component.wasm

npx jco transpile target/wasm32-unknown-unknown/release/kontor_ts_component.wasm \
  --name kontor-ts \
  -o ts
