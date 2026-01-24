# Test Configuration

## Running tests

The default build target is `wasm32-unknown-unknown`. Core tests (protocol, sync, client, lib unit tests) run on the **host** using the `webusb` feature disabled:

```bash
./test-host.sh
# or:
cargo test --target $(rustc -vV | grep host | cut -d' ' -f2) --no-default-features
```

## WASM-only tests (`wasm_test.rs`)

The tests in `tests/wasm_test.rs` are gated by the `bugreport-analysis` feature and call into `src/wasm.rs`, which depends on `web-sys`. They only run in a WASM environment:

```bash
wasm-pack test --headless --chrome   # or --firefox
```

Run with the feature enabled for `wasm_test`:

```bash
wasm-pack test --headless --chrome --features bugreport-analysis
```
