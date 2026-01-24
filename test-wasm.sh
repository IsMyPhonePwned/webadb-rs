#!/bin/bash
# Script to run wasm_test with host target
# This is needed because .cargo/config.toml sets default target to wasm32-unknown-unknown

HOST_TARGET=$(rustc -vV | grep host | cut -d' ' -f3)
echo "Running tests for target: $HOST_TARGET"
cargo test --test wasm_test --features bugreport-analysis --target "$HOST_TARGET" "$@"
