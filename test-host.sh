#!/usr/bin/env bash
# Run tests on the host target (protocol, sync, client, lib unit tests).
# Use this because the default build target is wasm32-unknown-unknown;
# core tests use --no-default-features to build without WebUSB and run natively.

set -e
HOST_TARGET=$(rustc -vV | grep host | cut -d' ' -f2)
echo "Running host tests (target=$HOST_TARGET, no webusb)..."
cargo test --target "$HOST_TARGET" --no-default-features "$@"
