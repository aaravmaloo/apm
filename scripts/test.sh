#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-"$ROOT_DIR/rust/target"}"
export CARGO_TARGET_DIR

echo "Testing Go root module..."
go test ./...

echo "Testing Go team module..."
(cd "$ROOT_DIR/team" && go test ./...)

echo "Testing rust/apm-get..."
cargo test --manifest-path "$ROOT_DIR/rust/apm-get/Cargo.toml"

echo "Checking rust/apm-native..."
cargo check --manifest-path "$ROOT_DIR/rust/apm-native/Cargo.toml" --all-targets

echo "Checking rust/faceid..."
cargo check --manifest-path "$ROOT_DIR/rust/faceid/Cargo.toml" --lib
