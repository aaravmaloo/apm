#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-"$ROOT_DIR/dist"}"
BIN_NAME="${BIN_NAME:-pm}"
TARGET="${CARGO_BUILD_TARGET:-}"

# Native library output directory
NATIVE_OUT="${APM_NATIVE_OUT:-"$ROOT_DIR/build/native"}"
mkdir -p "$NATIVE_OUT" "$DIST_DIR"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-"$ROOT_DIR/rust/target"}"
export CARGO_TARGET_DIR

# Build Unified Native Rust Library
echo "Building Unified Native Rust library..."
if [[ -n "$TARGET" ]]; then
  cargo build --release --manifest-path "$ROOT_DIR/rust/apm-native/Cargo.toml" --target "$TARGET"
  LIB_NATIVE="$CARGO_TARGET_DIR/$TARGET/release/libapm_native.a"
else
  cargo build --release --manifest-path "$ROOT_DIR/rust/apm-native/Cargo.toml"
  LIB_NATIVE="$CARGO_TARGET_DIR/release/libapm_native.a"
fi
cp "$LIB_NATIVE" "$NATIVE_OUT/libapm_native.a"

case "$(uname -s)" in
  Darwin*)
    RUST_NATIVE_FLAGS="-lc++ -framework Security -framework Foundation"
    GO_EXTLDFLAGS="-L$NATIVE_OUT -lapm_native $RUST_NATIVE_FLAGS"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    RUST_NATIVE_FLAGS="-lstdc++ -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 -lmfplat -lmf -lmfreadwrite -lmfuuid -lstrmiids -lntdll -luserenv -lws2_32 -ldbghelp"
    GO_EXTLDFLAGS="-static -L$NATIVE_OUT -lapm_native $RUST_NATIVE_FLAGS"
    ;;
  *)
    RUST_NATIVE_FLAGS="-lstdc++ -ldl -lpthread -lm"
    GO_EXTLDFLAGS="-static -L$NATIVE_OUT -lapm_native $RUST_NATIVE_FLAGS"
    ;;
esac

GO_TAGS="faceid nativeget"

export CGO_ENABLED=1
go build \
  -tags "$GO_TAGS" \
  -ldflags "-linkmode external -extldflags '$GO_EXTLDFLAGS'" \
  -o "$DIST_DIR/$BIN_NAME" \
  "$ROOT_DIR"

echo "Built $DIST_DIR/$BIN_NAME"
