#!/usr/bin/env sh
set -eu

APP_NAME="apm"
REPO="aaravmaloo/apm"
LATEST_API="https://api.github.com/repos/${REPO}/releases/latest"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' is not installed" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar
need_cmd uname
need_cmd mktemp

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch_raw="$(uname -m)"

case "$arch_raw" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "error: unsupported architecture: $arch_raw" >&2
    exit 1
    ;;
esac

case "$os" in
  darwin)
    install_root="/usr/local/opt/${APP_NAME}"
    ;;
  linux)
    install_root="/opt/${APP_NAME}"
    ;;
  *)
    echo "error: install.sh supports macOS (darwin) and Linux only" >&2
    exit 1
    ;;
esac

bin_dir="/usr/local/bin"
target_bin="${install_root}/${APP_NAME}"
link_bin="${bin_dir}/${APP_NAME}"

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  need_cmd sudo
  SUDO="sudo"
fi

release_json="$(curl -fsSL "$LATEST_API")"

asset_url="$(
  printf '%s' "$release_json" \
    | tr -d '\r' \
    | grep -Eo '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/^"browser_download_url"[[:space:]]*:[[:space:]]*"//; s/"$//' \
    | grep -E "_${os}_${arch}\\.tar\\.gz$" \
    | head -n 1
)"

version="$(
  printf '%s' "$release_json" \
    | tr -d '\r' \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1
)"

if [ -z "$asset_url" ]; then
  echo "error: could not find a ${os}/${arch} release asset at ${LATEST_API}" >&2
  exit 1
fi

if [ -z "$version" ]; then
  version="latest"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

archive_path="${tmp_dir}/apm.tar.gz"

curl -fsSL "$asset_url" -o "$archive_path"

tar -xzf "$archive_path" -C "$tmp_dir"

found_bin=""
for candidate in apm pm; do
  candidate_path="$(find "$tmp_dir" -type f -name "$candidate" | head -n 1 || true)"
  if [ -n "$candidate_path" ]; then
    found_bin="$candidate_path"
    break
  fi
done

if [ -z "$found_bin" ]; then
  echo "error: could not find an executable named 'apm' or 'pm' in the release archive" >&2
  exit 1
fi

$SUDO mkdir -p "$install_root" "$bin_dir"
$SUDO install -m 0755 "$found_bin" "$target_bin"
$SUDO ln -sfn "$target_bin" "$link_bin"

echo "Installed ${APP_NAME} (${version})"
echo "Binary: ${target_bin}"
echo "Command: ${link_bin}"
echo "Run: ${APP_NAME} --help"