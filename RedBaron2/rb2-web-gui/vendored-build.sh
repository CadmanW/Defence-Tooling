#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSET_DIR="$ROOT_DIR/internal/server/assets"
VENDOR_TARBALL="$ROOT_DIR/vendor.tar.xz"
REQUIRED_FILES=(
  "$VENDOR_TARBALL"
)

cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "go is required on PATH" >&2
  exit 1
fi

GO_VERSION="$(go env GOVERSION)"
if [[ "$GO_VERSION" != "go1.24.4" ]]; then
  echo "warning: expected Go 1.24.4, found $GO_VERSION" >&2
fi

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing $path; run ./vendor.sh first" >&2
    exit 1
  fi
done

cleanup() {
  rm -rf "$ROOT_DIR/vendor"
  rm -f "$ASSET_DIR/asciinema-player.css" "$ASSET_DIR/asciinema-player.min.js"
}
trap cleanup EXIT

cleanup
tar -xJf "$VENDOR_TARBALL" -C "$ROOT_DIR"

for path in \
  "$ROOT_DIR/vendor/modules.txt" \
  "$ASSET_DIR/asciinema-player.version" \
  "$ASSET_DIR/asciinema-player.css" \
  "$ASSET_DIR/asciinema-player.min.js"
do
  if [[ ! -f "$path" ]]; then
    echo "vendored artifact missing $path" >&2
    exit 1
  fi
done

export GOPROXY=off
export GOSUMDB=off

CGO_ENABLED=1 go build -mod=vendor -tags "fts5 vendored" -o rb2-web ./cmd/server

echo "Built $ROOT_DIR/rb2-web"
