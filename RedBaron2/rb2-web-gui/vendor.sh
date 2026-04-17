#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PLAYER_VERSION="$(tr -d '\n' < "$ROOT_DIR/internal/server/assets/asciinema-player.version")"
ASSET_DIR="$ROOT_DIR/internal/server/assets"
VENDOR_TARBALL="$ROOT_DIR/vendor.tar.xz"
PLAYER_TARBALL="$TMP_DIR/asciinema-player-${PLAYER_VERSION}.tgz"

cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "go is required on PATH" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required on PATH" >&2
  exit 1
fi

echo "Generating Go vendor tree..."
rm -rf "$ROOT_DIR/vendor"
go mod vendor

echo "Fetching asciinema-player@${PLAYER_VERSION}..."
npm pack "asciinema-player@${PLAYER_VERSION}" >/dev/null
mv "asciinema-player-${PLAYER_VERSION}.tgz" "$PLAYER_TARBALL"

mkdir -p "$ASSET_DIR"
rm -f "$ASSET_DIR/asciinema-player.css" "$ASSET_DIR/asciinema-player.min.js"

echo "Extracting vendored player assets..."
tar -xzf "$PLAYER_TARBALL" -C "$TMP_DIR" \
  package/dist/bundle/asciinema-player.css \
  package/dist/bundle/asciinema-player.min.js

cp "$TMP_DIR/package/dist/bundle/asciinema-player.css" "$ASSET_DIR/asciinema-player.css"
cp "$TMP_DIR/package/dist/bundle/asciinema-player.min.js" "$ASSET_DIR/asciinema-player.min.js"

if [[ ! -s "$ASSET_DIR/asciinema-player.css" || ! -s "$ASSET_DIR/asciinema-player.min.js" ]]; then
  echo "failed to extract asciinema-player assets" >&2
  exit 1
fi

echo "Packing vendored build inputs..."
rm -f "$VENDOR_TARBALL"
tar -cJf "$VENDOR_TARBALL" \
  vendor \
  internal/server/assets/asciinema-player.version \
  internal/server/assets/asciinema-player.css \
  internal/server/assets/asciinema-player.min.js

rm -rf "$ROOT_DIR/vendor"
rm -f "$ASSET_DIR/asciinema-player.css" "$ASSET_DIR/asciinema-player.min.js"

echo "Wrote:"
echo "  $VENDOR_TARBALL"
