#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "go is required on PATH" >&2
  exit 1
fi

GO_VERSION="$(go env GOVERSION)"
if [[ "$GO_VERSION" != "go1.24.4" ]]; then
  echo "warning: expected Go 1.24.4, found $GO_VERSION" >&2
fi

CGO_ENABLED=1 go build -tags fts5 -o rb2-web ./cmd/server

echo "Built $ROOT_DIR/rb2-web"
