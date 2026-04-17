# rb2-tty

Web-based viewer for Red Baron 2 TTY session recordings stored in S3/MinIO. It stitches chunked asciinema recordings in timestamp order, supports both plain `.cast.lzma` chunks and encrypted `.cast.age` chunks, and serves them through a browser interface with search, sorting, and GIF/MOV export.

## Prerequisites

- Go 1.24.4
- GCC (required by go-sqlite3, which uses CGO)
- An SSH private key that corresponds to the age recipient used to encrypt the recordings, if the bucket contains encrypted chunks

### Optional (for GIF/MOV export)

- [agg](https://github.com/asciinema/agg) -- asciinema GIF generator. Install the prebuilt binary:

```
curl -sL https://github.com/asciinema/agg/releases/download/v1.7.0/agg-x86_64-unknown-linux-gnu -o /tmp/agg
chmod +x /tmp/agg
sudo mv /tmp/agg /usr/local/bin/agg
```

- `ffmpeg` -- required for MOV export (GIF-to-H.264 conversion). On Fedora: `sudo dnf install ffmpeg-free`
- A monospace font for `agg` rendering (e.g. DejaVu Sans Mono): `sudo dnf install dejavu-sans-mono-fonts`

## Build

```
./build.sh
```

This is the normal online build. It resolves Go modules from the network and serves `asciinema-player` from jsDelivr at runtime.

The `fts5` build tag is included automatically because SQLite full-text search requires it.

## Generate vendored build inputs

Generate the offline build inputs:

```
./vendor.sh
```

This produces:

- `vendor.tar.xz`

`vendor.tar.xz` contains the Go `vendor/` tree plus the generated `asciinema-player` CSS/JS needed by the `vendored` build tag.

## Build from vendored inputs

```
./vendored-build.sh
```

This performs an offline Go build with `-mod=vendor` and the `vendored` build tag.

`vendored-build.sh` extracts `vendor.tar.xz`, builds, and then removes the unpacked vendored files.

## Docker

Build and run from a vendored artifact directory:

```sh
docker compose up --build
```

The Docker image expects `./vendor.sh` to have been run first so that `vendor.tar.xz` exists in the build context.

## Run

```
./rb2-web \
  -endpoint http://44.207.7.176:9000 \
  -bucket rb2-tty \
  -region us-east-1 \
  -access-key YOUR_ACCESS_KEY \
  -secret-key YOUR_SECRET_KEY \
  -path-style

# Add -key only when the bucket contains encrypted .cast.age chunks:
#   -key /path/to/ssh/private/key
```

Normal builds use jsDelivr for `asciinema-player`. Vendored builds embed generated local player assets and do not require network access after Go is installed.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-endpoint` | (required) | S3/MinIO endpoint URL |
| `-bucket` | (required) | S3 bucket name |
| `-region` | (required) | S3 region |
| `-access-key` | (required) | S3 access key |
| `-secret-key` | (required) | S3 secret key |
| `-key` | optional | Path to SSH private key for decrypting encrypted chunks |
| `-path-style` | `false` | Use path-style S3 URLs (required for MinIO) |
| `-port` | `8080` | HTTP server port |
| `-db` | `rb2tty.db` | Path to SQLite database file |

The server syncs sessions from S3 every 30 seconds, orders session chunks by their embedded chunk timestamps, and stores stitched cast data in the local SQLite cache database. Open `http://localhost:8080` in a browser.

## Project layout

```
cmd/server/main.go          Entry point, flag parsing
internal/models/session.go  Session struct and display helpers
internal/s3client/          S3/MinIO listing, chunk metadata parsing, ordering
internal/decrypt/           Age decryption + LZMA decompression
internal/castutil/          Cast file text extraction, user detection, duration parsing
internal/store/             SQLite persistence with FTS5 search
internal/server/            HTTP handlers, HTML templates, export logic
```
