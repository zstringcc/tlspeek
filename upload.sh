#!/usr/bin/env bash
# tlspeek/upload.sh — one-shot capture + direct upload to a sub2api admin.
#
# Usage (single command, paste-friendly):
#   bash <(curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/upload.sh)
#
# The script:
#   1. Reads SUB2API_URL / SUB2API_EMAIL / SUB2API_PASSWORD from env
#      (falling back to interactive prompts for any not set).
#   2. curl-fetches tlspeek.js to a tmp dir.
#   3. exec node with those env vars — node uploads to sub2api admin,
#      prints `✓ Uploaded to sub2api: id=N name=...` and exits 0.
#
# No `bash -c '...'` quoting, no `|` at line-end — robust against terminals
# that line-wrap on paste.

set -euo pipefail

# ----- defaults (override via env if you have a different deployment) -----
: "${SUB2API_URL:=http://64.186.231.54:3004}"
: "${SUB2API_EMAIL:=admin@sub2api.local}"

# ----- prompt password if not set -----
if [ -z "${SUB2API_PASSWORD:-}" ]; then
  read -srp "sub2api password for ${SUB2API_EMAIL}: " SUB2API_PASSWORD
  echo >&2
fi

# ----- prereq check -----
for cmd in node curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FATAL: $cmd not in PATH" >&2; exit 1; }
done

# ----- fetch + run -----
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js -o "$TMP/tlspeek.js"

export SUB2API_URL SUB2API_EMAIL SUB2API_PASSWORD
exec node "$TMP/tlspeek.js"
