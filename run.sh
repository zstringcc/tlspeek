#!/usr/bin/env bash
# tlspeek/run.sh — wrapper for GITHUB_TOKEN (private repo) or custom source URL.
#
# For PUBLIC repos you don't need this — just run:
#   curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js | node
#
# For PRIVATE repos:
#   GITHUB_TOKEN=ghp_xxx bash <(curl -fsSL \
#     -H "Authorization: Bearer $GITHUB_TOKEN" \
#     -H "Accept: application/vnd.github.raw" \
#     https://api.github.com/repos/zstringcc/tlspeek/contents/run.sh)
#
# Override source (forks / mirrors / offline):
#   TLSPEEK_RAW_BASE=https://my-mirror/tlspeek bash <(curl ...)
#
# Requires: node ≥ 18, curl. (No git, no go, no compile.)

set -euo pipefail

RAW_BASE_DEFAULT="https://raw.githubusercontent.com/zstringcc/tlspeek/main"
RAW_BASE="${TLSPEEK_RAW_BASE:-$RAW_BASE_DEFAULT}"

for cmd in node curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FATAL: $cmd not in PATH" >&2; exit 1; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {
  local url="$1" out="$2"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    if [[ "$url" == *"api.github.com"* ]]; then
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github.raw" "$url" -o "$out"
    else
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$url" -o "$out"
    fi
  else
    curl -fsSL "$url" -o "$out"
  fi
}

echo "[run.sh] Fetching tlspeek.js from $RAW_BASE ..." >&2
fetch "$RAW_BASE/tlspeek.js" "$TMP/tlspeek.js"

exec node "$TMP/tlspeek.js"
