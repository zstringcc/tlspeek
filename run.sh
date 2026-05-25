#!/usr/bin/env bash
# tlspeek/run.sh — one-shot wrapper: download main.go + go run + JSON to stdout.
#
# Usage (public repo):
#   bash <(curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/run.sh)
#
# Private repo / need token:
#   GITHUB_TOKEN=ghp_xxx bash <(curl -fsSL \
#     -H "Authorization: Bearer $GITHUB_TOKEN" \
#     -H "Accept: application/vnd.github.raw" \
#     https://api.github.com/repos/zstringcc/tlspeek/contents/run.sh)
#
# Override source URL (e.g. for forks / mirrors / offline):
#   TLSPEEK_RAW_BASE=https://my-mirror/tlspeek bash <(curl -fsSL ...)
#
# Requires: go ≥ 1.22, node ≥ 18, curl. (No git.)

set -euo pipefail

RAW_BASE_DEFAULT="https://raw.githubusercontent.com/zstringcc/tlspeek/main"
RAW_BASE="${TLSPEEK_RAW_BASE:-$RAW_BASE_DEFAULT}"

# Prereq checks
for cmd in go node curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FATAL: $cmd not in PATH" >&2; exit 1; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Fetch main.go (with optional token for private repos)
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

echo "[run.sh] Fetching main.go from $RAW_BASE ..." >&2
fetch "$RAW_BASE/main.go" "$TMP/main.go"

# Minimal go.mod (main.go uses only stdlib)
cat > "$TMP/go.mod" <<'EOF'
module x
go 1.22
EOF

# Run — JSON goes to stdout, all diagnostics to stderr.
# Caller can pipe / redirect freely: ... | pbcopy / > out.json / | jq / | curl -d @-
cd "$TMP"
exec go run .
