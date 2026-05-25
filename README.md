# tlspeek

Capture this machine's real Node.js TLS ClientHello as portable JSON.

**One command. Pure Node. No install. No compile.**

### Default — print YAML (paste into sub2api admin "粘贴 YAML 配置")
```bash
curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js | node
```

### Upload straight to sub2api admin — zero copy-paste
```bash
SUB2API_URL=http://YOUR-SUB2API:3004 \
SUB2API_TOKEN=eyJh... \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js | node'
```
Or with email+password (auto-login):
```bash
SUB2API_URL=http://YOUR-SUB2API:3004 \
SUB2API_EMAIL=admin@sub2api.local \
SUB2API_PASSWORD=... \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js | node'
```
Output (stderr only):
```
✓ Uploaded to sub2api: id=3 name=darwin_arm64_node_v24
```

## What it does

- Opens a local `net.createServer()` on a random port.
- Calls `tls.connect()` in the same process targeting that listener — with ALPN `[h2, http/1.1]` + SNI `api.anthropic.com` (real Claude Code CLI shape).
- Reads the raw ClientHello bytes (~1.5 KB), parses every field a fingerprint-mocking stack needs (`cipher_suites` / `curves` / `point_formats` / `signature_algorithms` / `alpn` / `supported_versions` / `key_share_groups` / `psk_modes` / extensions order / GREASE flag).
- Strips GREASE values (consumers re-inject via `enable_grease` flag).
- Emits JSON on **stdout**, diagnostics + JA3/JA4 hashes on **stderr**.

The captured fingerprint is **this machine's actual OpenSSL/BoringSSL stack behavior** — the real one you can replay elsewhere.

## Prerequisites

- `node ≥ 18` ← that's it. No Go, no Python, no npm install.
- `curl` to pull the script.

## Usage

### Public repo (most cases)
```bash
curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/tlspeek.js | node
```

### Private repo / need a token
```bash
GITHUB_TOKEN=ghp_xxx bash <(curl -fsSL \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/zstringcc/tlspeek/contents/run.sh)
```

### Common pipe patterns

```bash
# Only JSON, hide progress info
curl -fsSL .../tlspeek.js | node 2>/dev/null

# Straight to clipboard — macOS
curl -fsSL .../tlspeek.js | node 2>/dev/null | pbcopy

# Straight to clipboard — Linux
curl -fsSL .../tlspeek.js | node 2>/dev/null | xclip -sel clip

# Write to a file
curl -fsSL .../tlspeek.js | node 2>/dev/null > profile.json

# Filter with jq
curl -fsSL .../tlspeek.js | node 2>/dev/null | jq '{name, alpn_protocols, cipher_count: (.cipher_suites|length)}'

# Capture and POST to a TLS-profile-receiving API, no file write
curl -fsSL .../tlspeek.js | node 2>/dev/null | \
  curl -X POST https://your-api.example/v1/tls-profiles \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d @-
```

## Output schema

```json
{
  "name": "darwin_arm64_node_v24",
  "description": "Captured on darwin/arm64 Node 24.14.0 (2026-05-25)",
  "enable_grease": false,
  "cipher_suites": [4866, 4867, 4865, 49199, 49195, ...],
  "curves": [29, 23, 24],
  "point_formats": [0],
  "signature_algorithms": [1027, 2052, 1025, ...],
  "alpn_protocols": ["h2", "http/1.1"],
  "supported_versions": [772, 771],
  "key_share_groups": [29],
  "psk_modes": [1],
  "extensions": [65281, 0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51]
}
```

Field names are snake_case to match common TLS profile schemas. JA3 + simplified JA4 hashes are printed on **stderr** for human inspection (not in the JSON output).

## How it works

1. `net.createServer()` on a random `127.0.0.1` port — no TLS termination.
2. `tls.connect()` in the same Node process, explicitly setting:
   - `ALPNProtocols: ['h2', 'http/1.1']` (real Claude Code CLI default)
   - `servername: 'api.anthropic.com'` (so server_name extension is non-trivial)
   - `minVersion: 'TLSv1.2'`
   - `rejectUnauthorized: false` (we never actually serve a cert)
3. Server side accumulates the first TCP chunks until a full TLS record is buffered, then closes.
4. Parse ClientHello (TLS 1.3 spec): record header → handshake message → cipher_suites / compression_methods / extensions (server_name(0), supported_groups(10), ec_point_formats(11), signature_algorithms(13), ALPN(16), supported_versions(43), psk_key_exchange_modes(45), key_share(51)). GREASE detected via RFC 8701.
5. Emit JSON to stdout, summary + JA3/JA4 to stderr.

No network egress. No files written. No privileged operations.

## Multi-machine workflow

```bash
# Machine 1 — macOS arm64 + Node 24
curl -fsSL .../tlspeek.js | node 2>/dev/null > mac-arm64-node24.json

# Machine 2 — Linux x64 + Node 22
curl -fsSL .../tlspeek.js | node 2>/dev/null > linux-x64-node22.json

# Machine 3 — Windows WSL + Node 20
curl -fsSL .../tlspeek.js | node 2>/dev/null > wsl-node20.json

# Continue across 5-10 environments — total cost: ~2 seconds per machine
```

Each run is identical for the same machine (Node TLS stack is deterministic). Variety comes from running across different OSes + Node versions.

## Known limitations

- **ALPN pinned to `[h2, http/1.1]`** to match real Claude Code CLI. Edit the `ALPNProtocols` line in `tlspeek.js` if you need different.
- **JA4 approximation** — not strictly per the [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) spec. Shown on stderr for human verification only; not in JSON output.
- **Deterministic** — same machine + same Node version always produces the same JSON. Diversity must come from running on different environments.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `command not found: node` | Node not installed | Install Node ≥ 18 from https://nodejs.org |
| `timeout waiting for ClientHello` | OS firewall blocking localhost | Temporarily disable local firewall |
| `not a handshake record` | Something else hit your port first | Re-run (random port avoids collision) |
| `HTTP 404` fetching tlspeek.js | Private repo + no token | Set `GITHUB_TOKEN` env and use run.sh wrapper |

## License

MIT. See [LICENSE](./LICENSE).
