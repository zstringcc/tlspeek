# tlspeek

Capture this machine's real Node.js TLS ClientHello as portable JSON.

**One command, no install, no file write — JSON to stdout.**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/run.sh)
```

## What it does

- Spawns a Node `tls.connect()` against a local listener.
- Reads the raw ClientHello bytes (~1500 B) — does **not** terminate TLS.
- Parses the fields a fingerprint mocking stack needs (`cipher_suites`, `curves`, `point_formats`, `signature_algorithms`, `alpn`, `supported_versions`, `key_share_groups`, `psk_modes`, extensions order, GREASE flag).
- Outputs JSON on **stdout**, all diagnostics on **stderr**.

Output is **this machine's actual OpenSSL/BoringSSL stack behavior** — the real fingerprint you can replay elsewhere. ALPN + SNI are pinned to match real Claude Code CLI (`[h2, http/1.1]` + `api.anthropic.com`) so the captured fingerprint is in the same "shape" as a real CC client without you needing CC installed.

## Why

Different OSes / Node versions produce different TLS ClientHellos. If you're building a fingerprint mocking stack ([utls](https://github.com/refraction-networking/utls), [curl-impersonate](https://github.com/lwthiker/curl-impersonate), etc.), you need a pool of **real** captured profiles to replay — not synthetic ones. This tool gets you one profile per environment in a single command.

## Prerequisites

- `go ≥ 1.22`
- `node ≥ 18`
- `curl`

(That's all. No `git`, no `npm`, no admin rights.)

## Usage

### Public repo
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zstringcc/tlspeek/main/run.sh)
```

### Private repo / behind token
```bash
GITHUB_TOKEN=ghp_xxx bash <(curl -fsSL \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/zstringcc/tlspeek/contents/run.sh)
```

### Install as a persistent binary
```bash
# For private repo: setup once
export GOPRIVATE=github.com/zstringcc/*

go install github.com/zstringcc/tlspeek@latest
tlspeek
```

### Common pipe idioms

```bash
# macOS — straight to clipboard
bash <(curl -fsSL .../run.sh) | pbcopy

# Linux — clipboard
bash <(curl -fsSL .../run.sh) | xclip -sel clip

# To a file
bash <(curl -fsSL .../run.sh) > profile.json

# Filter / verify with jq
bash <(curl -fsSL .../run.sh) | jq '{ name, cipher_count: (.cipher_suites|length), alpn: .alpn_protocols }'

# Capture and POST to a profile-receiving API in one shot
bash <(curl -fsSL .../run.sh) | \
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

Field names are snake_case to match common TLS profile schemas. GREASE values are stripped from `cipher_suites` / `curves` / `extensions` — set `enable_grease: true` if your consumer re-injects GREASE.

JA3 + simplified JA4 hashes are printed on **stderr** for human inspection (so they don't pollute the JSON output).

## How it works

1. **Listen on a random localhost port.** Just a `net.Listen("tcp", "127.0.0.1:0")`, no TLS setup.
2. **Spawn Node.** `node -e <inline script>` with `tls.connect()` to our listener, explicitly setting ALPN `[h2, http/1.1]` + SNI `api.anthropic.com` + `minVersion: TLSv1.2`. `NODE_TLS_REJECT_UNAUTHORIZED=0` so Node doesn't bail on the cert it never receives.
3. **Read first TLS record** (5-byte header + handshake message ≈ 1.5 KB total) — do not respond. Close connection.
4. **Parse ClientHello.** Manual TLS 1.3 spec parser for handshake header / random / session_id / cipher_suites / compression_methods / extensions. Extensions parsed: server_name (0), supported_groups (10), ec_point_formats (11), signature_algorithms (13), ALPN (16), supported_versions (43), psk_key_exchange_modes (45), key_share (51). GREASE detected via RFC 8701 pattern.
5. **Emit.** JSON to stdout, summary + JA3/JA4 to stderr.

No network egress, no files written, no privileged operations.

## Multi-machine workflow

If you need profiles from many environments (different OSes / Node versions):

```bash
# Machine 1 — macOS arm64 + Node 24
bash <(curl -fsSL .../run.sh) > macos-arm64-node24.json

# Machine 2 — Linux x64 + Node 22
bash <(curl -fsSL .../run.sh) > linux-x64-node22.json

# Machine 3 — WSL Ubuntu + Node 20
bash <(curl -fsSL .../run.sh) > wsl-ubuntu-node20.json

# ... up to your target pool size
```

Each run takes ~2 seconds. Collect 5-10+ profiles, feed them into your fingerprint mocking pool, distribute requests across them.

## Known limitations

- **ALPN is hardcoded `[h2, http/1.1]`** to match real Claude Code CLI behavior. If you need other ALPN lists, edit `nodeFetchScript` in `main.go`.
- **JA4 is approximate** — not strictly per the [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) spec. JA4 is shown on stderr only for human verification; it's not in the JSON output.
- **Same machine, same fingerprint.** Node's underlying TLS stack is deterministic, so running this tool twice on the same machine gives identical profiles (modulo random bytes / session IDs which we strip anyway). Run on different machines to get diversity.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Node.js is required but not found in PATH` | Node not installed or PATH missing | Install Node ≥ 18, restart shell |
| `timeout waiting for Node to connect` | Node spawn failed or firewall blocking localhost | Check `node -e "console.log('ok')"`; disable local firewall temporarily |
| `not a handshake record` | Node connected with non-TLS (shouldn't happen — script forces `tls.connect()`) | File an issue with `node --version` output |
| HTTP 404 fetching main.go | Repo is private and no GITHUB_TOKEN set | Set `GITHUB_TOKEN` env or fork to a public repo |

## License

MIT. See [LICENSE](./LICENSE).
