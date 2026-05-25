// tlspeek — capture this machine's Node.js TLS ClientHello as portable JSON.
//
// One-shot CLI: spawn a local Node tls.connect against our own listener,
// read the raw ClientHello bytes, parse all the fields a fingerprint-mocking
// stack (utls, curl-impersonate, etc.) needs, and emit the result as JSON
// on stdout. All diagnostics go to stderr — pipe friendly.
//
// Use cases:
//   - Collect diverse real Node TLS fingerprints from many OS / Node
//     versions for replay (anti-fingerprinting / scraping / testing).
//   - Verify your TLS stack matches a known-good environment.
//   - Feed the JSON straight into a fingerprint mocking library's profile
//     format with minor adapter.
//
// How it works:
//  1. Listen on a random 127.0.0.1 port (no real TLS termination).
//  2. Spawn `node -e <inline script>` that opens tls.connect() to our
//     listener with the ALPN list real Claude Code CLI sends: [h2, http/1.1]
//     and SNI api.anthropic.com (so server_name extension is non-trivial).
//     All OTHER fields (cipher_suites, curves, extensions, sigalgs,
//     key_share, etc.) are chosen by this machine's actual OpenSSL/BoringSSL
//     stack — i.e. the real fingerprint we want to capture.
//  3. Accept the TCP connection, read the TLS record + ClientHello bytes
//     (~1500 bytes), then close. No TLS handshake response.
//  4. Parse 8 fields a generic TLS profile schema needs:
//     cipher_suites / curves / point_formats / signature_algorithms /
//     alpn / supported_versions / key_share_groups / psk_modes
//     plus extensions order and GREASE presence flag.
//  5. Strip GREASE values (consumers re-inject via enable_grease).
//  6. Compute JA3 + simplified JA4 hashes for human verification.
//  7. Emit JSON to stdout.
//
// Output schema is intentionally compatible with common fingerprint mocking
// profile formats (sub2api / refraction-networking utls profile / etc.).
//
// Run: go run .
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"crypto/sha256"
)

// =============================================================================
// Output schema
// =============================================================================

// Profile is the JSON payload describing the captured TLS ClientHello.
// Field names follow common TLS profile schemas (snake_case) so the JSON
// is easy to consume by mocking libraries / admin APIs.
type Profile struct {
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	EnableGREASE        *bool    `json:"enable_grease,omitempty"`
	CipherSuites        []uint16 `json:"cipher_suites,omitempty"`
	Curves              []uint16 `json:"curves,omitempty"`
	PointFormats        []uint16 `json:"point_formats,omitempty"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	ALPNProtocols       []string `json:"alpn_protocols,omitempty"`
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`
	KeyShareGroups      []uint16 `json:"key_share_groups,omitempty"`
	PSKModes            []uint16 `json:"psk_modes,omitempty"`
	Extensions          []uint16 `json:"extensions,omitempty"`
}

// =============================================================================
// TLS record + ClientHello parsing
// =============================================================================

type clientHello struct {
	cipherSuites        []uint16
	curves              []uint16
	pointFormats        []uint16
	signatureAlgorithms []uint16
	alpnProtocols       []string
	supportedVersions   []uint16
	keyShareGroups      []uint16
	pskModes            []uint16
	extensionsOrder     []uint16
	hasGREASE           bool
	serverName          string
	clientHelloRaw      []byte // for JA3/JA4 hash
}

// readTLSRecord reads exactly one TLS record from conn.
// Returns the handshake message bytes (after the 5-byte TLS record header).
func readTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read TLS record header: %w", err)
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record: type=0x%02x", header[0])
	}
	// header[1..3] = version (e.g. 0x0301 for TLS 1.0 in record header)
	length := binary.BigEndian.Uint16(header[3:5])
	if length == 0 || length > 16384 {
		return nil, fmt.Errorf("invalid record length: %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read TLS record body: %w", err)
	}
	return body, nil
}

func parseClientHello(handshake []byte) (*clientHello, error) {
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello (type=0x%02x)", handshake[0])
	}
	// 1 byte type + 3 byte length
	msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if 4+msgLen > len(handshake) {
		return nil, fmt.Errorf("ClientHello truncated: declared %d, have %d", msgLen, len(handshake)-4)
	}
	body := handshake[4 : 4+msgLen]
	ch := &clientHello{clientHelloRaw: handshake}
	r := &reader{buf: body}

	// legacy_version (2 bytes)
	if _, err := r.readUint16(); err != nil {
		return nil, fmt.Errorf("read legacy_version: %w", err)
	}
	// random (32 bytes)
	if _, err := r.readBytes(32); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	// session_id (variable, 1-byte length)
	sidLen, err := r.readUint8()
	if err != nil {
		return nil, fmt.Errorf("read session_id length: %w", err)
	}
	if _, err := r.readBytes(int(sidLen)); err != nil {
		return nil, fmt.Errorf("read session_id: %w", err)
	}
	// cipher_suites (2-byte length)
	csLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("read cipher_suites length: %w", err)
	}
	csBytes, err := r.readBytes(int(csLen))
	if err != nil {
		return nil, fmt.Errorf("read cipher_suites: %w", err)
	}
	for i := 0; i+2 <= len(csBytes); i += 2 {
		cs := binary.BigEndian.Uint16(csBytes[i:])
		ch.cipherSuites = append(ch.cipherSuites, cs)
		if isGREASE(cs) {
			ch.hasGREASE = true
		}
	}
	// compression_methods (1-byte length)
	cmLen, err := r.readUint8()
	if err != nil {
		return nil, fmt.Errorf("read compression_methods length: %w", err)
	}
	if _, err := r.readBytes(int(cmLen)); err != nil {
		return nil, fmt.Errorf("read compression_methods: %w", err)
	}
	// extensions (2-byte length)
	if r.remaining() == 0 {
		// no extensions (TLS 1.0 / 1.1)
		return ch, nil
	}
	extLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("read extensions length: %w", err)
	}
	extBytes, err := r.readBytes(int(extLen))
	if err != nil {
		return nil, fmt.Errorf("read extensions: %w", err)
	}
	parseExtensions(extBytes, ch)
	return ch, nil
}

func parseExtensions(extBytes []byte, ch *clientHello) {
	r := &reader{buf: extBytes}
	for r.remaining() > 0 {
		extType, err := r.readUint16()
		if err != nil {
			return
		}
		extDataLen, err := r.readUint16()
		if err != nil {
			return
		}
		extData, err := r.readBytes(int(extDataLen))
		if err != nil {
			return
		}
		ch.extensionsOrder = append(ch.extensionsOrder, extType)
		if isGREASE(extType) {
			ch.hasGREASE = true
		}
		switch extType {
		case 0: // server_name
			ch.serverName = parseSNI(extData)
		case 10: // supported_groups (curves)
			ch.curves = parseUint16ListWithLen2(extData)
		case 11: // ec_point_formats
			ch.pointFormats = parseUint8ListWithLen1AsUint16(extData)
		case 13: // signature_algorithms
			ch.signatureAlgorithms = parseUint16ListWithLen2(extData)
		case 16: // ALPN
			ch.alpnProtocols = parseALPN(extData)
		case 43: // supported_versions
			ch.supportedVersions = parseUint16ListWithLen1(extData)
		case 45: // psk_key_exchange_modes
			ch.pskModes = parseUint8ListWithLen1AsUint16(extData)
		case 51: // key_share
			ch.keyShareGroups = parseKeyShareGroups(extData)
		}
	}
}

// =============================================================================
// Extension data parsers
// =============================================================================

func parseSNI(data []byte) string {
	r := &reader{buf: data}
	listLen, err := r.readUint16()
	if err != nil || int(listLen) > r.remaining() {
		return ""
	}
	for r.remaining() >= 3 {
		nameType, _ := r.readUint8()
		nameLen, _ := r.readUint16()
		nameBytes, err := r.readBytes(int(nameLen))
		if err != nil {
			return ""
		}
		if nameType == 0 { // host_name
			return string(nameBytes)
		}
	}
	return ""
}

// parseUint16ListWithLen2: 2-byte length prefix, then list of uint16.
func parseUint16ListWithLen2(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := binary.BigEndian.Uint16(data[:2])
	if int(listLen)+2 > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen/2)
	for i := 2; i+2 <= 2+int(listLen); i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:]))
	}
	return out
}

// parseUint16ListWithLen1: 1-byte length prefix, list of uint16 (e.g. supported_versions).
func parseUint16ListWithLen1(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if listLen+1 > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen/2)
	for i := 1; i+2 <= 1+listLen; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:]))
	}
	return out
}

// parseUint8ListWithLen1AsUint16: 1-byte length prefix, list of uint8.
// Promote each to uint16 so it fits the TLS profile schema.
func parseUint8ListWithLen1AsUint16(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if listLen+1 > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen)
	for i := 1; i < 1+listLen; i++ {
		out = append(out, uint16(data[i]))
	}
	return out
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := binary.BigEndian.Uint16(data[:2])
	r := &reader{buf: data[2 : 2+int(listLen)]}
	var out []string
	for r.remaining() > 0 {
		nameLen, err := r.readUint8()
		if err != nil {
			return out
		}
		nameBytes, err := r.readBytes(int(nameLen))
		if err != nil {
			return out
		}
		out = append(out, string(nameBytes))
	}
	return out
}

func parseKeyShareGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := binary.BigEndian.Uint16(data[:2])
	r := &reader{buf: data[2 : 2+int(listLen)]}
	var out []uint16
	for r.remaining() >= 4 {
		group, _ := r.readUint16()
		keLen, _ := r.readUint16()
		if _, err := r.readBytes(int(keLen)); err != nil {
			return out
		}
		out = append(out, group)
	}
	return out
}

// =============================================================================
// Small bytes reader
// =============================================================================

type reader struct {
	buf []byte
	pos int
}

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) readUint8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, io.EOF
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, io.EOF
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, io.EOF
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

// =============================================================================
// GREASE detection (RFC 8701: 0x?A?A pattern where both nibbles equal)
// =============================================================================

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && (v>>8)&0xff == v&0xff
}

// stripGREASE returns the list with GREASE values removed.
// Useful for emitting a "clean" profile that consumers can replay (most
// mocking libraries re-inject GREASE based on the enable_grease flag).
func stripGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// =============================================================================
// JA3 + JA4 hash
// =============================================================================

// ja3 = MD5(version,ciphers,extensions,curves,point_formats) but we use SHA256
// for transparency. For interop verification we also print canonical JA3 string.
func ja3String(ch *clientHello) string {
	var parts [5]string
	parts[0] = "771" // TLS 1.2 in legacy_version
	parts[1] = joinUint16Dash(stripGREASE(ch.cipherSuites))
	parts[2] = joinUint16Dash(stripGREASE(ch.extensionsOrder))
	parts[3] = joinUint16Dash(stripGREASE(ch.curves))
	parts[4] = joinUint16Dash(ch.pointFormats)
	return strings.Join(parts[:], ",")
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ja4 = t13d{cipherCount}{extCount}{firstALPN}_<cipher-sha256-prefix>_<ext+sigalgs-sha256-prefix>
// Simplified spec. Real JA4 spec: https://github.com/FoxIO-LLC/ja4
// We output a reasonable approximation. Real JA4 distinguishes h2 vs h1 in
// the first segment letter.
func ja4String(ch *clientHello) string {
	cipherCount := len(stripGREASE(ch.cipherSuites))
	extCount := len(stripGREASE(ch.extensionsOrder))
	firstALPN := "00"
	if len(ch.alpnProtocols) > 0 {
		alpn := ch.alpnProtocols[0]
		if len(alpn) >= 2 {
			firstALPN = alpn[0:1] + alpn[len(alpn)-1:]
		}
	}
	cipherSegment := truncate(sha256Hex(joinUint16Dash(stripGREASE(ch.cipherSuites))), 12)
	extSegment := truncate(sha256Hex(joinUint16Dash(stripGREASE(ch.extensionsOrder))+"_"+joinUint16Dash(ch.signatureAlgorithms)), 12)
	return fmt.Sprintf("t13d%02d%02d%s_%s_%s", cipherCount, extCount, firstALPN, cipherSegment, extSegment)
}

func joinUint16Dash(list []uint16) string {
	if len(list) == 0 {
		return ""
	}
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(out, "-")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// =============================================================================
// Environment detection
// =============================================================================

type envInfo struct {
	OS          string
	Arch        string
	NodeVersion string
	CCVersion   string
}

func detectEnv() envInfo {
	info := envInfo{OS: runtime.GOOS, Arch: runtime.GOARCH}

	// node --version
	if out, err := exec.Command("node", "--version").Output(); err == nil {
		info.NodeVersion = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	}

	// claude --version (if present)
	if out, err := exec.Command("claude", "--version").Output(); err == nil {
		// "claude-cli 2.1.150 (Claude Code)" or similar
		line := strings.TrimSpace(string(out))
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.Contains(f, ".") && f[0] >= '0' && f[0] <= '9' {
				info.CCVersion = f
				break
			}
		}
	}
	return info
}

// =============================================================================
// Main flow
// =============================================================================

// nodeFetchScript opens a TLS connection to our listener with the **exact**
// ALPN / SNI / minVersion that real Claude Code (undici fetch with allowH2)
// sends to api.anthropic.com:
//
//   - ALPN: ["h2", "http/1.1"]  (real Claude Code CLI default)
//   - SNI:  api.anthropic.com   (so server_name extension carries that host)
//   - minVersion: TLSv1.2       (modern Node default)
//
// We bypass undici/fetch because:
//  1. Node's built-in fetch silently downgrades to h1 only on localhost,
//     even with `undici.Agent({allowH2:true})` — yields wrong ALPN.
//  2. tls.connect() lets us pin the exact ALPN list real CC sends.
//
// All OTHER fingerprint fields (cipher_suites, curves, extensions,
// signature_algorithms, key_share, etc.) are still chosen by Node's
// underlying OpenSSL/BoringSSL stack — i.e. THIS machine's real fingerprint.
// That's what we want to capture.
const nodeFetchScript = `
const tls = require('tls');
const url = new URL(process.env.TARGET_URL);
const socket = tls.connect({
  host: url.hostname,
  port: parseInt(url.port, 10),
  servername: 'api.anthropic.com',
  ALPNProtocols: ['h2', 'http/1.1'],
  minVersion: 'TLSv1.2',
  rejectUnauthorized: false,
}, () => {
  // ClientHello already sent — close immediately, we don't care about reply
  socket.end();
});
socket.on('error', () => {});
setTimeout(() => process.exit(0), 1500);
`

func main() {
	// 1. Start TCP listener on a random localhost port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	fmt.Fprintf(os.Stderr, "[1/4] Listening on 127.0.0.1:%d ...\n", port)

	// 2. Detect environment.
	env := detectEnv()
	if env.NodeVersion == "" {
		fail("Node.js is required but not found in PATH.\n"+
			"Install Node ≥ 18 (https://nodejs.org) and retry.\n"+
			"OS=%s/%s", env.OS, env.Arch)
	}
	fmt.Fprintf(os.Stderr, "[2/4] Detected: %s/%s, Node %s", env.OS, env.Arch, env.NodeVersion)
	if env.CCVersion != "" {
		fmt.Fprintf(os.Stderr, ", Claude Code %s", env.CCVersion)
	}
	fmt.Fprintln(os.Stderr)

	// 3. Accept once with a timeout.
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- accepted{conn, err}
	}()

	// 4. Spawn node in parallel to trigger the connection.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "-e", nodeFetchScript)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TARGET_URL=https://127.0.0.1:%d/probe", port),
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fail("spawn node: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[3/4] Triggered Node undici fetch (PID %d) ...\n", cmd.Process.Pid)
	go func() { _ = cmd.Wait() }()

	// 5. Wait for connection.
	var conn net.Conn
	select {
	case a := <-acceptCh:
		if a.err != nil {
			fail("accept: %v", a.err)
		}
		conn = a.conn
	case <-time.After(10 * time.Second):
		fail("timeout waiting for Node to connect to local listener")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 6. Read TLS record + ClientHello.
	hsBytes, err := readTLSRecord(conn)
	if err != nil {
		fail("read TLS record: %v", err)
	}
	ch, err := parseClientHello(hsBytes)
	if err != nil {
		fail("parse ClientHello: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[4/4] Captured ClientHello: %d bytes, %d ciphers, %d ext, ALPN=%v\n",
		len(hsBytes), len(ch.cipherSuites), len(ch.extensionsOrder), ch.alpnProtocols)

	// 7. Emit profile + hashes.
	emitOutput(ch, env)
}

func emitOutput(ch *clientHello, env envInfo) {
	cleanCiphers := stripGREASE(ch.cipherSuites)
	cleanCurves := stripGREASE(ch.curves)
	cleanExts := stripGREASE(ch.extensionsOrder)
	// Keep sigalgs/key_share/psk_modes/supported_versions as-is — these
	// rarely contain GREASE in practice, and TLS profile schema treats
	// them as exact arrays.

	name := profileName(env)
	desc := fmt.Sprintf("Captured on %s/%s Node %s",
		env.OS, env.Arch, env.NodeVersion)
	if env.CCVersion != "" {
		desc += fmt.Sprintf(" + Claude Code %s", env.CCVersion)
	}
	desc += fmt.Sprintf(" (%s)", time.Now().Format("2006-01-02"))

	enableGREASE := ch.hasGREASE
	profile := Profile{
		Name:                name,
		Description:         desc,
		EnableGREASE:        &enableGREASE,
		CipherSuites:        cleanCiphers,
		Curves:              cleanCurves,
		PointFormats:        ch.pointFormats,
		SignatureAlgorithms: ch.signatureAlgorithms,
		ALPNProtocols:       ch.alpnProtocols,
		SupportedVersions:   ch.supportedVersions,
		KeyShareGroups:      stripGREASE(ch.keyShareGroups),
		PSKModes:            ch.pskModes,
		Extensions:          cleanExts,
	}

	jsonBytes, _ := json.MarshalIndent(profile, "", "  ")

	// Summary 全部到 stderr,不污染 stdout
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "===== Profile summary =====")
	fmt.Fprintf(os.Stderr, "  Name:           %s\n", name)
	fmt.Fprintf(os.Stderr, "  GREASE present: %v\n", ch.hasGREASE)
	fmt.Fprintf(os.Stderr, "  SNI:            %s\n", ch.serverName)
	fmt.Fprintf(os.Stderr, "  JA3 string:     %s\n", truncate(ja3String(ch), 80))
	fmt.Fprintf(os.Stderr, "  JA3 hash(sha):  %s\n", sha256Hex(ja3String(ch))[:32])
	fmt.Fprintf(os.Stderr, "  JA4 (approx):   %s\n", ja4String(ch))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "===== Profile JSON (stdout — pipe to pbcopy / jq / curl) =====")

	// JSON 唯一进 stdout — 可被 pipe / 重定向 / 复制
	fmt.Println(string(jsonBytes))
}

func profileName(env envInfo) string {
	osPart := env.OS
	if osPart == "darwin" {
		osPart = "darwin"
	}
	archPart := env.Arch
	nodeMajor := nodeMajorVersion(env.NodeVersion)
	if nodeMajor == "" {
		return fmt.Sprintf("%s_%s_node_unknown", osPart, archPart)
	}
	return fmt.Sprintf("%s_%s_node_v%s", osPart, archPart, nodeMajor)
}

func nodeMajorVersion(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
