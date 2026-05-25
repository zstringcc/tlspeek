#!/usr/bin/env node
// tlspeek — Capture this machine's Node.js TLS ClientHello as portable JSON.
//
// Pure Node, no Go / no compile / no external deps. Just stdlib.
//
// How:
//   1. net.createServer() on a random localhost port.
//   2. tls.connect() inside the SAME process targeting that listener, with
//      ALPN [h2, http/1.1] + SNI api.anthropic.com (real Claude Code shape).
//   3. Server side reads the first TCP chunk (= TLS record + ClientHello),
//      does NOT respond, immediately closes.
//   4. Parse ClientHello → emit JSON on stdout. Diagnostics on stderr.

'use strict';

const net = require('net');
const tls = require('tls');
const os = require('os');
const cp = require('child_process');

// ----------------------------------------------------------------------------
// ClientHello byte parser (mirrors the Go version's algorithm 1:1)
// ----------------------------------------------------------------------------

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  remaining() { return this.buf.length - this.pos; }
  u8() {
    if (this.remaining() < 1) throw new Error('eof reading u8');
    return this.buf[this.pos++];
  }
  u16() {
    if (this.remaining() < 2) throw new Error('eof reading u16');
    const v = this.buf.readUInt16BE(this.pos);
    this.pos += 2;
    return v;
  }
  bytes(n) {
    if (this.remaining() < n) throw new Error(`eof reading ${n} bytes`);
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

function isGREASE(v) {
  return (v & 0x0f0f) === 0x0a0a && ((v >> 8) & 0xff) === (v & 0xff);
}

function stripGREASE(list) {
  return list.filter(v => !isGREASE(v));
}

function parseUint16ListWithLen2(buf) {
  if (buf.length < 2) return [];
  const listLen = buf.readUInt16BE(0);
  if (2 + listLen > buf.length) return [];
  const out = [];
  for (let i = 2; i + 2 <= 2 + listLen; i += 2) {
    out.push(buf.readUInt16BE(i));
  }
  return out;
}

function parseUint16ListWithLen1(buf) {
  if (buf.length < 1) return [];
  const listLen = buf[0];
  if (1 + listLen > buf.length) return [];
  const out = [];
  for (let i = 1; i + 2 <= 1 + listLen; i += 2) {
    out.push(buf.readUInt16BE(i));
  }
  return out;
}

function parseUint8ListWithLen1AsUint16(buf) {
  if (buf.length < 1) return [];
  const listLen = buf[0];
  if (1 + listLen > buf.length) return [];
  return Array.from(buf.slice(1, 1 + listLen));
}

function parseALPN(buf) {
  if (buf.length < 2) return [];
  const listLen = buf.readUInt16BE(0);
  const r = new Reader(buf.slice(2, 2 + listLen));
  const out = [];
  while (r.remaining() > 0) {
    const nameLen = r.u8();
    out.push(r.bytes(nameLen).toString('utf8'));
  }
  return out;
}

function parseSNI(buf) {
  const r = new Reader(buf);
  try {
    const listLen = r.u16();
    if (listLen > r.remaining()) return '';
    while (r.remaining() >= 3) {
      const nameType = r.u8();
      const nameLen = r.u16();
      const nameBytes = r.bytes(nameLen);
      if (nameType === 0) return nameBytes.toString('utf8');
    }
  } catch {}
  return '';
}

function parseKeyShareGroups(buf) {
  if (buf.length < 2) return [];
  const listLen = buf.readUInt16BE(0);
  const r = new Reader(buf.slice(2, 2 + listLen));
  const out = [];
  while (r.remaining() >= 4) {
    const group = r.u16();
    const keLen = r.u16();
    try { r.bytes(keLen); } catch { return out; }
    out.push(group);
  }
  return out;
}

function parseClientHello(buf) {
  // TLS record header: type(1) + version(2) + length(2)
  if (buf.length < 5) throw new Error('record too short');
  if (buf[0] !== 0x16) throw new Error(`not a handshake record: 0x${buf[0].toString(16)}`);
  const recordLen = buf.readUInt16BE(3);
  if (5 + recordLen > buf.length) throw new Error('record truncated');
  const hs = buf.slice(5, 5 + recordLen);
  // Handshake msg: type(1) + length(3)
  if (hs[0] !== 0x01) throw new Error(`not ClientHello (type=0x${hs[0].toString(16)})`);
  const msgLen = (hs[1] << 16) | (hs[2] << 8) | hs[3];
  if (4 + msgLen > hs.length) throw new Error('handshake truncated');
  const body = hs.slice(4, 4 + msgLen);
  const r = new Reader(body);

  const ch = {
    cipherSuites: [],
    curves: [],
    pointFormats: [],
    signatureAlgorithms: [],
    alpnProtocols: [],
    supportedVersions: [],
    keyShareGroups: [],
    pskModes: [],
    extensions: [],
    hasGREASE: false,
    serverName: '',
  };

  // legacy_version (2) + random (32) + session_id (variable)
  r.u16();
  r.bytes(32);
  const sidLen = r.u8();
  r.bytes(sidLen);

  // cipher_suites (length 2)
  const csLen = r.u16();
  const csBytes = r.bytes(csLen);
  for (let i = 0; i + 2 <= csBytes.length; i += 2) {
    const cs = csBytes.readUInt16BE(i);
    ch.cipherSuites.push(cs);
    if (isGREASE(cs)) ch.hasGREASE = true;
  }

  // compression_methods (length 1)
  const cmLen = r.u8();
  r.bytes(cmLen);

  // extensions (length 2) — TLS 1.0/1.1 may have none
  if (r.remaining() === 0) return ch;
  const extLen = r.u16();
  const extBytes = r.bytes(extLen);
  const er = new Reader(extBytes);
  while (er.remaining() > 0) {
    const extType = er.u16();
    const extDataLen = er.u16();
    const extData = er.bytes(extDataLen);
    ch.extensions.push(extType);
    if (isGREASE(extType)) ch.hasGREASE = true;
    switch (extType) {
      case 0:  ch.serverName = parseSNI(extData); break;
      case 10: ch.curves = parseUint16ListWithLen2(extData); break;
      case 11: ch.pointFormats = parseUint8ListWithLen1AsUint16(extData); break;
      case 13: ch.signatureAlgorithms = parseUint16ListWithLen2(extData); break;
      case 16: ch.alpnProtocols = parseALPN(extData); break;
      case 43: ch.supportedVersions = parseUint16ListWithLen1(extData); break;
      case 45: ch.pskModes = parseUint8ListWithLen1AsUint16(extData); break;
      case 51: ch.keyShareGroups = parseKeyShareGroups(extData); break;
    }
  }
  return ch;
}

// ----------------------------------------------------------------------------
// Environment detection
// ----------------------------------------------------------------------------

function detectEnv() {
  const env = {
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version.replace(/^v/, ''),
    ccVersion: '',
  };
  try {
    const out = cp.execSync('claude --version', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
    const m = out.match(/(\d+\.\d+\.\d+)/);
    if (m) env.ccVersion = m[1];
  } catch {}
  return env;
}

function profileName(env) {
  const platformMap = { darwin: 'darwin', linux: 'linux', win32: 'windows' };
  const platform = platformMap[env.platform] || env.platform;
  const major = (env.nodeVersion || '').split('.')[0] || 'unknown';
  return `${platform}_${env.arch}_node_v${major}`;
}

// ----------------------------------------------------------------------------
// Main flow
// ----------------------------------------------------------------------------

function die(msg) {
  process.stderr.write('FATAL: ' + msg + '\n');
  process.exit(1);
}

function main() {
  let captured = false;
  let firstChunk = Buffer.alloc(0);

  const server = net.createServer((socket) => {
    socket.on('data', (chunk) => {
      firstChunk = Buffer.concat([firstChunk, chunk]);
      // ClientHello is at most ~16KB; once we have a TLS record we're done
      if (firstChunk.length >= 5) {
        const recordLen = firstChunk.readUInt16BE(3);
        if (firstChunk.length >= 5 + recordLen) {
          captured = true;
          socket.destroy();
        }
      }
    });
    socket.on('close', () => {
      if (!captured) return;
      server.close();
      try {
        const ch = parseClientHello(firstChunk);
        emit(ch, detectEnv());
      } catch (e) {
        die('parse ClientHello: ' + e.message);
      }
    });
    socket.on('error', () => {});
  });

  server.on('error', (e) => die('listen: ' + e.message));

  server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    // Trigger handshake in this same process
    const client = tls.connect({
      host: '127.0.0.1',
      port,
      servername: 'api.anthropic.com',
      ALPNProtocols: ['h2', 'http/1.1'],
      minVersion: 'TLSv1.2',
      rejectUnauthorized: false,
    });
    client.on('error', () => {}); // expected — server kills connection
  });

  // Safety timeout
  setTimeout(() => {
    if (!captured) die('timeout waiting for ClientHello (10s)');
  }, 10000);
}

// ----------------------------------------------------------------------------
// JA3 / JA4
// ----------------------------------------------------------------------------

function joinDash(list) { return list.length === 0 ? '' : list.join('-'); }

function ja3String(ch) {
  return [
    '771',
    joinDash(stripGREASE(ch.cipherSuites)),
    joinDash(stripGREASE(ch.extensions)),
    joinDash(stripGREASE(ch.curves)),
    joinDash(ch.pointFormats),
  ].join(',');
}

function sha256Hex(s) {
  return require('crypto').createHash('sha256').update(s).digest('hex');
}

function ja4String(ch) {
  const cipherCount = stripGREASE(ch.cipherSuites).length;
  const extCount = stripGREASE(ch.extensions).length;
  let firstALPN = '00';
  if (ch.alpnProtocols.length > 0) {
    const a = ch.alpnProtocols[0];
    if (a.length >= 2) firstALPN = a[0] + a[a.length - 1];
  }
  const cipherSeg = sha256Hex(joinDash(stripGREASE(ch.cipherSuites))).slice(0, 12);
  const extSeg = sha256Hex(joinDash(stripGREASE(ch.extensions)) + '_' + joinDash(ch.signatureAlgorithms)).slice(0, 12);
  return `t13d${String(cipherCount).padStart(2, '0')}${String(extCount).padStart(2, '0')}${firstALPN}_${cipherSeg}_${extSeg}`;
}

// ----------------------------------------------------------------------------
// Emit
// ----------------------------------------------------------------------------

function emit(ch, env) {
  const name = profileName(env);
  const now = new Date().toISOString().slice(0, 10);
  let desc = `Captured on ${env.platform}/${env.arch} Node ${env.nodeVersion}`;
  if (env.ccVersion) desc += ` + Claude Code ${env.ccVersion}`;
  desc += ` (${now})`;

  const profile = {
    name,
    description: desc,
    enable_grease: ch.hasGREASE,
    cipher_suites: stripGREASE(ch.cipherSuites),
    curves: stripGREASE(ch.curves),
    point_formats: ch.pointFormats,
    signature_algorithms: ch.signatureAlgorithms,
    alpn_protocols: ch.alpnProtocols,
    supported_versions: ch.supportedVersions,
    key_share_groups: stripGREASE(ch.keyShareGroups),
    psk_modes: ch.pskModes,
    extensions: stripGREASE(ch.extensions),
  };

  // Default: silent. YAML to stdout (sub2api admin UI expects YAML).
  // TLSPEEK_FORMAT=json  → JSON output (for API POST / programmatic use)
  // TLSPEEK_VERBOSE=1    → one-line summary on stderr
  if (process.env.TLSPEEK_VERBOSE === '1') {
    process.stderr.write(
      `tlspeek: ${name} — ${profile.cipher_suites.length} ciphers, ${profile.extensions.length} ext, ALPN=[${ch.alpnProtocols.join(', ')}], JA4=${ja4String(ch)}\n`
    );
  }
  const format = (process.env.TLSPEEK_FORMAT || 'yaml').toLowerCase();
  if (format === 'json') {
    process.stdout.write(JSON.stringify(profile, null, 2) + '\n');
  } else {
    process.stdout.write(toYAML(profile) + '\n');
  }
  process.exit(0);
}

// Block-style YAML formatter for our specific Profile schema.
// Block style (not flow) is required because some YAML parsers (including
// sub2api admin's) don't accept inline JSON-style flow mappings.
function toYAML(p) {
  const lines = [];
  lines.push(`name: ${p.name}`);
  if (p.description) lines.push(`description: ${quoteYAML(p.description)}`);
  lines.push(`enable_grease: ${p.enable_grease}`);
  for (const [key, list] of [
    ['cipher_suites',        p.cipher_suites],
    ['curves',               p.curves],
    ['point_formats',        p.point_formats],
    ['signature_algorithms', p.signature_algorithms],
    ['alpn_protocols',       p.alpn_protocols],
    ['supported_versions',   p.supported_versions],
    ['key_share_groups',     p.key_share_groups],
    ['psk_modes',            p.psk_modes],
    ['extensions',           p.extensions],
  ]) {
    if (!list || list.length === 0) {
      lines.push(`${key}: []`);
      continue;
    }
    lines.push(`${key}:`);
    for (const v of list) {
      lines.push(typeof v === 'string' ? `  - ${quoteYAML(v)}` : `  - ${v}`);
    }
  }
  return lines.join('\n');
}

// quoteYAML wraps strings safely for YAML — uses JSON.stringify which produces
// double-quoted, escaped strings that are also valid YAML 1.2 scalars.
function quoteYAML(s) {
  return JSON.stringify(s);
}

main();
