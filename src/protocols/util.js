// SENTRA — pure crypto/format utilities (no Worker APIs; unit-testable in Node).
// Algorithms implemented from public specs: RFC 1321 (MD5, needed for Shadowsocks
// EVP_BytesToKey key derivation), SIP002/SIP003 URI conventions, AEAD chunk framing.

export const hexToBytes = (h) => {
  const clean = (h.match(/../g) || []).map(x => parseInt(x, 16));
  return new Uint8Array(clean);
};
export const bytesToHex = (b) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');

export function b64encode(str) {
  // unicode-safe base64 (RFC 4648, no padding for subscription payloads)
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decode(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// ── MD5 (RFC 1321) — pure JS, needed because WebCrypto has no MD5 and
//    Shadowsocks derives AES keys from a passphrase via EVP_BytesToKey(MD5) ──
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
const rl = (x, c) => (x << c) | (x >>> (32 - c));
const add = (...xs) => xs.reduce((a, b) => (a + b) >>> 0, 0);

export function md5(input) {
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const bitLen = msg.length * 8;
  const padded = new Uint8Array(((msg.length + 8) >> 6 << 6) + 64);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true); // MD5 encodes length little-endian
  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const M = new Int32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let [a, b, c, d] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c; c = b;
      b = add(b, rl(add(a, f, K[i], M[g]), S[i]));
      a = tmp;
    }
    a0 = add(a0, a); b0 = add(b0, b); c0 = add(c0, c); d0 = add(d0, d);
  }
  const out = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((v, i) => out.setUint32(i * 4, v, true));
  return bytesToHex(new Uint8Array(out.buffer));
}

// EVP_BytesToKey (OpenSSL compat): D_i = MD5(D_{i-1} || passphrase || salt)
export function evpBytesToKey(password, keyLen = 32, salt = new Uint8Array(0)) {
  const pass = typeof password === 'string' ? new TextEncoder().encode(password) : new Uint8Array(password);
  const chunks = [];
  let prev = new Uint8Array(0);
  let total = 0;
  while (total < keyLen) {
    const data = new Uint8Array(prev.length + pass.length + salt.length);
    data.set(prev); data.set(pass, prev.length); data.set(salt, prev.length + pass.length);
    prev = hexToBytes(md5(data));
    chunks.push(prev);
    total += prev.length;
  }
  const key = new Uint8Array(keyLen);
  let o = 0;
  for (const c of chunks) {
    for (const b of c) { if (o >= keyLen) break; key[o++] = b; }
  }
  return key;
}

// ── Shadowsocks AEAD (RFC-style chunk framing as used by shadowsocks-aead) ──
// subkey = HKDF-SHA1(key=masterKey, salt, info='ss-subkey', L=32)
// TCP nonce = 12-byte big-endian counter starting at 0, incremented per AEAD operation.
export async function ssSubkey(masterKey, salt) {
  const base = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-1', salt, info: new TextEncoder().encode('ss-subkey') },
    base, 256);
  return new Uint8Array(bits);
}

export class IncrementingNonce {
  constructor(len = 12) { this.n = new Uint8Array(len); }
  next() {
    const out = new Uint8Array(this.n);
    for (let i = this.n.length - 1; i >= 0; i--) {
      if (this.n[i] === 255) { this.n[i] = 0; continue; }
      this.n[i] += 1; break;
    }
    return out;
  }
}

export async function importAesKey(raw32) {
  return crypto.subtle.importKey('raw', raw32, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// Parse SOCKS5 address block: [atyp][addr][port]
export function parseSocksAddress(bytes, offset = 0) {
  const atyp = bytes[offset];
  let addr, port, len;
  if (atyp === 1) { // IPv4
    addr = bytes.slice(offset + 1, offset + 5).join('.');
    port = (bytes[offset + 5] << 8) | bytes[offset + 6];
    len = 7;
  } else if (atyp === 3) { // domain
    const dlen = bytes[offset + 1];
    addr = new TextDecoder().decode(bytes.slice(offset + 2, offset + 2 + dlen));
    port = (bytes[offset + 2 + dlen] << 8) | bytes[offset + 3 + dlen];
    len = 4 + dlen;
  } else if (atyp === 4) { // IPv6
    const seg = [];
    for (let i = 0; i < 8; i++) seg.push(bytes.slice(offset + 1 + i * 2, offset + 3 + i * 2).map(x => x.toString(16).padStart(2, '0')).join(''));
    addr = seg.map(s => s.replace(/^0+(?=[0-9a-f])/, '')).join(':');
    port = (bytes[offset + 17] << 8) | bytes[offset + 18];
    len = 19;
  } else {
    throw new Error('bad atyp ' + atyp);
  }
  return { atyp, addr, port, len };
}

export function buildSocksAddress(host, port) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const b = new Uint8Array(7);
    b[0] = 1;
    host.split('.').forEach((x, i) => { b[i + 1] = parseInt(x, 10); });
    b[5] = (port >> 8) & 255; b[6] = port & 255;
    return b;
  }
  if (host.includes(':')) {
    const b = new Uint8Array(19);
    b[0] = 4;
    const parts = host.split(':').flatMap(s => {
      s = s || '0';
      const v = parseInt(s, 16);
      return [(v >> 8) & 255, v & 255];
    });
    while (parts.length < 16) parts.push(0);
    b.set(parts.slice(0, 16), 1);
    b[17] = (port >> 8) & 255; b[18] = port & 255;
    return b;
  }
  const dh = new TextEncoder().encode(host);
  const b = new Uint8Array(4 + dh.length);
  b[0] = 3; b[1] = dh.length;
  b.set(dh, 2);
  b[2 + dh.length] = (port >> 8) & 255; b[3 + dh.length] = port & 255;
  return b;
}

// ── gRPC message framing (public gRPC wire spec: 1B compressed flag + 4B BE length) ──
export function grpcEncode(chunk) {
  const out = new Uint8Array(5 + chunk.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(1, chunk.length); // big-endian
  out.set(chunk, 5);
  return out;
}

// Streaming unframer: push raw bytes, get complete message payloads back
export class GrpcUnframer {
  constructor() { this.buf = new Uint8Array(0); }
  push(bytes) {
    const merged = new Uint8Array(this.buf.length + bytes.length);
    merged.set(this.buf); merged.set(bytes, this.buf.length);
    this.buf = merged;
    const out = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const len = ((this.buf[1] << 24) | (this.buf[2] << 16) | (this.buf[3] << 8) | this.buf[4]) >>> 0;
      if (len > 16 * 1024 * 1024) throw new Error('grpc frame too large');
      if (this.buf.length < 5 + len) break;
      out.push(this.buf.slice(5, 5 + len));
      this.buf = this.buf.slice(5 + len);
    }
    return out;
  }
}

// Extract session parts from an xhttp URL path: /xhttp/<proto>/<token>/<sid>
export function parseXhttpPath(pathname) {
  const m = pathname.match(/^\/xhttp\/(vless|trojan|ss)\/([A-Za-z0-9]+)\/([A-Za-z0-9-]+)\/?$/);
  return m ? { proto: m[1], token: m[2], sid: m[3] } : null;
}

export const concatBytes = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a); out.set(b, a.length);
  return out;
};

export const SS_TAG_LEN = 16; // AES-GCM tag size in the SS-AEAD chunk framing

// SS-AEAD decrypt pump with nonce-continuity: decrypts whole chunks only and
// caches the decrypted length block between feeds, so the GCM nonce never
// desyncs when the encrypted stream arrives in arbitrarily-sized pieces
// (gRPC frames / XHTTP POST bodies). state = { key, nonce: IncrementingNonce }.
export function makeSsPump(state) {
  let raw = new Uint8Array(0);
  let curLen = -1; // -1 = length block not yet decrypted
  return {
    async feed(bytes) {
      raw = concatBytes(raw, bytes);
      const parts = [];
      for (;;) {
        if (curLen < 0) {
          if (raw.length < 2 + SS_TAG_LEN) break;
          const lp = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: state.nonce.next() }, state.key, raw.slice(0, 2 + SS_TAG_LEN)));
          const l = (lp[0] << 8) | lp[1];
          if (l <= 0 || l > 0x3fff) return { fatal: true };
          curLen = l;
          raw = raw.slice(2 + SS_TAG_LEN);
          continue;
        }
        if (raw.length < curLen + SS_TAG_LEN) break;
        const body = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: state.nonce.next() }, state.key, raw.slice(0, curLen + SS_TAG_LEN)));
        parts.push(body);
        raw = raw.slice(curLen + SS_TAG_LEN);
        curLen = -1;
      }
      const total = parts.reduce((s, p) => s + p.length, 0);
      const out = new Uint8Array(total);
      let o = 0;
      for (const p of parts) { out.set(p, o); o += p.length; }
      return { plain: out };
    },
  };
}
