// SENTRA — WS→TCP relay core (Cloudflare Workers).
// Protocol framing implemented from public specifications:
//  • VLESS request:  [version][uuidLen][uuid][addonLen][addon][cmd][port:2][atyp][addr] (XTLS project spec)
//  • Trojan request: hex(sha224(password)) CRLF [cmd][atyp][addr] CRLF  (trojan-gfw spec)
//  • Shadowsocks AEAD (aes-256-gcm) with v2ray-plugin websocket framing:
//      stream = salt(32) || chunk{ [encLen:2][lenTag:16][encPayload][payloadTag:16] } (shadowsocks aead spec)
// The Worker opens an outbound TCP socket via `cloudflare:sockets` and pipes both ways.

import { connect } from 'cloudflare:sockets';
import { getCredMap, bufferTraffic, flushTraffic, getUserById, updateUser, now } from '../db.js';
import { getSettings } from '../config.js';
import {
  ssSubkey, IncrementingNonce, importAesKey, parseSocksAddress, evpBytesToKey, hexToBytes,
  grpcEncode, GrpcUnframer, parseXhttpPath, concatBytes, makeSsPump, SS_TAG_LEN,
} from './util.js';
import { sha224Hex } from '../db.js';

const SS_SALT_LEN = 32;

export async function handleWsUpgrade(request, env, ctx) {
  const settings = await getSettings(env);
  if (settings.kill_switch) return wsReject(503, 'service disabled');

  const url = new URL(request.url);
  const m = url.pathname.match(/^\/ws\/(vless|trojan|ss)\/([A-Za-z0-9]+)$/);
  if (!m) return wsReject(404, 'unknown relay path');
  const [, proto, token] = m;

  const user = await getUserByTokenSafe(env, token);
  if (!user) return wsReject(404, 'no such subscription');
  if (!user.enabled) return wsReject(403, 'user disabled');

  const gate = await gateCheck(env, user);
  if (!gate.ok) return wsReject(gate.status, gate.reason);

  const pair = new WebSocketPair();
  const client = pair[0], server = pair[1];
  server.accept();

  ctx.waitUntil(relayConnection(server, env, proto, user).catch(async (e) => {
    try { server.close(1011, String(e).slice(0, 100)); } catch {}
  }));

  return new Response(null, { status: 101, webSocket: client });
}

async function getUserByTokenSafe(env, token) {
  try {
    const q = await env.DB.prepare('SELECT id FROM users WHERE token = ?').bind(token).first();
    return q ? getUserById(env, q.id) : null;
  } catch { return null; }
}

// ── admission control: quotas, expiry, ip limit, first-connect activation ──
export async function gateCheck(env, user, ip = null) {
  const settings = await getSettings(env);
  if (settings.kill_switch) return { ok: false, status: 503, reason: 'kill switch active' };
  const t = now();
  if (user.expiresAt > 0 && user.expiresAt < t) {
    await updateUser(env, user.id, { enabled: false });
    return { ok: false, status: 403, reason: 'expired' };
  }
  if (user.startOnFirstConnect && user.durationDays > 0 && !user.startedAt) {
    const exp = t + user.durationDays * 86400_000;
    await updateUser(env, user.id, { startedAt: t, expiresAt: exp });
  }
  if (user.quotaBytes > 0 && user.usedBytes >= user.quotaBytes) return { ok: false, status: 402, reason: 'quota exhausted' };
  if (user.quotaRequests > 0 && user.usedRequests >= user.quotaRequests) return { ok: false, status: 402, reason: 'request quota exhausted' };
  if (user.ipLimit > 0 && ip) {
    const okIp = await ipLimitCheck(env, user.id, ip, user.ipLimit);
    if (!okIp) return { ok: false, status: 429, reason: 'device limit reached' };
  }
  return { ok: true };
}

async function ipLimitCheck(env, userId, ip, limit) {
  const prefix = `iplim:${userId}:`;
  try {
    const list = await env.KV.list({ prefix });
    const known = new Set(list.keys.map(k => k.slice(prefix.length)));
    if (known.has(ip)) {
      await env.KV.put(prefix + ip, '1', { expirationTtl: 1800 });
      return true;
    }
    if (known.size >= limit) return false;
    await env.KV.put(prefix + ip, '1', { expirationTtl: 1800 });
    return true;
  } catch { return true; } // fail-open if KV unavailable
}

function wsReject(status, reason) {
  return new Response(reason, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });
}

// ── the relay itself ──
async function relayConnection(server, env, proto, user) {
  const addr = await readTarget(server, env, proto, user); // {host, port, leftover, pskInfo}
  if (!addr) { try { server.close(1008, 'bad handshake'); } catch {} return; }

  bufferTraffic(user.id, 0, 0, 1);

  let socket;
  try {
    socket = connect({ hostname: addr.host, port: addr.port });
  } catch (e) {
    try { server.close(1014, 'dial failed'); } catch {}
    return;
  }
  const writer = socket.writable.getWriter();

  let up = 0, down = 0;
  const mark = () => {
    if (up + down > 1 << 18) { bufferTraffic(user.id, up, down); up = 0; down = 0; }
  };

  // client → target (first chunk may carry leftover payload bytes after the header)
  if (addr.leftover && addr.leftover.length) {
    await writer.write(addr.leftover);
    up += addr.leftover.length;
  }

  const closing = { done: false };
  const finish = async () => {
    if (closing.done) return;
    closing.done = true;
    bufferTraffic(user.id, up, down);
    try { await writer.close(); } catch {}
    try { socket.close(); } catch {}
    try { server.close(); } catch {}
  };

  server.addEventListener('message', async (ev) => {
    if (closing.done || !ev.data) return;
    try {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data)
        : ev.data instanceof Blob ? new Uint8Array(await ev.data.arrayBuffer())
        : new Uint8Array(ev.data);
      let payload = data;
      if (proto === 'ss' && addr.ssIn) payload = await ssDecryptChunks(addr.ssIn, data);
      if (!payload || !payload.length) return;
      await writer.write(payload);
      up += payload.length;
      mark();
    } catch (e) { await finish(); }
  });
  server.addEventListener('close', () => finish());
  server.addEventListener('error', () => finish());

  // protocol-specific response preamble before piping upstream data
  if (proto === 'vless') {
    const resp = new Uint8Array([0, 0]); // version 0, empty addon
    server.send(resp);
  }
  if (proto === 'ss' && addr.ssOut) {
    server.send(addr.ssOut.header); // our own salt so the client can derive the same subkey
  }

  const reader = socket.readable.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || closing.done) break;
      let out = value;
      if (proto === 'ss' && addr.ssOut) out = await addr.ssOut.encryptChunk(value);
      down += value.length;
      server.send(out instanceof Uint8Array ? out.buffer : out);
      mark();
    }
  } catch {}
  await finish();
}

// ── read + parse the target address per protocol ──
async function readTarget(server, env, proto, user) {
  const first = await firstMessage(server);
  if (!first || !first.length) return null;

  if (proto === 'vless') {
    // [ver][uLen][uuid16][aLen][addon][cmd][port2][atyp][addr]
    if (first.length < 24) return null;
    const uLen = first[1];
    if (uLen !== 16) return null;
    const uuid = [...first.slice(2, 18)].map(b => b.toString(16).padStart(2, '0')).join('')
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
    const map = await getCredMap(env);
    const uid = map.vless[uuid.toLowerCase()];
    if (uid !== user.id) return null; // credentials must belong to this subscription token
    let i = 18;
    const aLen = first[i]; i += 1 + aLen;
    const cmd = first[i]; i += 1;
    const port = (first[i] << 8) | first[i + 1]; i += 2;
    const parsed = parseSocksAddress(first, i);
    if (cmd !== 1) { try { server.close(1008, 'udp not supported on ws transport'); } catch {} return null; }
    return { host: parsed.addr, port: parsed.port, leftover: first.slice(i + parsed.len) };
  }

  if (proto === 'trojan') {
    if (first.length < 58) return null;
    const text = [...first.slice(0, 56)].map(b => String.fromCharCode(b)).join('');
    const hexHash = await sha224Hex(user.password);
    if (text.toLowerCase() !== hexHash) return null;
    if (first[56] !== 13 || first[57] !== 10) return null;
    const cmd = first[58];
    if (cmd !== 1) { try { server.close(1008, 'udp not supported on ws transport'); } catch {} return null; }
    const parsed = parseSocksAddress(first, 59);
    let tail = 59 + parsed.len;
    if (first[tail] === 13 && first[tail + 1] === 10) tail += 2;
    return { host: parsed.addr, port: parsed.port, leftover: first.slice(tail) };
  }

  if (proto === 'ss') {
    // user identification: try every enabled user's psk against the salted stream
    const salt = first.slice(0, SS_SALT_LEN);
    const candidates = [];
    candidates.push(user.password);
    try {
      const { results } = await env.DB.prepare('SELECT password FROM users WHERE enabled = 1 AND password IS NOT NULL').all();
      for (const r of results) if (r.password && !candidates.includes(r.password)) candidates.push(r.password);
    } catch {}
    for (const pass of candidates) {
      const master = evpBytesToKey(pass, 32);
      const sub = await ssSubkey(master, salt);
      // decryption state continues across the whole connection (chunk 0 = target address)
      const state = { key: await importAesKey(sub), nonce: new IncrementingNonce() };
      const plain0 = await ssDecryptChunks(state, first.slice(SS_SALT_LEN));
      if (!plain0) continue;
      const parsed = parseSocksAddress(plain0, 0);
      return {
        host: parsed.addr, port: parsed.port,
        leftover: plain0.slice(parsed.len), // already-decrypted payload bytes
        ssIn: state,
        ssOut: await makeSsOutbound(user.password),
      };
    }
    return null;
  }
  return null;
}

// decrypt one or more SS-AEAD chunks from a single ws message; keeps nonce state across calls
async function ssDecryptChunks(state, bytes) {
  try {
    let off = 0;
    const parts = [];
    while (off < bytes.length) {
      if (bytes.length - off < 2 + SS_TAG_LEN) break;
      const lenPlain = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: state.nonce.next() }, state.key, bytes.slice(off, off + 2 + SS_TAG_LEN)));
      const len = (lenPlain[0] << 8) | lenPlain[1];
      if (len <= 0 || len > 0x3fff) return null;
      off += 2 + SS_TAG_LEN;
      if (bytes.length - off < len + SS_TAG_LEN) return null;
      const body = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: state.nonce.next() }, state.key, bytes.slice(off, off + len + SS_TAG_LEN)));
      parts.push(body);
      off += len + SS_TAG_LEN;
    }
    const total = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  } catch { return null; }
}

// server → client direction with our own salt (client derives the same subkey from psk+salt)
async function makeSsOutbound(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SS_SALT_LEN));
  const master = evpBytesToKey(password, 32);
  const sub = await ssSubkey(master, salt);
  const key = await importAesKey(sub);
  const nonce = new IncrementingNonce();
  const header = salt.buffer;
  return {
    header,
    async encryptChunk(plain) {
      const lenBuf = new Uint8Array(2);
      lenBuf[0] = (plain.length >> 8) & 255;
      lenBuf[1] = plain.length & 255;
      const lenEnc = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce.next() }, key, lenBuf));
      const bodyEnc = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce.next() }, key, plain));
      const out = new Uint8Array(lenEnc.length + bodyEnc.length);
      out.set(lenEnc); out.set(bodyEnc, lenEnc.length);
      return out.buffer;
    },
  };
}

function firstMessage(ws) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { cleanup(); resolve(null); }, 10_000);
    const onMsg = (ev) => {
      cleanup();
      try {
        if (ev.data instanceof ArrayBuffer) resolve(new Uint8Array(ev.data));
        else if (ev.data instanceof Blob) ev.data.arrayBuffer().then(b => resolve(new Uint8Array(b)));
        else resolve(new Uint8Array(ev.data));
      } catch { resolve(null); }
    };
    const onClose = () => { cleanup(); resolve(null); };
    const cleanup = () => {
      clearTimeout(timer);
      ws.removeEventListener('message', onMsg);
      ws.removeEventListener('close', onClose);
    };
    ws.addEventListener('message', onMsg);
    ws.addEventListener('close', onClose);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  Streaming transports: gRPC (POST body of gRPC-framed protocol bytes) and
//  XHTTP/SplitHTTP (GET download stream + POST upload, session id in the path).
//  Both share the streaming header parser and the SS decrypt pump below.
//  Note: Workers cannot send HTTP trailers, so gRPC streams close without a
//  grpc-status trailer (clients may log EOF at close — data is already delivered).
// ═══════════════════════════════════════════════════════════════════════════

const silentClose = (w) => { try { const p = w?.close(); p?.catch?.(() => {}); } catch {} };

function socksNeeded(bytes, i) {
  if (i >= bytes.length) return -1;
  const atyp = bytes[i];
  let need;
  if (atyp === 1) need = 7;
  else if (atyp === 3) need = bytes.length > i + 1 ? 4 + bytes[i + 1] : -1;
  else if (atyp === 4) need = 19;
  else return -2; // bad atyp
  return (bytes.length >= i + need) ? need : -1;
}

// Streaming header parser shared by gRPC/XHTTP. bufRef.buf accumulates raw
// protocol bytes; pumpRef.pump adopts the winning SS decrypt pump.
async function parseStreamingHeader(env, proto, user, bufRef, pumpRef) {
  const buf = bufRef.buf;

  if (proto === 'vless' || proto === 'trojan') {
    if (proto === 'vless') {
      if (buf.length < 2) return { need: true };
      if (buf[1] !== 16) return { error: 'bad vless header' };
      if (buf.length < 18) return { need: true };
      const uuid = [...buf.slice(2, 18)].map(b => b.toString(16).padStart(2, '0')).join('')
        .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
      const map = await getCredMap(env);
      if (map.vless[uuid.toLowerCase()] !== user.id) return { error: 'vless auth failed' };
      let i = 18;
      if (buf.length < i + 1) return { need: true };
      const aLen = buf[i]; i += 1 + aLen;
      if (buf.length < i + 3) return { need: true };
      const cmd = buf[i]; i += 1;
      const port = (buf[i] << 8) | buf[i + 1]; i += 2;
      const need = socksNeeded(buf, i);
      if (need === -1) return { need: true };
      if (need === -2) return { error: 'bad address' };
      const parsed = parseSocksAddress(buf, i);
      if (cmd !== 1) return { error: 'udp not supported' };
      bufRef.buf = new Uint8Array(0);
      return { host: parsed.addr, port: parsed.port, leftover: buf.slice(i + parsed.len) };
    }
    // trojan
    if (buf.length < 58) return { need: true };
    const text = [...buf.slice(0, 56)].map(b => String.fromCharCode(b)).join('');
    if (text.toLowerCase() !== await sha224Hex(user.password)) return { error: 'trojan auth failed' };
    if (buf[56] !== 13 || buf[57] !== 10) return { error: 'bad trojan header' };
    const cmd = buf[58];
    if (cmd !== 1) return { error: 'udp not supported' };
    const need = socksNeeded(buf, 59);
    if (need === -1) return { need: true };
    if (need === -2) return { error: 'bad address' };
    const parsed = parseSocksAddress(buf, 59);
    if (buf.length < 59 + parsed.len + 2) return { need: true }; // trailing CRLF
    if (buf[59 + parsed.len] !== 13 || buf[60 + parsed.len] !== 10) return { error: 'bad trojan tail' };
    bufRef.buf = new Uint8Array(0);
    return { host: parsed.addr, port: parsed.port, leftover: buf.slice(61 + parsed.len) };
  }

  // ss: salt(32) + AEAD chunk stream; trial-decrypt with each enabled psk
  if (buf.length < SS_SALT_LEN + 2 + SS_TAG_LEN) return { need: true };
  const salt = buf.slice(0, SS_SALT_LEN);
  const candidates = [user.password];
  try {
    const { results } = await env.DB.prepare('SELECT password FROM users WHERE enabled = 1 AND password IS NOT NULL').all();
    for (const r of results) if (r.password && !candidates.includes(r.password)) candidates.push(r.password);
  } catch {}
  for (const pass of candidates) {
    const master = evpBytesToKey(pass, 32);
    const sub = await ssSubkey(master, salt);
    const state = { key: await importAesKey(sub), nonce: new IncrementingNonce() };
    const pump = makeSsPump(state);
    const r = await pump.feed(buf.slice(SS_SALT_LEN));
    if (r.need || (r.plain && !r.plain.length)) return { need: true };
    if (r.fatal || !r.plain) continue; // wrong psk — try the next candidate
    const need = socksNeeded(r.plain, 0);
    if (need === -1) return { need: true };
    if (need === -2) continue;
    const parsed = parseSocksAddress(r.plain, 0);
    bufRef.buf = new Uint8Array(0);
    pumpRef.pump = pump;
    return { host: parsed.addr, port: parsed.port, leftover: r.plain.slice(parsed.len), ssOut: await makeSsOutbound(user.password) };
  }
  return { error: 'ss auth failed' };
}

function rejectPlain(status, reason) {
  return new Response(reason, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });
}

async function authStreamingRequest(env, request, proto, token) {
  const settings = await getSettings(env);
  if (settings.kill_switch) return { reject: rejectPlain(503, 'service disabled') };
  const user = await getUserByTokenSafe(env, token);
  if (!user || !user.enabled) return { reject: rejectPlain(404, 'no such subscription') };
  const gate = await gateCheck(env, user, request.headers.get('cf-connecting-ip'));
  if (!gate.ok) return { reject: rejectPlain(gate.status, gate.reason) };
  return { user };
}

// ── gRPC transport: POST /grpc/<proto>/<token>, body = gRPC-framed stream ──
export async function handleGrpcPost(request, env, ctx) {
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/grpc\/(vless|trojan|ss)\/([A-Za-z0-9]+)$/);
  if (!m) return rejectPlain(404, 'unknown relay path');
  const auth = await authStreamingRequest(env, request, m[1], m[2]);
  if (auth.reject) return auth.reject;
  const { user } = auth;
  const proto = m[1];

  const { readable, writable } = new IdentityTransformStream();
  const dWriter = writable.getWriter();
  ctx.waitUntil(runGrpcRelay(request, env, proto, user, dWriter).catch(() => {
    try { dWriter.close(); } catch {}
  }));
  return new Response(readable, {
    status: 200,
    headers: { 'content-type': 'application/grpc', 'x-accel-buffering': 'no', 'cache-control': 'no-store' },
  });
}

async function runGrpcRelay(request, env, proto, user, dWriter) {
  const unframer = new GrpcUnframer();
  const bufRef = { buf: new Uint8Array(0) };
  const pumpRef = { pump: null };
  let header = null;
  let pending = []; // plaintext bytes waiting for the socket

  bufferTraffic(user.id, 0, 0, 1);
  let up = 0, down = 0;
  const mark = () => { if (up + down > 1 << 18) { bufferTraffic(user.id, up, down); up = 0; down = 0; } };

  const finish = async (socket, writer) => {
    bufferTraffic(user.id, up, down);
    try { await writer.close(); } catch {}
    try { socket.close(); } catch {}
    try { dWriter.close(); } catch {}
    try { await request.body?.cancel(); } catch {}
  };

  // phase 1: read the request stream until the protocol header is parsed
  const reqReader = request.body.getReader();
  let socket = null, writer = null;
  try {
    while (!header) {
      const { done, value } = await reqReader.read();
      if (done) return finish(socket || { close() {} }, writer || { async close() {} });
      let frames;
      try { frames = unframer.push(new Uint8Array(value)); } catch { return finish({ close() {} }, { async close() {} }); }
      for (const f of frames) {
        if (!header) {
          bufRef.buf = concatBytes(bufRef.buf, f);
          if (bufRef.buf.length > 65536) return finish({ close() {} }, { async close() {} }); // header never completed
          const r = await parseStreamingHeader(env, proto, user, bufRef, pumpRef);
          if (r.error) return finish({ close() {} }, { async close() {} });
          if (r.need) continue; // incomplete header — keep accumulating and retry
          header = r;
          if (header.leftover?.length) pending.push(header.leftover);
          if (header.ssOut) dWriter.write(grpcEncode(new Uint8Array(header.ssOut.header))); // SS salt, grpc-framed
        } else if (proto === 'ss' && pumpRef.pump) {
          const r = await pumpRef.pump.feed(f);
          if (r.fatal) return finish({ close() {} }, { async close() {} });
          if (r.plain?.length) pending.push(r.plain);
        } else {
          pending.push(f);
        }
      }
    }
  } catch { return finish({ close() {} }, { async close() {} }); }

  // phase 2: dial the target
  try {
    socket = connect({ hostname: header.host, port: header.port });
  } catch { return finish({ close() {} }, { async close() {} }); }
  writer = socket.writable.getWriter();
  for (const p of pending) { try { await writer.write(p); up += p.length; } catch {} }
  pending = [];

  const closing = { done: false };
  const finishAll = () => finish(socket, writer);
  const guard = (fn) => async (...a) => { if (!closing.done) await fn(...a); };

  // phase 3: upload — remaining request frames → target
  const uploadPump = guard(async () => {
    for (;;) {
      const { done, value } = await reqReader.read();
      if (closing.done) return;
      if (done) { try { await writer.close(); } catch {} return; } // half-close upload side
      let frames;
      try { frames = unframer.push(new Uint8Array(value)); } catch { return finishAll(); }
      for (const f of frames) {
        let payload = f;
        if (proto === 'ss' && pumpRef.pump) {
          const r = await pumpRef.pump.feed(f);
          if (r.fatal) return finishAll();
          payload = r.plain;
        }
        if (payload?.length) { await writer.write(payload); up += payload.length; mark(); }
      }
    }
  });

  // phase 4: download — target → grpc-framed response stream
  const downloadPump = guard(async () => {
    const reader = socket.readable.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (closing.done || done) break;
      let out = value;
      if (proto === 'ss' && header.ssOut) out = new Uint8Array(await header.ssOut.encryptChunk(value));
      down += value.length;
      await dWriter.write(grpcEncode(out));
      mark();
    }
    await finishAll();
  });

  await Promise.allSettled([uploadPump(), downloadPump()]);
}

// ── XHTTP/SplitHTTP transport: GET {path}/{sid} = download, POST = upload ──
const XSESSIONS = new Map(); // isolate-local session registry
const X_TTL_MS = 120_000;

function sweepXsessions() {
  const t = now();
  for (const [sid, s] of XSESSIONS) if (t - s.at > X_TTL_MS) { try { s.finish?.(); } catch {} XSESSIONS.delete(sid); }
}

export async function handleXhttp(request, env, ctx) {
  sweepXsessions();
  const url = new URL(request.url);
  const p = parseXhttpPath(url.pathname);
  if (!p) return rejectPlain(404, 'bad xhttp path');
  const auth = await authStreamingRequest(env, request, p.proto, p.token);
  if (auth.reject) return auth.reject;
  const user = auth.user;

  let sess = XSESSIONS.get(p.sid);
  if (!sess) {
    bufferTraffic(user.id, 0, 0, 1);
    sess = {
      sid: p.sid, proto: p.proto, user, at: now(), ready: false, header: null,
      bufRef: { buf: new Uint8Array(0) }, pumpRef: { pump: null },
      pendingUp: [], dWriter: null, downAlive: false,
      socket: null, writer: null, closing: false,
      up: 0, down: 0, halfCloseTimer: null, uploadChain: Promise.resolve(),
      finish: null,
    };
    sess.finish = () => {
      if (sess.closing) return;
      sess.closing = true;
      clearTimeout(sess.halfCloseTimer);
      bufferTraffic(user.id, sess.up, sess.down);
      silentClose(sess.writer);
      try { sess.socket?.close(); } catch {}
      silentClose(sess.dWriter);
      XSESSIONS.delete(p.sid);
    };
    XSESSIONS.set(p.sid, sess);
  }
  sess.at = now();

  if (request.method === 'GET') {
    const { readable, writable } = new IdentityTransformStream();
    silentClose(sess.dWriter); // replace a stale/closed download stream (client reconnect)
    sess.dWriter = writable.getWriter();
    ctx.waitUntil(attachDownstream(sess).catch(() => sess.finish()));
    ctx.waitUntil(xhttpWatchdog(sess));
    return new Response(readable, {
      status: 200,
      headers: { 'content-type': 'application/octet-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' },
    });
  }
  if (request.method === 'POST') {
    // serialize concurrent upload POSTs through a per-session chain (packet-up mode)
    sess.uploadChain = sess.uploadChain.then(() => xhttpUpload(request, env, sess)).catch(() => sess.finish());
    ctx.waitUntil(sess.uploadChain);
    return new Response(null, { status: 204 });
  }
  return rejectPlain(405, 'method not allowed');
}

async function xhttpWatchdog(sess) {
  for (;;) {
    await new Promise(r => setTimeout(r, 30_000));
    if (sess.closing) return;
    if (now() - sess.at > X_TTL_MS) return sess.finish();
  }
}

// downstream pump: target socket → GET stream. The GET may arrive before or after
// the POST that carries the header, and clients may reconnect the download stream.
async function attachDownstream(sess) {
  if (sess.downAlive) return; // a pump is already streaming into the current writer
  sess.downAlive = true;
  // wait for the POST side to finish parsing its header (GET may arrive first)
  const t0 = now();
  while (!sess.ready && !sess.closing && now() - t0 < X_TTL_MS) {
    await new Promise(r => setTimeout(r, 20));
  }
  if (sess.closing || !sess.socket) { sess.downAlive = false; return sess.finish(); }
  if (sess.proto === 'ss' && sess.ssOut) {
    try { await sess.dWriter.write(sess.ssOut.header); } // salt = first bytes of the download stream
    catch { sess.downAlive = false; return; }
  }
  const reader = sess.socket.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (sess.closing || done) break;
    let out = value;
    if (sess.proto === 'ss' && sess.ssOut) out = await sess.ssOut.encryptChunk(value);
    sess.down += value.length;
    if (sess.down > 1 << 18) { bufferTraffic(sess.user.id, 0, sess.down); sess.down = 0; }
    let w = sess.dWriter;
    if (!w) { // download stream detached (client reconnecting) — brief wait, else drop this chunk
      const t1 = now();
      while (!(w = sess.dWriter) && !sess.closing && now() - t1 < 5000) {
        await new Promise(r => setTimeout(r, 20));
      }
      if (sess.closing) break;
      if (!w) continue;
    }
    try {
      await w.write(out instanceof Uint8Array ? out : new Uint8Array(out));
    } catch {
      silentClose(w);
      if (sess.dWriter === w) sess.dWriter = null; // next GET reattaches a fresh writer
    }
  }
  sess.downAlive = false;
  sess.finish();
}

// upload side: one or more POST bodies → protocol header (first) → target socket
async function xhttpUpload(request, env, sess) {
  clearTimeout(sess.halfCloseTimer); // a new packet arrived before the grace half-close fired
  const reader = request.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (sess.closing) return;
    if (done) {
      // end of one POST body: in stream-one mode this is the client's half-close; in
      // packet-up mode more POSTs follow — half-close only after a quiet grace period
      clearTimeout(sess.halfCloseTimer);
      sess.halfCloseTimer = setTimeout(async () => {
        if (!sess.closing && sess.ready && sess.writer) { try { await sess.writer.close(); } catch {} }
      }, 4000);
      return;
    }
    const chunk = new Uint8Array(value);
    if (!sess.ready) {
      sess.bufRef.buf = concatBytes(sess.bufRef.buf, chunk);
      if (sess.bufRef.buf.length > 65536) return sess.finish(); // header never completed
      const header = await parseStreamingHeader(env, sess.proto, sess.user, sess.bufRef, sess.pumpRef);
      if (header.error) return sess.finish();
      if (header.need) continue;
      sess.header = header;
      sess.ssOut = header.ssOut || null;
      if (header.leftover?.length) sess.pendingUp.push(header.leftover);
      try {
        sess.socket = connect({ hostname: header.host, port: header.port });
      } catch { return sess.finish(); }
      sess.writer = sess.socket.writable.getWriter();
      for (const p of sess.pendingUp) { await sess.writer.write(p); sess.up += p.length; }
      sess.pendingUp = [];
      sess.ready = true;
    } else {
      let payload = chunk;
      if (sess.proto === 'ss' && sess.pumpRef.pump) {
        const r = await sess.pumpRef.pump.feed(chunk);
        if (r.fatal) return sess.finish();
        payload = r.plain;
      }
      if (payload?.length) {
        await sess.writer.write(payload);
        sess.up += payload.length;
        if (sess.up > 1 << 18) { bufferTraffic(sess.user.id, sess.up, 0); sess.up = 0; }
      }
    }
  }
}
