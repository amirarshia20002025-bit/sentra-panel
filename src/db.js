// SENTRA — D1 data layer: users, traffic accounting, audit log, scan cache, uuid map.
import { invalidateSettingsCache } from './config.js';

// ── helpers ──
export const now = () => Date.now();
export const todayUTC = () => new Date().toISOString().slice(0, 10);

export function randomHex(nBytes) {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function randomToken(len = 24) {
  const abc = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return [...b].map(x => abc[x % abc.length]).join('');
}

export function randomUuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ── users ──
const USER_COLS = 'id, name, token, uuid, password, enabled, quota_bytes, used_bytes, quota_requests, used_requests, ip_limit, start_on_first_connect, duration_days, started_at, expires_at, reset_period, last_reset_at, isp_tag, note, created_at';

function rowToUser(r) {
  return {
    id: r.id, name: r.name, token: r.token, uuid: r.uuid, password: r.password,
    enabled: !!r.enabled, quotaBytes: r.quota_bytes, usedBytes: r.used_bytes,
    quotaRequests: r.quota_requests, usedRequests: r.used_requests,
    ipLimit: r.ip_limit, startOnFirstConnect: !!r.start_on_first_connect,
    durationDays: r.duration_days || 0, startedAt: r.started_at, expiresAt: r.expires_at, resetPeriod: r.reset_period,
    lastResetAt: r.last_reset_at, ispTag: r.isp_tag || '', note: r.note || '',
    createdAt: r.created_at,
  };
}

export async function createUser(env, u) {
  const t = now();
  const rec = {
    name: u.name || 'user', token: u.token || randomToken(20),
    uuid: u.uuid || randomUuid(), password: u.password || randomToken(16),
    quota_bytes: u.quotaBytes ?? 0, quota_requests: u.quotaRequests ?? 0,
    ip_limit: u.ipLimit ?? 0, start_on_first_connect: u.startOnFirstConnect ? 1 : 0,
    duration_days: u.durationDays ?? 0,
    expires_at: u.expiresAt ?? 0, reset_period: u.resetPeriod || 'never',
    isp_tag: u.ispTag || '', note: u.note || '',
  };
  const res = await env.DB.prepare(
    `INSERT INTO users (name, token, uuid, password, quota_bytes, quota_requests, ip_limit,
      start_on_first_connect, duration_days, expires_at, reset_period, isp_tag, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(rec.name, rec.token, rec.uuid, rec.password, rec.quota_bytes, rec.quota_requests,
    rec.ip_limit, rec.start_on_first_connect, rec.duration_days, rec.expires_at, rec.reset_period,
    rec.isp_tag, rec.note, t).run();
  await bumpUuidMapVersion(env);
  await logAudit(env, 'admin', 'user.create', rec.name);
  return { id: res.meta.last_row_id, ...rec, enabled: true, usedBytes: 0, usedRequests: 0 };
}

export async function updateUser(env, id, patch) {
  const map = {
    name: 'name', token: 'token', uuid: 'uuid', password: 'password',
    quotaBytes: 'quota_bytes', quotaRequests: 'quota_requests', ipLimit: 'ip_limit',
    startOnFirstConnect: 'start_on_first_connect', durationDays: 'duration_days',
    expiresAt: 'expires_at', resetPeriod: 'reset_period', ispTag: 'isp_tag', note: 'note',
    startedAt: 'started_at',
  };
  const sets = [], vals = [];
  for (const [k, col] of Object.entries(map)) {
    if (k in patch) { sets.push(`${col} = ?`); vals.push(patch[k]); }
  }
  if ('enabled' in patch) { sets.push('enabled = ?'); vals.push(patch.enabled ? 1 : 0); }
  if ('usedBytes' in patch) { sets.push('used_bytes = ?'); vals.push(patch.usedBytes); }
  if ('usedRequests' in patch) { sets.push('used_requests = ?'); vals.push(patch.usedRequests); }
  if (!sets.length) return;
  vals.push(id);
  await env.DB.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  await bumpUuidMapVersion(env);
}

export async function deleteUser(env, id) {
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM traffic_daily WHERE user_id = ?').bind(id).run();
  await bumpUuidMapVersion(env);
  await logAudit(env, 'admin', 'user.delete', String(id));
}

export async function listUsers(env) {
  const { results } = await env.DB.prepare(`SELECT ${USER_COLS} FROM users ORDER BY id DESC`).all();
  return results.map(rowToUser);
}

export async function getUserById(env, id) {
  const r = await env.DB.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).bind(id).first();
  return r ? rowToUser(r) : null;
}

export async function getUserByToken(env, token) {
  const r = await env.DB.prepare(`SELECT ${USER_COLS} FROM users WHERE token = ?`).bind(token).first();
  return r ? rowToUser(r) : null;
}

// ── credential → user map (KV cached, version-stamped) ──
let UUID_MAP = null, UUID_MAP_AT = 0;
const UUID_MAP_TTL_MS = 60_000;

async function bumpUuidMapVersion(env) {
  UUID_MAP = null; UUID_MAP_AT = 0;
  try { await env.KV.put('uuidmap_ver', String(now())); } catch {}
}

export async function buildUuidMap(env) {
  const users = await listUsers(env);
  const m = { vless: {}, trojan: {} };
  for (const u of users) {
    if (!u.enabled) continue;
    if (u.uuid) m.vless[u.uuid.toLowerCase()] = u.id;
    if (u.password) m.trojan[await sha224Hex(u.password)] = u.id;
  }
  try { await env.KV.put('uuidmap', JSON.stringify(m)); } catch {}
  return m;
}

export async function getCredMap(env) {
  if (UUID_MAP && now() - UUID_MAP_AT < UUID_MAP_TTL_MS) return UUID_MAP;
  try {
    const raw = await env.KV.get('uuidmap');
    if (raw) { UUID_MAP = JSON.parse(raw); UUID_MAP_AT = now(); return UUID_MAP; }
  } catch {}
  UUID_MAP = await buildUuidMap(env);
  UUID_MAP_AT = now();
  return UUID_MAP;
}

// ── traffic accounting (isolate-local buffer, flushed by cron or on demand) ──
const TRAFFIC = new Map(); // userId -> {up, down, req}

export function bufferTraffic(userId, up, down, req = 0) {
  const t = TRAFFIC.get(userId) || { up: 0, down: 0, req: 0 };
  t.up += up; t.down += down; t.req += req;
  TRAFFIC.set(userId, t);
}

export async function flushTraffic(env) {
  if (!TRAFFIC.size) return 0;
  const day = todayUTC();
  const stmtUser = env.DB.prepare('UPDATE users SET used_bytes = used_bytes + ?, used_requests = used_requests + ? WHERE id = ?');
  const stmtDay = env.DB.prepare(
    `INSERT INTO traffic_daily (user_id, day, up, down) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, day) DO UPDATE SET up = up + excluded.up, down = down + excluded.down`);
  const batch = [];
  let totalBytes = 0;
  for (const [uid, t] of TRAFFIC.entries()) {
    batch.push(stmtUser.bind(t.up + t.down, t.req, uid));
    batch.push(stmtDay.bind(uid, day, t.up, t.down));
    totalBytes += t.up + t.down;
  }
  TRAFFIC.clear();
  await env.DB.batch(batch);
  return totalBytes;
}

export async function resetQuotas(env, period) {
  const p = ['daily', 'weekly', 'monthly'];
  const users = await listUsers(env);
  const stmt = env.DB.prepare('UPDATE users SET used_bytes = 0, used_requests = 0, last_reset_at = ? WHERE id = ? AND reset_period = ?');
  const day = now();
  const batch = users
    .filter(u => u.resetPeriod === period && p.includes(period))
    .map(u => stmt.bind(day, u.id, period));
  if (batch.length) await env.DB.batch(batch);
  await logAudit(env, 'system', `quota.reset.${period}`, `${batch.length} users`);
  return batch.length;
}

export async function expireSweep(env) {
  const t = now();
  await env.DB.prepare('UPDATE users SET enabled = 0 WHERE enabled = 1 AND expires_at > 0 AND expires_at < ?').bind(t).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t).run();
  await bumpUuidMapVersion(env);
}

// ── audit log ──
export async function logAudit(env, actor, action, detail = '') {
  try {
    await env.DB.prepare('INSERT INTO audit_log (at, actor, action, detail) VALUES (?, ?, ?, ?)')
      .bind(now(), actor, action, String(detail).slice(0, 400)).run();
  } catch {}
}

export async function recentAudit(env, limit = 50) {
  const { results } = await env.DB.prepare('SELECT at, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?').bind(limit).all();
  return results;
}

// ── scan cache ──
export async function saveScan(env, rows) {
  if (!rows.length) return;
  const stmt = env.DB.prepare(
    `INSERT INTO scan_cache (ip, ok, latency, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET ok = excluded.ok, latency = excluded.latency, updated_at = excluded.updated_at`);
  await env.DB.batch(rows.map(r => stmt.bind(r.ip, r.ok ? 1 : 0, r.latency, now())));
}

export async function loadScan(env, maxAgeMs = 6 * 3600_000) {
  const { results } = await env.DB.prepare(
    'SELECT ip, ok, latency FROM scan_cache WHERE updated_at > ? ORDER BY latency ASC LIMIT 60'
  ).bind(now() - maxAgeMs).all();
  return results.map(r => ({ ip: r.ip, ok: !!r.ok, latency: r.latency }));
}

// ── pure SHA-224 (Trojan auth needs it; WebCrypto lacks SHA-224) ──
// Standard FIPS 180-4 SHA-224: SHA-256 round function with the SHA-224 initial state,
// output = first 28 bytes of the final 32-byte state. Implemented from the spec.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
// SHA-224 initial hash values (distinct from SHA-256's)
const H224 = new Uint32Array([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);

export async function sha224Hex(input) {
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const bitLen = msg.length * 8;
  const withPad = new Uint8Array(((msg.length + 8) >> 6 << 6) + 64);
  withPad.set(msg);
  withPad[msg.length] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(withPad.length - 4, bitLen >>> 0);
  const h = Uint32Array.from(H224);
  const w = new Uint32Array(64);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    const upd = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i] + upd[i]) >>> 0;
  }
  // SHA-224 output: first 7 words (28 bytes) of the state
  return h.subarray(0, 7).reduce((s, x) => s + x.toString(16).padStart(8, '0'), '');
}
