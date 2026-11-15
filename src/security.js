// SENTRA — security layer: password hashing (PBKDF2), sessions, login-attempt throttle,
// TOTP 2FA (RFC 6238) with recovery codes, first-run claim token, CSRF tokens.

import { now, randomToken, randomHex, logAudit } from './db.js';
import { getSettings, setSetting, setSettingsBulk, invalidateSettingsCache } from './config.js';

const SESSION_TTL_MS = 12 * 3600_000;
const ATTEMPT_WINDOW_MS = 15 * 60_000;
const ATTEMPT_MAX = 5;
const ATTEMPTS = new Map(); // ip -> {count, last}

const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

// ── password hashing ──
export async function hashPassword(password, saltHex = null, iterations = 120_000) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return { hash: hex(bits), salt: hex(salt), iterations };
}
export async function verifyPassword(password, record) {
  const cand = await hashPassword(password, record.salt, record.iterations || 120_000);
  const a = cand.hash, b = record.hash;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const hexToBytes = h => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)));

// ── admin credentials ──
export async function adminExists(env) {
  const s = await getSettings(env);
  return !!(s.admin_auth && s.admin_auth.hash);
}
export async function setAdminPassword(env, password) {
  const rec = await hashPassword(password);
  const totp = await generateTotpSecret();
  const recovery = Array.from({ length: 10 }, () => randomToken(10));
  const recoveryRecords = [];
  for (const r of recovery) recoveryRecords.push(await hashPassword(r));
  await setSettingsBulk(env, {
    admin_auth: rec,
    totp_secret: totp,
    totp_enabled: false,
    recovery_codes: recoveryRecords,
    installed: true,
  });
  return { recoveryCodes: recovery, totpSecret: totp };
}

// ── login throttle ──
export function checkAttempts(ip) {
  const rec = ATTEMPTS.get(ip);
  if (!rec) return { ok: true, remaining: ATTEMPT_MAX };
  if (now() - rec.last > ATTEMPT_WINDOW_MS) { ATTEMPTS.delete(ip); return { ok: true, remaining: ATTEMPT_MAX }; }
  if (rec.count >= ATTEMPT_MAX) return { ok: false, retryInMs: ATTEMPT_WINDOW_MS - (now() - rec.last) };
  return { ok: true, remaining: ATTEMPT_MAX - rec.count };
}
export function recordFailure(ip) {
  const rec = ATTEMPTS.get(ip) || { count: 0, last: now() };
  rec.count += 1; rec.last = now();
  ATTEMPTS.set(ip, rec);
  if (ATTEMPTS.size > 512) {
    for (const [k, v] of ATTEMPTS) if (now() - v.last > ATTEMPT_WINDOW_MS) ATTEMPTS.delete(k);
  }
}
export function clearAttempts(ip) { ATTEMPTS.delete(ip); }

// ── sessions (KV for speed + D1 for durability) ──
export async function createSession(env, data = {}) {
  const token = randomToken(40);
  const rec = { data, created: now() };
  const exp = now() + SESSION_TTL_MS;
  try { await env.KV.put('sess:' + token, JSON.stringify(rec), { expirationTtl: Math.floor(SESSION_TTL_MS / 1000) }); } catch {}
  try { await env.DB.prepare('INSERT INTO sessions (token, data, expires_at) VALUES (?, ?, ?)').bind(token, JSON.stringify(rec), exp).run(); } catch {}
  return { token, expiresAt: exp };
}
export async function getSession(env, token) {
  if (!token) return null;
  try {
    const raw = await env.KV.get('sess:' + token);
    if (raw) return JSON.parse(raw).data;
  } catch {}
  try {
    const row = await env.DB.prepare('SELECT data FROM sessions WHERE token = ? AND expires_at > ?').bind(token, now()).first();
    return row ? JSON.parse(row.data).data : null;
  } catch { return null; }
}
export async function destroySession(env, token) {
  try { await env.KV.delete('sess:' + token); } catch {}
  try { await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run(); } catch {}
}
export function sessionCookie(token, maxAgeSec = SESSION_TTL_MS / 1000) {
  return `sentra_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}
export const CLEAR_COOKIE = 'sentra_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

// ── TOTP (RFC 6238, 6 digits, 30s, SHA-1) ──
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(bytes) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += B32[(val << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s) {
  let bits = 0, val = 0; const out = [];
  for (const ch of s.toUpperCase().replace(/=+$/, '')) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
export async function generateTotpSecret() {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}
export async function totpCode(secretB32, timeStep = Math.floor(Date.now() / 30_000)) {
  const key = await crypto.subtle.importKey('raw', base32Decode(secretB32), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, timeStep);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}
export async function verifyTotp(env, code) {
  const s = await getSettings(env);
  if (!s.totp_secret) return false;
  const step = Math.floor(Date.now() / 30_000);
  for (const d of [-1, 0, 1]) {
    if ((await totpCode(s.totp_secret, step + d)) === String(code).trim()) return true;
  }
  return false;
}
export async function consumeRecoveryCode(env, code) {
  const s = await getSettings(env);
  const codes = s.recovery_codes || [];
  for (let i = 0; i < codes.length; i++) {
    const rec = codes[i];
    if (rec && typeof rec === 'object' && rec.hash && await verifyPassword(String(code), rec)) {
      codes[i] = null; // one-time use
      await setSetting(env, 'recovery_codes', codes);
      return true;
    }
  }
  return false;
}
export async function setRecoveryCodes(env, codes) {
  const recs = [];
  for (const c of codes) recs.push(await hashPassword(c));
  await setSetting(env, 'recovery_codes', recs);
}

// ── first-run claim (binds panel to its owner; token shown exactly once) ──
export async function ensureClaimToken(env) {
  const s = await getSettings(env);
  if (s.claim_token) return s.claim_token;
  const token = randomToken(16) + '-' + randomHex(4);
  await setSetting(env, 'claim_token', token);
  await logAudit(env, 'system', 'install.claim.generated', '');
  return token;
}
export async function claimValid(env, token) {
  const s = await getSettings(env);
  return !!s.claim_token && token === s.claim_token;
}

// ── CSRF ──
export function newCsrf() { return randomToken(24); }
export function csrfOk(req, sess) {
  const got = req.headers.get('x-sentra-csrf') || '';
  return !!sess?.csrf && got === sess.csrf;
}
