// SENTRA — admin API: login/install, users CRUD + bulk ops, settings, stats, scan,
// backup export/import, kill switch, audit. All mutations require session + CSRF.

import {
  listUsers, createUser, updateUser, deleteUser, getUserById, flushTraffic,
  resetQuotas, expireSweep, recentAudit, logAudit, now, randomToken, randomUuid, loadScan,
} from './db.js';
import { getSettings, setSettingsBulk, sanitizeSettingsPatch, invalidateSettingsCache } from './config.js';
import {
  adminExists, setAdminPassword, verifyPassword, verifyTotp, consumeRecoveryCode,
  createSession, destroySession, getSession, sessionCookie, CLEAR_COOKIE,
  checkAttempts, recordFailure, clearAttempts, newCsrf, claimValid, ensureClaimToken, csrfOk,
} from './security.js';
import { runScan, radarCandidates } from './scanner.js';

const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', ...headers } });
const err = (status, msg) => json({ ok: false, error: msg }, status);

const clientIp = (req) => req.headers.get('cf-connecting-ip') || '0.0.0.0';
const cookieVal = (req, name) => (req.headers.get('cookie') || '').split(/;\s*/).map(s => s.split('=')) .find(([k]) => k === name)?.[1];

async function sessionOf(request, env) {
  return getSession(env, cookieVal(request, 'sentra_session'));
}

// ── router ──
export async function handleAdminApi(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  // ── public endpoints ──
  if (path === '/admin/api/install-info' && method === 'GET') {
    const installed = await adminExists(env);
    let claim = null;
    if (!installed) claim = await ensureClaimToken(env);
    return json({ ok: true, installed, claim });
  }
  if (path === '/admin/api/install' && method === 'POST') {
    const installed = await adminExists(env);
    if (installed) return err(400, 'already installed');
    const body = await request.json().catch(() => ({}));
    if (!await claimValid(env, body.claim_token || '')) return err(403, 'invalid claim token');
    if (!body.password || String(body.password).length < 8) return err(400, 'password too short (min 8)');
    const out = await setAdminPassword(env, String(body.password));
    await logAudit(env, 'admin', 'install.done', '');
    return json({ ok: true, recoveryCodes: out.recoveryCodes, totpSecret: out.totpSecret });
  }
  if (path === '/admin/api/login' && method === 'POST') {
    const gate = checkAttempts(clientIp(request));
    if (!gate.ok) return err(429, `too many attempts; retry in ${Math.ceil(gate.retryInMs / 60000)} min`);
    const body = await request.json().catch(() => ({}));
    const s = await getSettings(env);
    const ok = s.admin_auth && await verifyPassword(String(body.password || ''), s.admin_auth);
    if (!ok) { recordFailure(clientIp(request)); return err(403, 'wrong password'); }
    if (s.totp_enabled) {
      const code = String(body.totp || '').trim();
      const goodCode = code && await verifyTotp(env, code);
      const goodRec = !goodCode && code && await consumeRecoveryCode(env, code);
      if (!goodCode && !goodRec) { recordFailure(clientIp(request)); return err(403, '2FA code invalid'); }
    }
    clearAttempts(clientIp(request));
    const csrf = newCsrf();
    const sess = await createSession(env, { role: 'admin', csrf });
    return json({ ok: true, csrf }, 200, { 'set-cookie': sessionCookie(sess.token) });
  }

  // ── everything below needs an admin session ──
  const sess = await sessionOf(request, env);
  if (!sess || sess.role !== 'admin') return err(401, 'not signed in');
  if (method !== 'GET' && !csrfOk(request, sess)) return err(403, 'csrf mismatch');

  // users
  if (path === '/admin/api/users' && method === 'GET') {
    const users = await listUsers(env);
    return json({ ok: true, users });
  }
  if (path === '/admin/api/users' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const u = await createUser(env, {
      name: String(b.name || 'user').slice(0, 60),
      quotaBytes: num(b.quotaGb) > 0 ? Math.round(num(b.quotaGb) * 1024 ** 3) : 0,
      quotaRequests: num(b.quotaRequests),
      ipLimit: num(b.ipLimit),
      startOnFirstConnect: !!b.startOnFirstConnect,
      durationDays: num(b.durationDays),
      expiresAt: b.expiresAt ? Date.parse(b.expiresAt) : (num(b.durationDays) > 0 ? 0 : 0),
      resetPeriod: ['daily', 'weekly', 'monthly', 'never'].includes(b.resetPeriod) ? b.resetPeriod : 'never',
      ispTag: String(b.ispTag || '').slice(0, 12),
      note: String(b.note || '').slice(0, 200),
    });
    return json({ ok: true, user: u });
  }
  const um = path.match(/^\/admin\/api\/users\/(\d+)$/);
  if (um) {
    const id = parseInt(um[1], 10);
    if (method === 'PATCH') {
      const b = await request.json().catch(() => ({}));
      const patch = {};
      for (const k of ['name', 'note', 'resetPeriod', 'ispTag', 'resetPeriod']) if (k in b) patch[k] = b[k];
      if ('quotaGb' in b) patch.quotaBytes = num(b.quotaGb) > 0 ? Math.round(num(b.quotaGb) * 1024 ** 3) : 0;
      if ('quotaRequests' in b) patch.quotaRequests = num(b.quotaRequests);
      if ('ipLimit' in b) patch.ipLimit = num(b.ipLimit);
      if ('durationDays' in b) patch.durationDays = num(b.durationDays);
      if ('expiresAt' in b) patch.expiresAt = b.expiresAt ? Date.parse(b.expiresAt) : 0;
      if ('enabled' in b) patch.enabled = !!b.enabled;
      if ('startOnFirstConnect' in b) patch.startOnFirstConnect = !!b.startOnFirstConnect;
      if (b.rotateCredentials) { patch.uuid = randomUuid(); patch.password = randomToken(16); patch.token = randomToken(20); }
      await updateUser(env, id, patch);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await deleteUser(env, id);
      return json({ ok: true });
    }
  }
  if (path === '/admin/api/users/bulk' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const ids = (b.ids || []).map(Number).filter(Number.isFinite);
    const op = b.op;
    const stmt = { enable: { enabled: true }, disable: { enabled: false } };
    for (const id of ids) {
      if (op === 'delete') await deleteUser(env, id);
      else if (op === 'reset') await updateUser(env, id, { usedBytes: 0, usedRequests: 0 });
      else if (stmt[op]) await updateUser(env, id, stmt[op]);
    }
    await logAudit(env, 'admin', `user.bulk.${op}`, ids.join(','));
    return json({ ok: true, count: ids.length });
  }
  // per-user daily series (up/down) for the sparkline in the edit dialog
  const usm = path.match(/^\/admin\/api\/user-stats\/(\d+)$/);
  if (usm && method === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT day, up, down FROM traffic_daily WHERE user_id = ? AND day >= ? ORDER BY day ASC'
    ).bind(parseInt(usm[1], 10), new Date(now() - 14 * 86400_000).toISOString().slice(0, 10)).all();
    return json({ ok: true, daily: results });
  }

  // settings
  if (path === '/admin/api/settings' && method === 'GET') {
    const s = await getSettings(env);
    const masked = {
      ...s,
      admin_auth: undefined,
      claim_token: undefined,
      recovery_codes: undefined,
      tg_bot_token: s.tg_bot_token ? '•••stored•••' : '',
      has_totp: !!s.totp_secret,
    };
    return json({ ok: true, settings: masked });
  }
  if (path === '/admin/api/settings' && method === 'PATCH') {
    const b = await request.json().catch(() => ({}));
    const patch = sanitizeSettingsPatch(b);
    if (typeof b.tg_bot_token === 'string' && b.tg_bot_token && !b.tg_bot_token.startsWith('•••')) {
      patch.tg_bot_token = b.tg_bot_token.trim();
    }
    await setSettingsBulk(env, patch);
    await logAudit(env, 'admin', 'settings.patch', Object.keys(patch).join(','));
    return json({ ok: true });
  }

  // stats + ops
  if (path === '/admin/api/stats' && method === 'GET') {
    ctx.waitUntil(flushTraffic(env).catch(() => {}));
    const users = await listUsers(env);
    const { results: daily } = await env.DB.prepare(
      `SELECT day, SUM(up + down) AS bytes, SUM(up) AS up, SUM(down) AS down FROM traffic_daily WHERE day >= ?
       GROUP BY day ORDER BY day ASC`).bind(new Date(now() - 14 * 86400_000).toISOString().slice(0, 10)).all();
    const { results: topUsers } = await env.DB.prepare(
      'SELECT user_id, SUM(up + down) AS bytes FROM traffic_daily GROUP BY user_id ORDER BY bytes DESC LIMIT 8').all();
    const nameOf = Object.fromEntries(users.map(u => [u.id, u.name]));
    return json({
      ok: true,
      users: { total: users.length, active: users.filter(u => u.enabled).length },
      usage: users.reduce((s, u) => s + u.usedBytes, 0),
      daily: daily.map(r => ({ day: r.day, bytes: r.bytes })),
      topUsers: topUsers.map(r => ({ name: nameOf[r.user_id] || ('#' + r.user_id), bytes: r.bytes })),
      audit: await recentAudit(env, 20),
      scan: await loadScan(env),
    });
  }
  if (path === '/admin/api/scan' && method === 'POST') {
    const results = await runScan(env, 20);
    return json({ ok: true, results: results.slice(0, 10) });
  }
  if (path === '/admin/api/radar-pool' && method === 'GET') {
    return json({ ok: true, ...(await radarCandidates(env)) });
  }

  // backup / restore (owner-only; includes settings secrets — treat the file as a password)
  if (path === '/admin/api/backup' && method === 'GET') {
    const { results: settingsRows } = await env.DB.prepare('SELECT key, value FROM settings').all();
    const users = await listUsers(env);
    return new Response(JSON.stringify({ exported_at: now(), settings: settingsRows, users }, null, 2), {
      headers: { 'content-type': 'application/json', 'content-disposition': `attachment; filename="sentra-backup-${now()}.json"` },
    });
  }
  if (path === '/admin/api/restore' && method === 'POST') {
    const b = await request.json().catch(() => null);
    if (!b || !Array.isArray(b.users) || !Array.isArray(b.settings)) return err(400, 'bad backup format');
    const su = env.DB.prepare(
      `INSERT INTO users (name, token, uuid, password, enabled, quota_bytes, used_bytes, quota_requests, used_requests,
        ip_limit, start_on_first_connect, duration_days, started_at, expires_at, reset_period, last_reset_at, isp_tag, note, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(token) DO UPDATE SET name = excluded.name, enabled = excluded.enabled`);
    await env.DB.batch(b.users.map(u => su.bind(
      u.name, u.token, u.uuid, u.password, u.enabled ? 1 : 0, u.quotaBytes, u.usedBytes,
      u.quotaRequests, u.usedRequests, u.ipLimit, u.startOnFirstConnect ? 1 : 0, u.durationDays || 0,
      u.startedAt, u.expiresAt, u.resetPeriod, u.lastResetAt, u.ispTag, u.note, u.createdAt || now())));
    const ss = env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
    await env.DB.batch(b.settings.map(r => ss.bind(r.key, r.value)));
    invalidateSettingsCache();
    await logAudit(env, 'admin', 'backup.restore', `${b.users.length} users`);
    return json({ ok: true, restored: b.users.length });
  }

  // sessions / misc
  if (path === '/admin/api/logout' && method === 'POST') {
    await destroySession(env, cookieVal(request, 'sentra_session'));
    return json({ ok: true }, 200, { 'set-cookie': CLEAR_COOKIE });
  }
  if (path === '/admin/api/sweep' && method === 'POST') {
    await flushTraffic(env);
    await expireSweep(env);
    const n = await resetQuotas(env, sweepPeriod(url));
    return json({ ok: true, flushed: true, swept: true, resets: n });
  }

  return err(404, 'unknown admin api route');
}

function sweepPeriod(url) {
  const p = url.searchParams.get('period') || 'daily';
  return ['daily', 'weekly', 'monthly'].includes(p) ? p : 'daily';
}
const num = (v) => { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; };
