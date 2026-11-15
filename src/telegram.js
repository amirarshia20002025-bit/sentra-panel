// SENTRA — Telegram integration: webhook bot (user management + notifications)
// and the optional Telegram web reverse proxy (/tgk, /tgz paths).

import { listUsers, createUser, updateUser, deleteUser, getUserById, logAudit, now, randomToken, randomUuid } from './db.js';
import { getSettings, setSetting } from './config.js';
import { gateCheck } from './protocols/relay.js';

function apiBase(token) { return `https://api.telegram.org/bot${token}`; }

export async function tgCall(token, method, payload) {
  const res = await fetch(`${apiBase(token)}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return res.json().catch(() => null);
}

export async function notify(env, text) {
  const s = await getSettings(env);
  if (!s.tg_notify || !s.tg_bot_token || !s.tg_chat_id) return;
  await tgCall(s.tg_bot_token, 'sendMessage', {
    chat_id: s.tg_chat_id, text, parse_mode: 'HTML', disable_web_page_preview: true,
  });
}

// ── webhook entry: POST /bot/<secret> ──
export async function handleBotWebhook(request, env) {
  const url = new URL(request.url);
  const secret = url.pathname.split('/').pop();
  const settings = await getSettings(env);
  if (env.BOT_PATH_SECRET && secret !== env.BOT_PATH_SECRET) return new Response('forbidden', { status: 403 });

  const update = await request.json().catch(() => null);
  if (!update?.message) return new Response('ok');

  const msg = update.message;
  const chatId = msg.chat.id;
  const text = (msg.text || '').trim();
  const cmd = text.split(/\s+/);
  const lang = (settings.panel_lang === 'en') ? en : fa; // bot replies follow the panel language

  const knownOwner = String(settings.tg_chat_id || '') === String(chatId);
  if (!settings.tg_chat_id) {
    // first /start binds the owner — the token printed by /install must be sent first
    if (cmd[0] !== '/start' && cmd[0] !== '/claim') {
      await send(settings, chatId, lang.bindFirst);
      return new Response('ok');
    }
    if (cmd[0] === '/start') {
      await send(settings, chatId, `${lang.welcome}\n\n${lang.sendClaim}`);
      return new Response('ok');
    }
    if (cmd[0] === '/claim' && cmd[1] && cmd[1] === settings.claim_token) {
      await setSetting(env, 'tg_chat_id', String(chatId));
      await logAudit(env, 'bot', 'owner.bind', String(chatId));
      await send(settings, chatId, lang.ownerBound);
      return new Response('ok');
    }
  }
  if (!knownOwner) {
    await send(settings, chatId, lang.notOwner);
    return new Response('ok');
  }

  const reply = await execCommand(env, settings, cmd);
  await send(settings, chatId, reply);
  return new Response('ok');
}

async function send(settings, chatId, text) {
  await tgCall(settings.tg_bot_token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true });
}

async function execCommand(env, settings, cmd) {
  const lang = (settings.panel_lang === 'en') ? en : fa;
  const c0 = cmd[0];
  const hostname = settings.hostname || 'your-worker.workers.dev';
  switch (c0) {
    case '/start':
    case '/help':
      return lang.help(hostname);
    case '/status': {
      const users = await listUsers(env);
      const active = users.filter(u => u.enabled).length;
      const totalBytes = users.reduce((s, u) => s + u.usedBytes, 0);
      return lang.status(users.length, active, fmtBytes(totalBytes));
    }
    case '/adduser': {
      const name = cmd[1];
      if (!name) return lang.usageAdd;
      const gb = parseFloat(cmd[2]) || 0;
      const days = parseInt(cmd[3], 10) || 0;
      const u = await createUser(env, {
        name,
        quotaBytes: gb > 0 ? Math.round(gb * 1024 ** 3) : 0,
        expiresAt: days > 0 ? now() + days * 86400_000 : 0,
        startOnFirstConnect: days > 0 && cmd[4] === 'first',
        durationDays: days,
      });
      await notify(env, `➕ ${name} (${gb || '∞'}GB / ${days || '∞'}d)`);
      return lang.userAdded(u.name, u.token, `https://${hostname}/sub/${u.token}`);
    }
    case '/listusers': {
      const users = await listUsers(env);
      if (!users.length) return lang.noUsers;
      return users.slice(0, 30).map(u =>
        `${u.enabled ? '🟢' : '🔴'} <b>${esc(u.name)}</b> — ${fmtBytes(u.usedBytes)}${u.quotaBytes ? '/' + fmtBytes(u.quotaBytes) : ''} — id:${u.id}`).join('\n');
    }
    case '/deluser': {
      if (!cmd[1]) return lang.needId;
      await deleteUser(env, parseInt(cmd[1], 10));
      return lang.deleted;
    }
    case '/ban':
    case '/unban': {
      if (!cmd[1]) return lang.needId;
      const u = await getUserById(env, parseInt(cmd[1], 10));
      if (!u) return lang.notFound;
      await updateUser(env, u.id, { enabled: c0 === '/unban' });
      return `${c0 === '/ban' ? '⛔' : '✅'} ${esc(u.name)}`;
    }
    case '/sub': {
      if (!cmd[1]) return lang.needId;
      const u = await getUserById(env, parseInt(cmd[1], 10));
      if (!u) return lang.notFound;
      return `<code>https://${hostname}/sub/${u.token}</code>`;
    }
    case '/panel':
      return `https://${hostname}/admin`;
    default:
      return lang.unknownCmd;
  }
}

const esc = (s) => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const fmtBytes = (n) => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
};

// bilingual bot strings
const fa = {
  welcome: 'سلام! من ربات پنل SENTRA هستم.',
  sendClaim: 'برای اتصال به پنل خودتان، دستور زیر را بفرستید:\n<code>/claim توکن-نصب</code>',
  bindFirst: 'اول با <code>/claim توکن-نصب</code> صاحب پنل را معرفی کنید (توکن در صفحه /install دیده می‌شود).',
  ownerBound: '✅ شما صاحب پنل شدید.',
  notOwner: 'این پنل به مالک دیگری متصل است.',
  unknownCmd: 'دستور ناشناخته. /help را ببینید.',
  needId: 'شناسه عددی کاربر لازم است. مثلاً: /ban 3',
  notFound: 'کاربر پیدا نشد.',
  deleted: '🗑 کاربر حذف شد.',
  noUsers: 'هنوز کاربری ساخته نشده.',
  usageAdd: 'مثال: /adduser ali 50 30 first   (نام، حجم GB، روز، شمارش از اولین اتصال اختیاری)',
  userAdded: (n, t, link) => `✅ کاربر <b>${esc(n)}</b> ساخته شد.\nتوکن: <code>${t}</code>\nاشتراک:\n${link}`,
  status: (total, active, bytes) => `📊 کاربران: ${active} فعال از ${total}\nمصرف کل: ${bytes}`,
  help: (h) => `🔧 دستورات:\n/status — وضعیت\n/adduser نام [GB] [روز] [first]\n/listusers\n/sub id\n/ban id /unban id\n/deluser id\n/panel\n\nپنل: ${h}/admin`,
};
const en = {
  welcome: 'Hello! I am the SENTRA panel bot.',
  sendClaim: 'Bind yourself as owner:\n<code>/claim install-token</code>',
  bindFirst: 'First bind the owner with <code>/claim install-token</code> (shown on /install).',
  ownerBound: '✅ You are the panel owner now.',
  notOwner: 'This panel belongs to another owner.',
  unknownCmd: 'Unknown command. See /help.',
  needId: 'Numeric user id required. e.g. /ban 3',
  notFound: 'User not found.',
  deleted: '🗑 User deleted.',
  noUsers: 'No users yet.',
  usageAdd: 'Example: /adduser ali 50 30 first  (name, GB, days, count-from-first-connect optional)',
  userAdded: (n, t, link) => `✅ User <b>${esc(n)}</b> created.\nToken: <code>${t}</code>\nSubscription:\n${link}`,
  status: (total, active, bytes) => `📊 Users: ${active}/${total} active\nTotal usage: ${bytes}`,
  help: (h) => `🔧 Commands:\n/status\n/adduser name [GB] [days] [first]\n/listusers\n/sub id\n/ban id /unban id\n/deluser id\n/panel\n\nPanel: ${h}/admin`,
};

// ── Telegram web reverse proxy (optional, mirrors web.telegram.org) ──
export async function handleTgWebProxy(request, variant = 'k') {
  const url = new URL(request.url);
  const target = `https://web.telegram.org/${variant}${url.pathname.replace(/^\/tg[ kz]/, '') || '/'}`;
  const res = await fetch(target, {
    headers: {
      'user-agent': request.headers.get('user-agent') || 'Mozilla/5.0',
      'accept': request.headers.get('accept') || '*/*',
    },
    redirect: 'manual',
  });
  const headers = new Headers(res.headers);
  headers.delete('content-security-policy');
  headers.delete('x-frame-options');
  headers.set('access-control-allow-origin', '*');
  return new Response(res.body, { status: res.status, headers });
}
