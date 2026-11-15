// SENTRA — subscription endpoint: UA-sniffed formats, quota headers, self-service page.

import { getUserByToken, flushTraffic } from './db.js';
import { getSettings } from './config.js';
import { buildUserNodes, buildNodeUri } from './protocols/links.js';
import { emitBase64, emitClash, emitSingbox, FORMAT_CONTENT_TYPES } from './protocols/formats.js';

function detectFormat(request, urlPath, explicit) {
  if (explicit && FORMAT_CONTENT_TYPES[explicit]) return explicit;
  const ua = request.headers.get('user-agent') || '';
  if (/sing-box|SFI\/|SFA\/|SFM\/|SFG\/|SagerNet/i.test(ua)) return 'singbox';
  if (/clash|mihomo|meta|verge|Stash|FoXray/i.test(ua)) return 'clash';
  if (urlPath.endsWith('/clash')) return 'clash';
  if (urlPath.endsWith('/singbox') || urlPath.endsWith('/sing-box')) return 'singbox';
  if (urlPath.endsWith('/raw')) return 'raw';
  return 'base64';
}

export function quotaHeaders(user, settings) {
  const total = user.quotaBytes > 0 ? user.quotaBytes : 1024 * 1024 * 1024 * 1024; // 1TB cap shown for unlimited
  const expire = user.expiresAt > 0 ? Math.floor(user.expiresAt / 1000) : 0;
  return {
    'subscription-userinfo': `upload=0; download=${user.usedBytes}; total=${total}; expire=${expire}`,
    'profile-update-interval': '6',
    'profile-web-page-url': '',
    'content-disposition': `attachment; filename="sentra-${user.token}.conf"`,
  };
}

export async function handleSubscription(request, env, ctx) {
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/sub\/([A-Za-z0-9]+)(?:\/([a-z-]+))?$/);
  if (!m) return new Response('not found', { status: 404 });
  const [, token, pathFmt] = m;

  const settings = await getSettings(env);
  if (settings.kill_switch) return new Response('service disabled', { status: 503 });

  if (pathFmt === 'view') return selfServicePage(request, env, settings, token);

  const user = await getUserByToken(env, token);
  if (!user || !user.enabled) return new Response('subscription not found', { status: 404 });

  // best-effort usage flush so clients see fresh quota numbers
  ctx.waitUntil(flushTraffic(env).catch(() => {}));

  const format = detectFormat(request, url.pathname, url.searchParams.get('format'));
  const isp = url.searchParams.get('isp');
  const hostname = request.headers.get('x-forwarded-host') || url.hostname;
  let nodes = buildUserNodes(user, settings, { hostname });
  if (isp && isp !== 'all') {
    const filtered = nodes.filter(n => (n.isp || 'NET') === isp.toUpperCase());
    if (filtered.length) nodes = filtered;
  }

  let body, ctype = FORMAT_CONTENT_TYPES[format] || 'text/plain';
  if (format === 'clash') body = emitClash(nodes, settings, user);
  else if (format === 'singbox') body = emitSingbox(nodes, settings, user);
  else if (format === 'raw') body = nodes.map(buildNodeUri).join('\n');
  else body = emitBase64(nodes);

  const headers = { 'content-type': ctype, ...quotaHeaders(user, settings) };
  if (format === 'clash') {
    headers['profile-web-page-url'] = `https://${hostname}/sub/${token}/view`;
    headers['subscription-userinfo'] = headers['subscription-userinfo'];
  }
  return new Response(body, { headers });
}

// ── self-service page: user sees their own quota + links (+QR when vendor lib present) ──
async function selfServicePage(request, env, settings, token) {
  const user = await getUserByToken(env, token);
  if (!user) return new Response('not found', { status: 404 });
  const hostname = request.headers.get('x-forwarded-host') || new URL(request.url).hostname;
  const nodes = buildUserNodes(user, settings, { hostname });
  const pct = user.quotaBytes > 0 ? Math.min(100, Math.round(user.usedBytes / user.quotaBytes * 100)) : 0;
  const links = nodes.map(n => ({ name: n.name, uri: buildNodeUri(n) }));
  const gb = (n) => n > 0 ? (n / 1024 ** 3).toFixed(1) + ' GB' : '∞';
  const exp = user.expiresAt > 0 ? new Date(user.expiresAt).toISOString().slice(0, 10) : '∞';
  const subUrl = `https://${hostname}/sub/${token}`;
  const eSub = encodeURIComponent(subUrl);
  const b64Sub = btoa(subUrl); // Shadowrocket wants base64(sub-url)
  const html = `<!doctype html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTRA — اشتراک ${esc(user.name)}</title>
<style>
:root{color-scheme:dark}
body{background:#000;color:#e5e7eb;font-family:Vazirmatn,Tahoma,sans-serif;margin:0;padding:24px}
.card{background:#0b1220;border:1px solid #1e2a3a;border-radius:14px;padding:16px;max-width:820px;margin:0 auto 16px}
h1{font-size:18px;margin:0 0 12px}h2{font-size:15px}
.bar{height:8px;background:#1e2a3a;border-radius:4px;overflow:hidden}
.bar>div{height:100%;background:#2f9e8f}
.link{background:#101b2c;border:1px solid #233147;border-radius:8px;padding:8px 10px;font-size:11px;word-break:break-all;direction:ltr;text-align:left;margin:6px 0}
button{background:#2f9e8f;border:0;border-radius:8px;color:#04110e;padding:6px 12px;font-weight:700;cursor:pointer;margin:3px 2px}
</style></head><body>
<div class="card"><h1>📡 اشتراک: ${esc(user.name)}</h1>
<p>مصرف: ${gb(user.usedBytes)} از ${gb(user.quotaBytes)} — انقضا: ${exp}</p>
<div class="bar"><div style="width:${pct}%"></div></div></div>
<div class="card"><h2>لینک اشتراک (به همه کلاینت‌ها)</h2>
<div class="link" id="sub">${subUrl}</div>
<button onclick="cp('sub')">کپی اشتراک</button> <a href="?format=clash"><button>Clash</button></a> <a href="?format=singbox"><button>sing-box</button></a></div>
<div class="card"><h2>ایمپورت یک‌کلیکی</h2>
<p><a href="v2rayng://install-sub?url=${eSub}"><button>v2rayNG</button></a>
<a href="clash://install-config?url=${eSub}"><button>Clash / Mihomo</button></a>
<a href="sing-box://import-remote?url=${eSub}"><button>sing-box</button></a>
<a href="hiddify://import/sub?url=${eSub}"><button>Hiddify</button></a>
<a href="sub://${b64Sub}"><button>Shadowrocket</button></a>
<a href="streisand://import/${subUrl}"><button>Streisand</button></a>
<a href="pharos://import/sub?url=${eSub}"><button>Pharos</button></a></p>
<p style="color:#5f7581;font-size:11px">روی گوشی که اپ نصب است، دکمه را بزنید تا اشتراک مستقیم اضافه شود.</p></div>
<div class="card"><h2>لینک‌های مستقیم</h2>${links.map(l =>
  `<div><b>${esc(l.name)}</b></div><div class="link">${esc(l.uri)}</div>`).join('')}</div>
<div class="card"><h2 id="qr-title">QR</h2><div id="qr" style="background:#fff;padding:8px;display:inline-block"></div></div>
<script src="/vendor/qrcode.js"></script>
<script>
function cp(id){navigator.clipboard.writeText(document.getElementById(id).textContent.trim())}
try{
  const q=window.qrcode(0,'M');q.addData(document.getElementById('sub').textContent.trim());q.make();
  document.getElementById('qr').innerHTML=q.createSvgTag({cellSize:4});
}catch(e){document.getElementById('qr-title').textContent='QR در دسترس نیست'}
</script></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
