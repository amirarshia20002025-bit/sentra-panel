// SENTRA — Worker entry: routes fetch/upgrade/scheduled events to the right module.

import { handleWsUpgrade, handleGrpcPost, handleXhttp } from './protocols/relay.js';
import { handleAdminApi } from './admin.js';
import { handleSubscription } from './subscriptions.js';
import { panelPage, landingPage } from './panel.js';
import { handleBotWebhook, handleTgWebProxy } from './telegram.js';
import { getSettings } from './config.js';
import { flushTraffic, expireSweep, resetQuotas, logAudit } from './db.js';
import QR_LIB from './vendor/qrcode.js.txt'; // Text-rule embedded (wrangler.toml [[rules]])

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // WebSocket relay
    if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      return handleWsUpgrade(request, env, ctx);
    }

    try {
      // landing
      if (path === '/' && request.method === 'GET') return landingPage(url.hostname);

      // panel SPA (both /admin and /install serve the same app; state comes from the API)
      if ((path === '/admin' || path === '/install') && request.method === 'GET') return panelPage();

      // admin api
      if (path.startsWith('/admin/api/')) return handleAdminApi(request, env, ctx);

      // subscriptions (base64/clash/singbox/view)
      if (path.startsWith('/sub/')) return handleSubscription(request, env, ctx);

      // streaming transports (experimental): gRPC POST + XHTTP GET/POST sessions
      if (path.startsWith('/grpc/') && request.method === 'POST') return handleGrpcPost(request, env, ctx);
      if (path.startsWith('/xhttp/')) return handleXhttp(request, env, ctx);

      // telegram bot webhook
      if (path.startsWith('/bot/') && request.method === 'POST') return handleBotWebhook(request, env);

      // optional telegram web reverse proxy
      if (path.startsWith('/tgk/') || path.startsWith('/tgz/')) {
        const s = await getSettings(env);
        if (!s.webproxy_enabled) return new Response('disabled', { status: 404 });
        return handleTgWebProxy(request, path.startsWith('/tgk/') ? 'k' : 'z');
      }

      // vendored QR library (MIT)
      if (path === '/vendor/qrcode.js') {
        return new Response(QR_LIB, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=86400' } });
      }

      return new Response('not found', { status: 404 });
    } catch (e) {
      return new Response('internal error: ' + String(e).slice(0, 300), { status: 500 });
    }
  },

  // cron: flush buffered traffic, expire users, apply scheduled quota resets
  async scheduled(event, env, ctx) {
    try {
      const flushed = await flushTraffic(env);
      await expireSweep(env);
      const d = event.scheduledTime ? new Date(event.scheduledTime) : new Date();
      let resets = 0;
      resets += await resetQuotas(env, 'daily');
      if (d.getUTCDay() === 1) resets += await resetQuotas(env, 'weekly');
      if (d.getUTCDate() === 1) resets += await resetQuotas(env, 'monthly');
      await logAudit(env, 'system', 'cron', `flushed=${flushed} resets=${resets}`);
    } catch (e) {
      await logAudit(env, 'system', 'cron.error', String(e).slice(0, 200));
    }
  },
};
