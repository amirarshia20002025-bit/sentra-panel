// SENTRA — clean Cloudflare-IP scanner (server-side TCP probe) + candidate IP pool.
// The pool is a small static sample of the public Cloudflare ranges; the client-side
// Radar (in the panel) measures real HTTP latency from the user's own network, which is
// the measurement that actually matters for their ISP.

import { connect } from 'cloudflare:sockets';
import { saveScan, loadScan, now } from './db.js';
import { getSettings } from './config.js';

// Sample of public Cloudflare IPv4 ranges (docs: https://www.cloudflare.com/ips-v4)
const CF_CIDRS = [
  '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '141.101.64.0/18', '162.158.0.0/15', '108.162.192.0/18', '190.93.240.0/20',
  '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '173.245.48.0/20',
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
];

// deterministic spread: pick `count` representative IPs from different ranges
export function sampleCfIps(count = 24) {
  const out = new Set();
  for (const cidr of CF_CIDRS) {
    const [base, bits] = cidr.split('/');
    const [a, b, c] = base.split('.').map(Number);
    const hostBits = 32 - parseInt(bits, 10);
    // take a few offsets across the range (skip .0 and .255-style edges)
    for (const frac of [0.05, 0.3, 0.55, 0.8]) {
      const h = Math.floor((2 ** hostBits - 2) * frac) + 1;
      out.add(`${a}.${b}.${c + (h >> 8)}.${h & 255}`);
      if (out.size >= count) break;
    }
    if (out.size >= count) break;
  }
  return [...out].slice(0, count);
}

// TCP-connect latency probe (no TLS handshake; safe "reachable" signal)
async function probeTcp(ip, port = 443, timeoutMs = 3000) {
  const t0 = Date.now();
  try {
    const socket = connect({ hostname: ip, port });
    const writer = socket.writable.getWriter();
    const read = socket.readable.getReader();
    await Promise.race([writer.write(new Uint8Array(0)), timeout(timeoutMs)]);
    const latency = Date.now() - t0;
    await writer.close().catch(() => {});
    try { socket.close(); } catch {}
    return { ip, ok: true, latency };
  } catch {
    return { ip, ok: false, latency: 0 };
  }
}
const timeout = (ms) => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms));

export async function runScan(env, count = 20) {
  const ips = sampleCfIps(count);
  const results = await Promise.all(ips.map(ip => probeTcp(ip)));
  await saveScan(env, results);
  return results.sort((a, b) => a.latency - b.latency);
}

export async function bestIps(env, n = 5, maxAgeMs = 6 * 3600_000) {
  const rows = await loadScan(env, maxAgeMs);
  return rows.filter(r => r.ok).slice(0, n);
}

// ── client-side Radar candidates: the panel JS pings these from the user's browser ──
export async function radarCandidates(env) {
  const settings = await getSettings(env);
  const cached = await bestIps(env, 12);
  const pool = cached.length >= 6 ? cached.map(r => r.ip) : sampleCfIps(28);
  return { pool, isps: settings.isp_ips || {} };
}
