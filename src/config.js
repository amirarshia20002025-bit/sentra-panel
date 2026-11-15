// SENTRA — settings layer: D1-backed key/value settings with KV read cache.
// All JSON-serializable. Defaults live here; the panel can override any subset.

const CACHE = new Map(); // settings cache (per isolate)
let CACHE_AT = 0;
const CACHE_TTL_MS = 30_000;

export const DEFAULTS = {
  installed: false,          // true once admin password is set via /install
  claim_token: '',           // first-run unification token (shown once)
  // — panel/branding —
  panel_lang: 'fa',          // fa | en | ru (labels live in the panel i18n table)
  node_template: 'SENTRA-{COUNTRY}-{ISP}-{NAME}',
  // — protocol defaults —
  default_transport: 'ws',
  // — extra transports (experimental; ws is always on) —
  transports: { ws: true, grpc: false, xhttp: false },
  security_level: 'balanced', // relaxed | balanced | hard (drives ECH/fragment/decoy presets)
  ech_enabled: true,
  ech_resolver: 'udp://1.1.1.1',
  fragment_enabled: true,
  fragment_len: '100-200',
  fragment_interval: '10-20',
  fingerprint: 'chrome',      // chrome | safari | ios | android | edge | firefox
  decoy_sni_enabled: false,
  decoy_hosts: [],            // up to 32 hostnames
  // — routing —
  adblock: true,
  pornblock: true,
  domestic_bypass: true,
  fakeip: false,
  block_quic: true,
  block_malware: true,
  ai_sanction_bypass: true,
  // — ISP clean-IP presets (editable in panel; applied to generated nodes) —
  isp_ips: {
    MCI: [], Irancell: [], Rightel: [], TCI: [], Gaming: [],
  },
  // — multi-location "VIP" list: country code -> preferred clean IP (optional) —
  locations: {},
  // — chains: user-supplied upstreams (socks5/http/https/turn/sstp) —
  chains: [],
  // — WARP/amnezia client credential block (private key, peer pubkey, addresses...) —
  warp: null,
  // — ops —
  kill_switch: false,        // global stop: all relays and subscriptions off
  github_mirror_repo: '',    // owner/name for raw.githubusercontent sub mirror
  tg_bot_token: '',
  tg_chat_id: '',
  tg_notify: true,
  webproxy_enabled: false,   // Telegram web reverse proxy on /tgk /tgz
  backup_note: '',
};

export async function getSettings(env) {
  const now = Date.now();
  if (CACHE_AT && now - CACHE_AT < CACHE_TTL_MS && CACHE.has('__all__')) {
    return CACHE.get('__all__');
  }
  const stored = {};
  try {
    const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
    for (const row of results) {
      try { stored[row.key] = JSON.parse(row.value); } catch { stored[row.key] = row.value; }
    }
  } catch (e) {
    // D1 unavailable (first run before db:init): fall back to defaults
    stored.__db_error = String(e);
  }
  const merged = structuredClone(DEFAULTS);
  for (const [k, v] of Object.entries(stored)) {
    if (k in merged && v !== null && typeof v === 'object' && !Array.isArray(v) &&
        typeof merged[k] === 'object' && merged[k] !== null && !Array.isArray(merged[k])) {
      merged[k] = { ...merged[k], ...v };
    } else {
      merged[k] = v;
    }
  }
  CACHE.set('__all__', merged);
  CACHE_AT = now;
  return merged;
}

export function invalidateSettingsCache() {
  CACHE.clear();
  CACHE_AT = 0;
}

export async function setSetting(env, key, value) {
  await env.DB.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).bind(key, JSON.stringify(value)).run();
  invalidateSettingsCache();
}

export async function setSettingsBulk(env, obj) {
  const stmt = env.DB.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  );
  const batch = Object.entries(obj).map(([k, v]) => stmt.bind(k, JSON.stringify(v)));
  if (batch.length) await env.DB.batch(batch);
  invalidateSettingsCache();
}

export function sanitizeSettingsPatch(patch) {
  const allowed = new Set(Object.keys(DEFAULTS));
  const out = {};
  for (const [k, v] of Object.entries(patch || {})) {
    if (!allowed.has(k)) continue;
    if (k === 'installed' || k === 'claim_token') continue; // handled by install flow only
    out[k] = v;
  }
  return out;
}
