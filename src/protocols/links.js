// SENTRA — pure config-node builders: internal Node shape → VLESS/Trojan/SS share URIs.
// URI conventions follow the public client implementations (Xray URI params, SIP002/SIP003).
// No Worker APIs here — unit-testable in Node.

export const SS_CIPHER = 'aes-256-gcm';

// ── node shape ──
// {
//   name, protocol: 'vless'|'trojan'|'ss',
//   server (address clients dial), port,
//   host (worker hostname used for SNI/Host), path,
//   uuid (vless) | password (trojan) | ssPassword (ss),
//   tls: true, sni, fp, ech, alpn, fragment: '100-200,10-20'|null,
//   isp, country, insecure:false
// }

export function formatNodeName(template, ctx) {
  // ctx: { name, country, isp, date }
  return (template || 'SENTRA-{COUNTRY}-{ISP}-{NAME}')
    .replace('{COUNTRY}', ctx.country || 'XX')
    .replace('{ISP}', ctx.isp || 'NET')
    .replace('{NAME}', ctx.name || '')
    .replace('{DATE}', ctx.date || new Date().toISOString().slice(0, 10))
    .replace('{FLAG}', ({ US: '🇺🇸', DE: '🇩🇪', GB: '🇬🇧', FR: '🇫🇷', NL: '🇳🇱', TR: '🇹🇷', CA: '🇨🇦', BR: '🇧🇷', UA: '🇺🇦', TH: '🇹🇭', RO: '🇷🇴', DK: '🇩🇰', FI: '🇫🇮', GL: '🇬🇱', CO: '🇨🇴', MX: '🇲🇽', PA: '🇵🇦', CU: '🇨🇺', AT: '🇦🇹', SE: '🇸🇪', IR: '🇮🇷' })[ctx.country] || '🌐')
    .trim();
}

function q(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&');
}

export function buildVlessUri(node) {
  const params = {
    type: node.transport || 'ws',
    security: 'tls',
    encryption: 'none',
    sni: node.sni,
    host: node.host_header || node.host,
    path: node.path || (node.transport === 'grpc' ? undefined : '/ws'),
    serviceName: node.transport === 'grpc' ? (node.serviceName || 'Tun') : undefined,
    mode: node.transport === 'grpc' ? (node.grpcMode || 'gun')
        : node.transport === 'xhttp' ? (node.xhttpMode || 'auto') : undefined,
    fp: node.fp || 'chrome',
    alpn: node.alpn || 'h2,http/1.1',
    ech: node.ech ? node.ech : undefined,
    fragment: node.fragment || undefined,
  };
  const name = encodeURIComponent(node.name);
  return `vless://${node.uuid}@${node.server}:${node.port}?${q(params)}#${name}`;
}

export function buildTrojanUri(node) {
  const params = {
    type: node.transport || 'ws',
    security: 'tls',
    sni: node.sni,
    host: node.host_header || node.host,
    path: node.path || (node.transport === 'grpc' ? undefined : '/trojan'),
    serviceName: node.transport === 'grpc' ? (node.serviceName || 'Tun') : undefined,
    mode: node.transport === 'grpc' ? (node.grpcMode || 'gun')
        : node.transport === 'xhttp' ? (node.xhttpMode || 'auto') : undefined,
    fp: node.fp || 'chrome',
    alpn: node.alpn || 'h2,http/1.1',
    ech: node.ech ? node.ech : undefined,
    fragment: node.fragment || undefined,
  };
  const name = encodeURIComponent(node.name);
  return `trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${q(params)}#${name}`;
}

export function buildSsUri(node) {
  // SIP002: ss://base64(method:password)@host:port with SIP003 v2ray-plugin over websocket+tls
  const userinfo = b64(`${SS_CIPHER}:${node.ssPassword}`);
  const plugin = `v2ray-plugin;mode=websocket;tls;host=${node.host_header || node.host};path=${node.path || '/ss'}`;
  const name = encodeURIComponent(node.name);
  return `ss://${userinfo}@${node.server}:${node.port}/?plugin=${encodeURIComponent(plugin)}#${name}`;
}

const b64 = (s) => {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
};

export function buildNodeUri(node) {
  if (node.protocol === 'vless') return buildVlessUri(node);
  if (node.protocol === 'trojan') return buildTrojanUri(node);
  if (node.protocol === 'ss') return buildSsUri(node);
  throw new Error('unknown protocol ' + node.protocol);
}

// ── node factory: build the full node list for a user from settings ──
// settings: { node_template, security_level, ech_enabled, ech_resolver, fragment_enabled,
//             fragment_len, fragment_interval, fingerprint, decoy_* , isp_ips, locations,
//             chains, warp }
export function buildUserNodes(user, settings, opts = {}) {
  const host = opts.hostname || settings.hostname || 'your-worker.workers.dev';
  const port = 443;
  const date = new Date().toISOString().slice(0, 10);
  const level = settings.security_level || 'balanced';
  // security presets (SENSIBLE defaults by level; all overridable in settings)
  const fragEnabled = level === 'relaxed' ? false : settings.fragment_enabled !== false;
  const echOn = level === 'relaxed' ? false : settings.ech_enabled !== false;
  const frag = fragEnabled ? `${settings.fragment_len || '100-200'},${settings.fragment_interval || '10-20'}` : null;
  const fp = settings.fingerprint || 'chrome';
  const sni = host;
  const tr = settings.transports || { ws: true, grpc: false, xhttp: false };
  const mk = (proto, transport = 'ws') => ({
    protocol: proto,
    transport,
    server: host, port,
    host_header: host, sni,
    serviceName: transport === 'grpc' ? 'Tun' : undefined,
    xhttpMode: transport === 'xhttp' ? 'auto' : undefined,
    path: transport === 'ws'
      ? (proto === 'vless' ? `/ws/vless/${user.token}` : proto === 'trojan' ? `/ws/trojan/${user.token}` : `/ws/ss/${user.token}`)
      : transport === 'xhttp' ? `/xhttp/${proto}/${user.token}`
      : undefined, // grpc: service name carries the path
    uuid: user.uuid, password: user.password, ssPassword: user.password,
    fp, ech: echOn ? sni : null, fragment: frag, alpn: 'h2,http/1.1',
    country: 'XX', isp: 'NET',
  });

  const nodes = [];
  const push = (n, ctx) => {
    n.country = ctx.country;
    n.isp = ctx.isp;
    n.name = formatNodeName(settings.node_template, { name: user.name, date, ...ctx });
    nodes.push(n);
  };
  // main nodes: every enabled transport × enabled protocol on the worker host
  const transportTag = { ws: '', grpc: '-gRPC', xhttp: '-XHTTP' };
  for (const [t, on] of Object.entries(tr)) {
    if (!on) continue;
    if (t === 'ws') {
      for (const proto of ['vless', 'trojan', 'ss']) {
        push(mk(proto, 'ws'), { country: 'XX', isp: 'NET', name: proto.toUpperCase() });
      }
    } else {
      // grpc/xhttp carry only VLESS+Trojan (SS over these transports has no client support)
      for (const proto of ['vless', 'trojan']) {
        push(mk(proto, t), { country: 'XX', isp: 'NET', name: proto.toUpperCase() + transportTag[t] });
      }
    }
  }
  // per-ISP clean-IP variants (VLESS+Trojan only; SS variant adds no value on a fixed IP)
  const ispIps = settings.isp_ips || {};
  for (const [isp, ips] of Object.entries(ispIps)) {
    if (!Array.isArray(ips) || !ips.length) continue;
    const ip = ips[0];
    for (const proto of ['vless', 'trojan']) {
      const n = mk(proto);
      n.server = ip;
      push(n, { country: 'XX', isp, name: proto.toUpperCase() + '-IP' });
    }
  }
  // multi-location variants from the locations table
  const locs = settings.locations || {};
  for (const [cc, ip] of Object.entries(locs)) {
    if (!ip) continue;
    const n = mk('vless');
    n.server = ip;
    push(n, { country: cc, isp: 'VIP', name: 'VLESS' });
  }
  // proxy chains (each chain is an extra node that dials through the upstream)
  for (const c of settings.chains || []) {
    const n = mk('vless');
    n.chain = c;
    push(n, { country: c.country || 'CH', isp: 'CHAIN', name: 'VLESS→' + (c.name || c.type) });
  }
  return nodes;
}

// WARP / AmneziaWG WireGuard client config (client-side tunnel; used for calls/UDP)
export function buildWarpConfig(warp, label = 'SENTRA-WARP') {
  if (!warp || !warp.private_key || !warp.peer_public_key) return null;
  const lines = [
    `[Interface]`,
    `PrivateKey = ${warp.private_key}`,
    `Address = ${warp.address_v4 || '172.16.0.2/32'}`,
    (warp.address_v6 ? `Address = ${warp.address_v6}` : null),
    `DNS = ${warp.dns || '1.1.1.1'}`,
    (warp.mtu ? `MTU = ${warp.mtu}` : 'MTU = 1280'),
    ``,
    `[Peer]`,
    `PublicKey = ${warp.peer_public_key}`,
    `Endpoint = ${warp.endpoint || '162.159.192.1:2408'}`,
    (warp.reserved ? `# reserved = ${JSON.stringify(warp.reserved)}` : null),
    `AllowedIPs = ${warp.allowed_ips || '0.0.0.0/0, ::/0'}`,
    `PersistentKeepalive = 25`,
    ``,
    // AmneziaWG obfuscation parameters (only meaningful in AmneziaWG-compatible clients)
    (warp.awg ? [`Jc = ${warp.awg.Jc || 4}`, `Jmin = ${warp.awg.Jmin || 40}`, `Jmax = ${warp.awg.Jmax || 70}`,
      `S1 = ${warp.awg.S1 || 15}`, `S2 = ${warp.awg.S2 || 20}`,
      `H1 = ${warp.awg.H1 || 1}`, `H2 = ${warp.awg.H2 || 2}`, `H3 = ${warp.awg.H3 || 3}`, `H4 = ${warp.awg.H4 || 4}`].join('\n') : null),
  ].filter(x => x !== null);
  return lines.join('\n');
}
