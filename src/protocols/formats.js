// SENTRA — subscription format emitters: Base64 (v2ray-family), Clash/Mihomo YAML,
// sing-box JSON. Routing presets (ad-block, domestic bypass, QUIC block, malware block,
// AI-sanction bypass, FakeIP) are emitted as static rules maintained in this file.
// Pure JS — unit-testable in Node.

import { buildNodeUri, buildWarpConfig, SS_CIPHER } from './links.js';

// ── 1) Base64 subscription (list of share URIs) ──
export function emitBase64(nodes) {
  const raw = nodes.map(buildNodeUri).join('\n');
  const bytes = new TextEncoder().encode(raw);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ── tiny YAML emitter (deterministic; scalars quoted only when needed) ──
function yq(v) {
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  if (v === null || v === undefined) return '""';
  const s = String(v);
  if (s === '' || /[\n"'#{}[\]&*!|>%@`,:]|\s$|^[\s-]|^$/.test(s) || /^-/.test(s) || s.includes(': ') || s.endsWith(':')) {
    return JSON.stringify(s);
  }
  return s;
}
function yline(indent, k, v) { return ' '.repeat(indent) + `${k}: ${yq(v)}`; }
function ylist(indent, items) { return items.map(x => ' '.repeat(indent) + '- ' + (typeof x === 'object' ? JSON.stringify(x) : yq(x))).join('\n'); }
function yobj(indent, obj) {
  return Object.entries(obj).map(([k, v]) => {
    if (v === null || v === undefined) return ' '.repeat(indent) + `${k}: {}`;
    if (Array.isArray(v)) return v.length
      ? ' '.repeat(indent) + `${k}:\n` + (v.every(x => typeof x === 'object' && x !== null)
        ? v.map(o => ' '.repeat(indent + 2) + '- ' + Object.entries(o).map(([k2, v2]) => `${k2}: ${yq(v2)}`).join(' ')).join('\n')
        : ylist(indent + 2, v))
      : ' '.repeat(indent) + `${k}: []`;
    if (typeof v === 'object') {
      const inner = yobj(indent + 2, v);
      return Object.keys(v).length ? ' '.repeat(indent) + `${k}:\n${inner}` : ' '.repeat(indent) + `${k}: {}`;
    }
    return yline(indent, k, v);
  }).join('\n');
}

// ── static rule lists (maintained by hand from public blocklists' categories) ──
const AD_DOMAINS = [
  'doubleclick.net', 'googlesyndication.com', 'googletagservices.com', 'google-analytics.com',
  'analytics.tiktok.com', 'ads.unitymedia.unity', 'app-measurement.com', 'crashlytics.com',
  'scorecardresearch.com', 'quantserve.com', 'moatads.com', 'zedo.com', 'pubmatic.com',
  'criteo.com', 'outbrain.com', 'taboola.com', 'adnxs.com', 'adsrvr.org', 'teads.tv',
];
const PORN_DOMAINS = [
  'pornhub.com', 'xvideos.com', 'xnxx.com', 'xhamster.com', 'redtube.com', 'youporn.com',
  'onlyfans.com', 'stripchat.com', 'chaturbate.com', 'brazzers.com',
];
const MALWARE_DOMAINS = [
  'malware-site.example', 'known-bad.example', // placeholder pattern — extend from feeds
  'zeustracker.abuse.ch', 'feodotracker.abuse.ch',
];
const AI_DOMAINS = [
  'openai.com', 'chatgpt.com', 'ai.google.dev', 'gemini.google.com', 'generativelanguage.googleapis.com',
  'claude.ai', 'anthropic.com', 'perplexity.ai', 'groq.com', 'x.ai', 'copilot.microsoft.com',
  'huggingface.co', 'poew.com',
];
// major Iranian domains for domestic bypass (kept short; GEOIP,IR does the heavy lifting)
const IR_DOMAINS = [
  'ir', 'aparat.com', 'divar.ir', 'snapp.ir', 'digikala.com', 'tapsi.ir', 'alibaba.ir',
  'sheypoor.com', 'filimo.com', 'namava.ir', 'bimeh.com', 'idpay.ir', 'zarinpal.com',
  'nextpay.org', 'shad.ir', 'hamrah.ir', 'sopho.ir', 'cafebroker.com',
];
const DOMESTIC_BANKS = ['bmi.ir', 'bki.ir', 'bsi.ir', 'bankmellat.ir', 'sep.ir', 'sb24.com', 'edbi.ir', 'tejaratbank.ir', 'bpi.ir'];

function clashRules(s) {
  const rules = [];
  if (s.block_quic) rules.push('AND,((NETWORK,udp),(DST-PORT,443)),REJECT');
  for (const d of AD_DOMAINS) if (s.adblock) rules.push(`DOMAIN-SUFFIX,${d},REJECT`);
  for (const d of PORN_DOMAINS) if (s.pornblock) rules.push(`DOMAIN-SUFFIX,${d},REJECT`);
  for (const d of MALWARE_DOMAINS) if (s.block_malware) rules.push(`DOMAIN-SUFFIX,${d},REJECT`);
  for (const d of AI_DOMAINS) if (s.ai_sanction_bypass) rules.push(`DOMAIN-SUFFIX,${d},SELECT`);
  for (const d of IR_DOMAINS) if (s.domestic_bypass) rules.push(`DOMAIN-SUFFIX,${d},DIRECT`);
  for (const d of DOMESTIC_BANKS) if (s.domestic_bypass) rules.push(`DOMAIN-SUFFIX,${d},DIRECT`);
  if (s.domestic_bypass) rules.push('GEOIP,IR,DIRECT');
  rules.push('MATCH,SELECT');
  return rules;
}

// transport options per node for Clash/Mihomo
function clashNetOpts(n) {
  if (n.transport === 'grpc') {
    return { network: 'grpc', 'grpc-opts': { 'grpc-service-name': n.serviceName || 'Tun' } };
  }
  if (n.transport === 'xhttp') {
    return { network: 'xhttp', 'xhttp-opts': { mode: n.xhttpMode || 'auto', path: n.path, headers: { Host: n.host_header || n.host } } };
  }
  return { network: 'ws', 'ws-opts': { path: n.path, headers: { Host: n.host_header || n.host } } };
}

function clashProxies(nodes, chains, warp) {
  const out = [];
  for (const n of nodes) {
    const common = { name: n.name, server: n.server, port: n.port, tls: true, 'client-fingerprint': n.fp || 'chrome' };
    if (n.protocol === 'vless') {
      out.push(yobj(2, { ...common, type: 'vless', uuid: n.uuid, servername: n.sni,
        ...clashNetOpts(n), ...(n.ech ? { 'ech-opts': { enable: true } } : {}) }));
    } else if (n.protocol === 'trojan') {
      out.push(yobj(2, { ...common, type: 'trojan', password: n.password, sni: n.sni, ...clashNetOpts(n) }));
    } else if (n.protocol === 'ss') {
      out.push(yobj(2, { name: n.name, type: 'ss', server: n.server, port: n.port, cipher: SS_CIPHER,
        password: n.ssPassword, plugin: 'v2ray-plugin',
        'plugin-opts': { mode: 'websocket', tls: true, host: n.host_header || n.host, path: n.path } }));
    }
    if (n.chain) {
      const c = n.chain;
      out.push(yobj(2, { name: n.name + ' (chain)', type: c.type === 'turn' ? 'http' : c.type,
        server: c.host, port: c.port, ...(c.username ? { username: c.username } : {}), ...(c.password ? { password: c.password } : {}),
        ...(c.tls ? { tls: true } : {}), 'dialer-proxy': n.name }));
    }
  }
  if (warp && warp.private_key) {
    out.push(yobj(2, { name: 'SENTRA-WARP', type: 'wireguard', 'private-key': warp.private_key,
      'public-key': warp.peer_public_key, ip: warp.address_v4 || '172.16.0.2', ...(warp.address_v6 ? { ipv6: warp.address_v6 } : {}),
      ...(warp.reserved ? { 'reserved-nums': warp.reserved } : {}), mtu: warp.mtu || 1280,
      udp: true, 'remote-dns-resolve': true, dns: [warp.dns || '1.1.1.1'],
      peers: [{ server: (warp.endpoint || '162.159.192.1:2408').split(':')[0],
        port: parseInt((warp.endpoint || '162.159.192.1:2408').split(':')[1] || '2408', 10), 'allowed-ips': ['0.0.0.0/0', '::/0'] }] }));
  }
  return out.join('\n');
}

export function emitClash(nodes, settings, user, opts = {}) {
  const groups = ['AUTO', 'SELECT', 'DIRECT'];
  const allNames = nodes.map(n => n.name);
  const hasWarp = !!(settings.warp && settings.warp.private_key);
  const yaml = `# SENTRA subscription for ${user.name} — generated ${new Date().toISOString()}
# Clash/Mihomo profile (port-spread copies are included by the panel when enabled)
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: true
unified-delay: true
tcp-concurrent: true
external-controller: :9090
profile:
  store-selected: true
dns:
  enable: true
  listen: :1053
  ${settings.fakeip ? 'enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16' : 'enhanced-mode: redir-host'}
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  nameserver:
    - ${settings.ech_resolver === 'udp://1.1.1.1' ? '1.1.1.1' : 'https://1.1.1.1/dns-query'}
    - https://dns.google/dns-query
proxies:
${clashProxies(nodes, settings.chains || [], settings.warp)}
proxy-groups:
${yobj(2, { name: 'SELECT', type: 'select', proxies: ['AUTO', ...(hasWarp ? ['SENTRA-WARP'] : []), ...allNames, 'DIRECT'] })}
${yobj(2, { name: 'AUTO', type: 'url-test', proxies: allNames, url: 'http://www.gstatic.com/generate_204', interval: 300, tolerance: 50 })}
rules:
${clashRules(settings).map(r => '  - ' + JSON.stringify(r).replace(/"/g, '')).join('\n')}
`;
  return yaml;
}

// transport options per node for sing-box (xhttp needs an Xray-family/sing-box ≥1.12 client)
function sbTransport(n, host) {
  if (n.transport === 'grpc') return { type: 'grpc', service_name: n.serviceName || 'Tun' };
  if (n.transport === 'xhttp') return { type: 'xhttp', mode: n.xhttpMode || 'auto', path: n.path, headers: { Host: n.host_header || n.host } };
  return { type: 'ws', path: n.path, headers: { Host: n.host_header || n.host }, early_data_header_name: 'Sec-WebSocket-Protocol' };
}

// ── sing-box JSON ──
export function emitSingbox(nodes, settings, user, opts = {}) {
  const host = nodes[0]?.host || settings.hostname;
  const outbounds = [];
  const names = [];
  for (const n of nodes) {
    const o = { tag: n.name, server: n.server, server_port: n.port };
    if (n.chain) {
      const c = n.chain;
      outbounds.push({
        tag: n.name + ' (chain)', type: c.type === 'turn' ? 'http' : c.type,
        server: c.host, server_port: c.port,
        ...(c.username ? { username: c.username } : {}), ...(c.password ? { password: c.password } : {}),
        ...(c.tls ? { tls: { enabled: true } } : {}),
      });
      o.detour = n.name + ' (chain)';
    }
    const tls = {
      enabled: true, server_name: n.sni || host, insecure: false,
      utls: { enabled: true, fingerprint: n.fp || 'chrome' },
    };
    if (n.ech) tls.ech = { enabled: true };
    if (n.protocol === 'vless') Object.assign(o, { type: 'vless', uuid: n.uuid, flow: '', tls, transport: sbTransport(n, host) });
    if (n.protocol === 'trojan') Object.assign(o, { type: 'trojan', password: n.password, tls, transport: sbTransport(n, host) });
    if (n.protocol === 'ss') Object.assign(o, { type: 'shadowsocks', method: SS_CIPHER, password: n.ssPassword, plugin: 'v2ray-plugin', plugin_opts: `mode=websocket;tls;host=${n.host_header || n.host};path=${n.path}` });
    outbounds.push(o);
    names.push(n.name);
  }
  const warpCfg = settings.warp && settings.warp.private_key ? {
    tag: 'SENTRA-WARP', type: 'wireguard',
    local_address: [settings.warp.address_v4 || '172.16.0.2/32', ...(settings.warp.address_v6 ? [settings.warp.address_v6] : [])],
    private_key: settings.warp.private_key,
    peers: [{ public_key: settings.warp.peer_public_key,
      endpoint: settings.warp.endpoint || '162.159.192.1:2408',
      ...(settings.warp.reserved ? { reserved: settings.warp.reserved } : {}),
      allowed_ips: ['0.0.0.0/0', '::/0'] }],
    mtu: settings.warp.mtu || 1280,
  } : null;
  if (warpCfg) outbounds.push(warpCfg);

  const rules = [];
  if (settings.block_quic) rules.push({ protocol: ['udp'], port: 443, outbound: 'block' });
  if (settings.adblock) rules.push({ outbound: 'block', domain_suffix: AD_DOMAINS });
  if (settings.pornblock) rules.push({ outbound: 'block', domain_suffix: PORN_DOMAINS });
  if (settings.block_malware) rules.push({ outbound: 'block', domain_suffix: MALWARE_DOMAINS });
  if (settings.ai_sanction_bypass) rules.push({ outbound: 'SELECT', domain_suffix: AI_DOMAINS });
  if (settings.domestic_bypass) {
    rules.push({ outbound: 'direct', domain_suffix: [...IR_DOMAINS, ...DOMESTIC_BANKS] });
    rules.push({ outbound: 'direct', ip_is_private: true });
  }
  rules.push({ outbound: 'direct', clash_mode: 'Direct' });
  rules.push({ outbound: 'GLOBAL', clash_mode: 'Global' });

  const config = {
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: [
        { tag: 'cf-doh', address: 'https://1.1.1.1/dns-query', detour: 'SELECT' },
        { tag: 'local', address: 'local' },
        { tag: 'block-dns', address: 'local', address_resolver: 'local' },
      ],
      rules: [
        { outbound: 'direct', server: 'local' },
        ...(settings.fakeip ? [{ query_type: ['A', 'AAAA'], server: 'cf-doh' }] : []),
      ],
      independent_cache: true,
      ...(settings.fakeip ? { fakeip: { enabled: true, inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' } } : {}),
    },
    inbounds: [
      { tag: 'tun-in', type: 'tun', address: settings.fakeip ? ['198.18.0.1/30'] : ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed' },
    ],
    outbounds: [
      { tag: 'SELECT', type: 'selector', outbounds: ['AUTO', ...(warpCfg ? ['SENTRA-WARP'] : []), ...names.slice(0, 24), 'direct'], default: 'AUTO', interrupt_exist_connections: true },
      { tag: 'AUTO', type: 'urltest', outbounds: names.slice(0, 24), url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 50 },
      ...outbounds,
      { tag: 'direct', type: 'direct' },
      { tag: 'block', type: 'block' },
      { tag: 'dns-out', type: 'dns' },
    ],
    route: {
      rules,
      final: 'SELECT',
      auto_detect_interface: true,
      ...(settings.domestic_bypass ? { default_domain_resolver: { server: 'local' } } : {}),
    },
    experimental: { cache_file: { enabled: true, store_fakeip: settings.fakeip } },
  };
  return JSON.stringify(config, null, 2);
}

// ── content-type helpers used by the subscription endpoint ──
export const FORMAT_CONTENT_TYPES = {
  base64: 'text/plain; charset=utf-8',
  clash: 'text/yaml; charset=utf-8',
  singbox: 'application/json; charset=utf-8',
  raw: 'text/plain; charset=utf-8',
};
