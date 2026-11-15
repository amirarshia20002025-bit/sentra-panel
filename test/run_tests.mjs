// SENTRA — unit tests for the pure logic layers (run: node test/run_tests.mjs)
// Vectors come from the public specs: RFC 1321 (MD5), FIPS 180-4 (SHA-224),
// RFC 6238 (TOTP), shadowsocks EVP_BytesToKey convention.

import { md5, evpBytesToKey, bytesToHex, hexToBytes, parseSocksAddress, buildSocksAddress, b64encode, b64decode, IncrementingNonce, grpcEncode, GrpcUnframer, parseXhttpPath, concatBytes, makeSsPump, ssSubkey, importAesKey } from '../src/protocols/util.js';
import { formatNodeName, buildUserNodes, buildVlessUri, buildTrojanUri, buildSsUri, buildWarpConfig } from '../src/protocols/links.js';
import { emitBase64, emitClash, emitSingbox } from '../src/protocols/formats.js';
import { sha224Hex } from '../src/db.js';
import { hashPassword, verifyPassword, totpCode, base32Decode, base32Encode } from '../src/security.js';

let pass = 0, fail = 0;
function t(name, cond) {
  if (cond) { pass++; console.log('  ✅', name); }
  else { fail++; console.log('  ❌', name); }
}

// ── MD5 ──
console.log('MD5 (RFC 1321 vectors)');
t('md5("")', md5('') === 'd41d8cd98f00b204e9800998ecf8427e');
t('md5("abc")', md5('abc') === '900150983cd24fb0d6963f7d28e17f72');
t('md5 pangram', md5('The quick brown fox jumps over the lazy dog') === '9e107d9d372bb6826bd81d3542a419d6');

// ── SHA-224 (FIPS 180-4) — vectors cross-checked with Node crypto.createHash ──
console.log('SHA-224');
t('sha224("abc")', await sha224Hex('abc') === '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
t('sha224("")', await sha224Hex('') === 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
t('sha224("password")', await sha224Hex('password') === 'd63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01');

// ── EVP_BytesToKey (shadowsocks key derivation) ──
console.log('EVP_BytesToKey');
{
  const k = evpBytesToKey('secret', 32);
  t('key length 32', k.length === 32);
  // deterministic: same passphrase → same key
  const k2 = evpBytesToKey('secret', 32);
  t('deterministic', bytesToHex(k) === bytesToHex(k2));
  // first 16 bytes of the 32-byte key == MD5 chain (D1 = md5(pass))
  const d1 = hexToBytes(md5('secret'));
  t('D1 chain correct', bytesToHex(k.slice(0, 16)) === bytesToHex(d1));
}

// ── TOTP (RFC 6238) ──
console.log('TOTP (RFC 6238)');
{
  // The standard 8-digit test secret "12345678901234567890" in base32:
  const secret = base32Encode(new TextEncoder().encode('12345678901234567890'));
  const code = await totpCode(secret, 1); // T=59s → counter 1 → 6-digit code 287082
  t('RFC vector T=1 → 287082', code === '287082');
  const round = base32Decode(base32Encode(new Uint8Array([1, 2, 3, 250])));
  t('base32 roundtrip', [...round].join(',') === '1,2,3,250');
}

// ── password hashing ──
console.log('PBKDF2');
{
  const rec = await hashPassword('s3cret-pass');
  t('verify ok', await verifyPassword('s3cret-pass', rec));
  t('verify wrong', !(await verifyPassword('wrong', rec)));
}

// ── socks address helpers ──
console.log('SOCKS address');
{
  const b = buildSocksAddress('example.com', 443);
  const p = parseSocksAddress(b, 0);
  t('domain roundtrip', p.addr === 'example.com' && p.port === 443);
  const ipb = buildSocksAddress('104.16.1.1', 8080);
  const ip = parseSocksAddress(ipb, 0);
  t('ipv4 roundtrip', ip.addr === '104.16.1.1' && ip.port === 8080 && ip.atyp === 1);
  const n = new IncrementingNonce();
  t('nonce starts at 0 (SS spec)', n.next()[11] === 0 && n.next()[11] === 1 && n.next()[11] === 2);
}

// ── base64 helpers ──
console.log('base64');
t('unicode roundtrip', b64decode(b64encode('سلام دنیا 123')) === 'سلام دنیا 123');

// ── node builders ──
console.log('node builders');
{
  const user = { name: 'ali', token: 'tok123', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000', password: 'pass123456' };
  const settings = {
    node_template: 'SENTRA-{COUNTRY}-{ISP}-{NAME}',
    security_level: 'hard', ech_enabled: true, fragment_enabled: true,
    fragment_len: '100-200', fragment_interval: '10-20', fingerprint: 'chrome',
    isp_ips: { MCI: ['1.2.3.4'], Irancell: [] },
    locations: { DE: '5.6.7.8' },
    chains: [{ name: 'mid', type: 'socks5', host: '9.9.9.9', port: 1080, country: 'CH' }],
  };
  const nodes = buildUserNodes(user, settings, { hostname: 'demo.workers.dev' });
  t('3 base protocols', nodes.filter(n => n.isp === 'NET').length === 3);
  t('ISP variant built', nodes.some(n => n.isp === 'MCI' && n.server === '1.2.3.4'));
  t('location node', nodes.some(n => n.country === 'DE' && n.server === '5.6.7.8'));
  t('chain node', nodes.some(n => n.isp === 'CHAIN' && n.chain));
  const v = buildVlessUri(nodes[0]);
  t('vless uri shape', v.startsWith(`vless://${user.uuid}@demo.workers.dev:443?`) && v.includes('security=tls') && v.includes('ech='));
  const tr = buildTrojanUri(nodes.find(n => n.protocol === 'trojan'));
  t('trojan uri shape', tr.startsWith(`trojan://${encodeURIComponent(user.password)}@`));
  const ss = buildSsUri(nodes.find(n => n.protocol === 'ss'));
  t('ss uri has v2ray-plugin', ss.startsWith('ss://') && ss.includes('v2ray-plugin'));
  const name = formatNodeName('SENTRA-{FLAG}-{ISP}-{NAME}', { country: 'DE', isp: 'MCI', name: 'ali' });
  t('template', name === 'SENTRA-🇩🇪-MCI-ali');
  const wg = buildWarpConfig({ private_key: 'AAA', peer_public_key: 'BBB', awg: { Jc: 4 } });
  t('wireguard config', wg.includes('[Interface]') && wg.includes('Jc = 4'));
}

// ── format emitters ──
console.log('format emitters');
{
  const user = { name: 'ali', token: 'tok123', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000', password: 'pass123456' };
  const settings = {
    node_template: 'SENTRA-{ISP}-{NAME}', security_level: 'balanced',
    ech_enabled: true, fragment_enabled: true, fingerprint: 'chrome',
    isp_ips: { MCI: ['1.2.3.4'] }, locations: {}, chains: [],
    warp: { private_key: 'PK', peer_public_key: 'PPK', reserved: [1, 2, 3], endpoint: '162.159.192.1:2408' },
    adblock: true, pornblock: true, domestic_bypass: true, fakeip: false,
    block_quic: true, block_malware: true, ai_sanction_bypass: true,
  };
  const nodes = buildUserNodes(user, settings, { hostname: 'demo.workers.dev' });
  const b64 = emitBase64(nodes);
  const decoded = b64decode(b64);
  t('base64 roundtrip count', decoded.split('\n').length === nodes.length);
  const yaml = emitClash(nodes, settings, user);
  t('clash has proxies + rules', yaml.includes('proxies:') && yaml.includes('GEOIP,IR,DIRECT') && yaml.includes('type: wireguard'));
  t('clash QUIC block', yaml.includes('NETWORK,udp'));
  const sb = emitSingbox(nodes, settings, user);
  const parsed = JSON.parse(sb);
  t('singbox valid JSON', Array.isArray(parsed.outbounds) && parsed.outbounds.length > 4);
  t('singbox wireguard outbound', parsed.outbounds.some(o => o.type === 'wireguard'));
  t('singbox ech flag', sb.includes('"ech"'));
  t('singbox route rules', sb.includes('"domain_suffix"'));
}

// ── gRPC framing + XHTTP path (streaming transports) ──
console.log('streaming transports (gRPC / XHTTP)');
{
  const a = grpcEncode(new Uint8Array([1, 2, 3]));
  t('grpc frame 1B flag + 4B len', a.length === 8 && a[0] === 0 && a[1] === 0 && a[2] === 0 && a[5] === 1);
  const uf = new GrpcUnframer();
  const p1 = uf.push(a.slice(0, 3)); // partial header
  const p2 = uf.push(a.slice(3));    // remainder completes the frame
  t('grpc partial→complete', p1.length === 0 && p2.length === 1 && p2[0][2] === 3);
  const big = new GrpcUnframer().push(grpcEncode(new Uint8Array(60000)));
  t('grpc large frame', big.length === 1 && big[0].length === 60000);
  t('xhttp path parse', parseXhttpPath('/xhttp/vless/tok123/abc-def-123')?.sid === 'abc-def-123'
    && parseXhttpPath('/xhttp/vless/tok123/abc-def-123')?.proto === 'vless');
  t('xhttp path reject', parseXhttpPath('/xhttp/vless/tok123') === null && parseXhttpPath('/grpc/vless/tok') === null);
}

// ── SS-AEAD decrypt pump: nonce continuity across arbitrarily split feeds ──
console.log('SS decrypt pump (nonce continuity)');
{
  const pass = 'pump-pass';
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const sub = await ssSubkey(evpBytesToKey(pass, 32), salt);
  const key = await importAesKey(sub);
  // SS spec: the nonce counter is continuous across the whole session, not per chunk —
  // chunk 0 uses counter 0,1 and chunk 1 uses counter 2,3 (this is exactly what the pump must follow)
  const encNonce = new IncrementingNonce();
  const encStream = async (plain) => { // one SS chunk as a spec-conformant client emits it
    const lb = new Uint8Array([plain.length >> 8, plain.length & 255]);
    const le = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: encNonce.next() }, key, lb));
    const be = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: encNonce.next() }, key, plain));
    return concatBytes(le, be);
  };
  const s1 = await encStream(new TextEncoder().encode('hello world'));
  const s2 = await encStream(new TextEncoder().encode('A'.repeat(300)));
  const stream = concatBytes(s1, s2);
  const expect = 'hello world' + 'A'.repeat(300);

  const r1 = await makeSsPump({ key: await importAesKey(sub), nonce: new IncrementingNonce() }).feed(stream);
  t('pump single feed', new TextDecoder().decode(r1.plain) === expect);

  // feed in 7-byte slices: the pump must cache the length block so the nonce stays aligned
  const pump2 = makeSsPump({ key: await importAesKey(sub), nonce: new IncrementingNonce() });
  let acc = new Uint8Array(0);
  let fatal = false;
  for (let i = 0; i < stream.length; i += 7) {
    const r = await pump2.feed(stream.slice(i, i + 7));
    if (r.fatal) { fatal = true; break; }
    if (r.plain?.length) acc = concatBytes(acc, r.plain);
  }
  t('pump partial 7-byte feeds', !fatal && new TextDecoder().decode(acc) === expect);
}

// ── transport-aware node builders ──
console.log('transport builders');
{
  const user = { name: 'ali', token: 'tok123', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000', password: 'pass123456' };
  const s2 = {
    node_template: 'SENTRA-{ISP}-{NAME}', security_level: 'relaxed',
    transports: { ws: true, grpc: true, xhttp: true },
    isp_ips: {}, locations: {}, chains: [],
  };
  const nodes2 = buildUserNodes(user, s2, { hostname: 'd.workers.dev' });
  t('3 ws + 2 grpc + 2 xhttp', nodes2.filter(n => n.isp === 'NET').length === 7);
  const gn = nodes2.find(n => n.transport === 'grpc' && n.protocol === 'vless');
  const gu = buildVlessUri(gn);
  t('grpc uri params', gu.includes('type=grpc') && gu.includes('serviceName=Tun') && gu.includes('mode=gun'));
  const xn = nodes2.find(n => n.transport === 'xhttp' && n.protocol === 'vless');
  const xu = buildVlessUri(xn);
  t('xhttp uri params', xu.includes('type=xhttp') && xu.includes('mode=auto') && xu.includes(encodeURIComponent('/xhttp/vless/tok123')));
  const yaml2 = emitClash(nodes2, s2, user);
  t('clash grpc + xhttp networks', yaml2.includes('network: grpc') && yaml2.includes('grpc-service-name: Tun') && yaml2.includes('network: xhttp'));
  const sb2 = JSON.parse(emitSingbox(nodes2, s2, user));
  t('singbox grpc transport', sb2.outbounds.some(o => o.transport?.type === 'grpc'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
