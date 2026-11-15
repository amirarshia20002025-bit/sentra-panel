// SENTRA — build dist/worker.js: esbuild bundle → javascript-obfuscator
// Pipeline: bundle src/index.js (ESM, cloudflare:sockets external, .txt=text loader)
//           → obfuscate with an eval-free option set (Workers blocks dynamic codegen,
//             so debugProtection/selfDefending/eval-based features must stay OFF).
// Usage:    npm i && npm run obfuscate   →  dist/worker.js
import { build } from 'esbuild';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
mkdirSync(DIST, { recursive: true });

console.log('① esbuild bundle …');
const bundle = (await build({
  entryPoints: [join(ROOT, 'src', 'index.js')],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'neutral',
  external: ['cloudflare:sockets'],
  loader: { '.txt': 'text' },
  write: false,
  logLevel: 'silent',
})).outputFiles[0].text;
console.log(`   bundle: ${(bundle.length / 1024).toFixed(1)} KB`);

console.log('② obfuscate …');
const obfuscated = JavaScriptObfuscator.obfuscate(bundle, {
  compact: true,
  comments: false,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.4,
  deadCodeInjection: false,
  debugProtection: false,
  selfDefending: false,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,
  stringArray: true,
  stringArrayThreshold: 0.75,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayEncoding: ['base64'],
  stringArrayIndexShift: true,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 0.5,
  stringArrayWrappersCount: 2,
  stringArrayWrappersType: 'function',
  splitStrings: true,
  splitStringsChunkLength: 10,
  numbersToExpressions: true,
  unicodeEscapeSequence: false,
  transformObjectKeys: false,
}).getObfuscatedCode();

const banner =
  '/* SENTRA — obfuscated production build of src/index.js.\n' +
  '   Pipeline: esbuild bundle → javascript-obfuscator (no eval / new Function — Workers blocks dynamic codegen).\n' +
  '   Deploy: set main = "dist/worker.js" in wrangler.toml. Regenerate: npm run obfuscate */\n';
const final = banner + obfuscated;
writeFileSync(join(DIST, 'worker.js'), final);

console.log('③ post-checks …');
const checks = {
  'eval(': (final.match(/\beval\s*\(/g) || []).length,
  'new Function(': (final.match(/new\s+Function\s*\(/g) || []).length,
  'Function("…")': (final.match(/Function\s*\(\s*['"`]/g) || []).length,
  'debugger': (final.match(/\bdebugger\b/g) || []).length,
};
let bad = false;
for (const [k, v] of Object.entries(checks)) { if (v > 0) bad = true; console.log(`   ${k.padEnd(16)} → ${v} ${v ? '⛔' : '✓'}`); }
const hasSockets = /['"]cloudflare:sockets['"]/.test(final);
console.log(`   import cloudflare:sockets → ${hasSockets ? 'preserved ✓' : '⛔ missing!'}`);
if (bad || !hasSockets) { console.error('⛔ verification failed'); process.exit(1); }
console.log(`✅ dist/worker.js: ${(final.length / 1024).toFixed(1)} KB — deploy it by setting main = "dist/worker.js" in wrangler.toml`);
