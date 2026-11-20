'use strict';
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { buildTests, probe, isCanaryHost, findClientRedirect } = require('../lib/scanner');

const base = {
  domain: 'rh-canary.example', mode: 'both', commonParams: false, timeout: 3000,
  maxRedirects: 5, clientSide: true, headers: {}, userAgent: 'test'
};

// Vulnerable: /login?next=X redirects anywhere. Safe: /safe only allows relative paths.
// Meta: /meta reflects next into <meta refresh>. Path: //host paths redirect.
const server = http.createServer((req, res) => {
  try { handle(req, res); } catch { res.writeHead(400); res.end(); }
});
function handle(req, res) {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/login') {
    res.writeHead(302, { Location: u.searchParams.get('next') || '/' }); return res.end();
  }
  if (u.pathname === '/safe') {
    const n = u.searchParams.get('next') || '/';
    res.writeHead(302, { Location: /^\/(?![\/\\])/.test(n) ? n : '/' }); return res.end();
  }
  if (u.pathname === '/meta') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<meta http-equiv="refresh" content="0; url=${u.searchParams.get('next')}">`);
  }
  if (u.pathname === '/hop') { res.writeHead(302, { Location: '/login?next=' + encodeURIComponent(u.searchParams.get('next')) }); return res.end(); }
  res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('ok');
}
let origin;
test.before(() => new Promise((r) => server.listen(0, '127.0.0.1', () => { origin = `http://127.0.0.1:${server.address().port}`; r(); })));
test.after(() => server.close());

const scan = async (url, o = {}) => {
  const opts = { ...base, ...o };
  for (const t of buildTests(url, opts)) { const r = await probe(t, opts); if (r && !r.error) return { t, r }; }
  return null;
};

test('isCanaryHost', () => {
  assert.ok(isCanaryHost('rh-canary.example', 'rh-canary.example'));
  assert.ok(isCanaryHost('a.rh-canary.example', 'rh-canary.example'));
  assert.ok(!isCanaryHost('notrh-canary.example', 'rh-canary.example'));
});

test('detects vulnerable param redirect', async () => {
  const f = await scan(`${origin}/login?next=/home`);
  assert.ok(f); assert.strictEqual(f.r.type, 'server-side'); assert.strictEqual(f.t.param, 'next');
});

test('does not flag safe endpoint', async () => {
  assert.strictEqual(await scan(`${origin}/safe?next=/home`, { mode: 'param' }), null);
});

test('detects meta-refresh client-side redirect', async () => {
  const f = await scan(`${origin}/meta?next=/x`, { mode: 'param' });
  assert.ok(f); assert.strictEqual(f.r.type, 'client-side');
});

test('follows same-site hops before hitting canary', async () => {
  const f = await scan(`${origin}/hop?next=/x`, { mode: 'param' });
  assert.ok(f); assert.ok(f.r.chain.length >= 2);
});

test('common params discovers redirect param not in URL', async () => {
  const f = await scan(`${origin}/login`, { mode: 'param', commonParams: true });
  assert.ok(f); assert.strictEqual(f.t.param, 'next');
});

test('clientSide off ignores meta refresh', async () => {
  assert.strictEqual(await scan(`${origin}/meta?next=/x`, { mode: 'param', clientSide: false }), null);
});

test('findClientRedirect JS', () => {
  assert.ok(findClientRedirect('<script>window.location = "//rh-canary.example/x"</script>', 'http://a.com', 'rh-canary.example'));
});
