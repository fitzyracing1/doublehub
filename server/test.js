'use strict';
const assert = require('assert'), L = require('./lib'), E = require('../embed.js'), { createServer } = require('./server');
const SECRET = 'x'.repeat(40), app = { id: 'acme', origins: ['https://acme.dev'] };
// origin checks
assert(L.originAllowed(app, 'https://acme.dev'));
['https://evil.dev', 'https://acme.dev.evil.dev', 'http://acme.dev', 'https://acme.dev/x', 'javascript:1', '', null].forEach(o => assert(!L.originAllowed(app, o), o));
const so = 'https://auth.dh', pop = {};
assert(E.acceptMessage({ origin: so, source: pop, data: { type: 'doublehub:grant', grant: 'a.b' } }, so, pop));
assert(!E.acceptMessage({ origin: 'https://evil.dev', source: pop, data: { type: 'doublehub:grant', grant: 'a.b' } }, so, pop));
assert(!E.acceptMessage({ origin: so, source: {}, data: { type: 'doublehub:grant', grant: 'a.b' } }, so, pop));
assert(!E.acceptMessage({ origin: so, source: pop, data: { type: 'x' } }, so, pop));
assert.throws(() => E.authorizeUrl('http://auth.dh', 'acme', 'https://acme.dev'));
// state + PKCE
const { verifier, challenge } = L.pkce();
assert.strictEqual(challenge, L.challengeFor(verifier)); assert(/^[\w-]{43}$/.test(challenge));
const st = L.createStore(); st.putState('s1', { app: 'acme' });
assert(st.takeState('s1')); assert.strictEqual(st.takeState('s1'), null, 'state single-use');
st.putState('s2', {}, 1000, 0); assert.strictEqual(st.takeState('s2', 5000), null, 'state expiry');
// grant signing / expiry / binding
const g = L.signGrant({ app: 'acme', origin: 'https://acme.dev', sub: '1' }, SECRET, 300, 0);
assert.strictEqual(L.verifyGrant(g, SECRET, { now: 1000, origin: 'https://acme.dev', app: 'acme' }).sub, '1');
assert.throws(() => L.verifyGrant(g, SECRET, { now: 301000 }), /expired/);
assert.throws(() => L.verifyGrant(g, SECRET, { now: 0, origin: 'https://evil.dev' }), /origin/);
assert.throws(() => L.verifyGrant(g, 'y'.repeat(40), { now: 0 }), /signature/);
const [b, s] = g.split('.'), forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url')), origin: 'https://evil.dev' })).toString('base64url') + '.' + s;
assert.throws(() => L.verifyGrant(forged, SECRET, { now: 0 }), /signature/);
assert.throws(() => L.signGrant({}, 'short'));
// revoke
st.grantConsent('acme', 'https://acme.dev', '1', {}); const c = L.verifyGrant(g, SECRET, { now: 0 });
assert(!st.isRevoked(c)); st.revoke('acme', 'https://acme.dev', '1', c.jti); assert(st.isRevoked(c));
// end-to-end over HTTP with a fake GitHub
(async () => {
  const cfg = { secret: SECRET, base: 'http://127.0.0.1:0', apps: { acme: { ...app, client_id: 'cid', client_secret: 'cs', app_key: 'k'.repeat(32) } } };
  let sentVerifier;
  const fake = async (url, o) => url.includes('access_token') ? (sentVerifier = JSON.parse(o.body).code_verifier, { json: async () => ({ access_token: 'gho_t' }) }) : { json: async () => ({ id: 7, login: 'octo' }) };
  const store = L.createStore(), srv = createServer(cfg, store, fake).listen(0); await new Promise(r => srv.on('listening', r));
  const base = 'http://127.0.0.1:' + srv.address().port, f = (p, o) => fetch(base + p, { redirect: 'manual', ...o });
  assert.strictEqual((await f('/authorize?app=acme&origin=https://evil.dev')).status, 403);
  const a = await f('/authorize?app=acme&origin=https://acme.dev'); assert.strictEqual(a.status, 302);
  const gh = new URL(a.headers.get('location')); assert.strictEqual(gh.host, 'github.com'); assert.strictEqual(gh.searchParams.get('code_challenge_method'), 'S256');
  assert.strictEqual((await f('/callback?code=c&state=wrong')).status, 400);
  const cb = await f('/callback?code=c&state=' + gh.searchParams.get('state')); assert.strictEqual(cb.status, 302);
  assert.strictEqual(L.challengeFor(sentVerifier), gh.searchParams.get('code_challenge'));
  assert.strictEqual((await f('/callback?code=c&state=' + gh.searchParams.get('state'))).status, 400, 'replay');
  const page = await (await f(cb.headers.get('location'))).text(); assert(page.includes('https://acme.dev'));
  const id = page.match(/name=id value="([^"]+)"/)[1], csrf = page.match(/name=csrf value="([^"]+)"/)[1];
  assert.strictEqual((await f('/consent', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `id=${id}&csrf=bad&decision=allow` })).status, 400);
  const done = await (await f('/consent', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `id=${id}&csrf=${csrf}&decision=allow` })).text();
  assert(done.includes(', "https://acme.dev")'), 'postMessage targets bound origin');
  const grant = done.match(/"grant":"([^"]+)"/)[1];
  const tok = o => f('/token', { method: 'POST', headers: { authorization: 'Bearer ' + 'k'.repeat(32) }, body: JSON.stringify({ app: 'acme', origin: o, grant }) });
  assert.strictEqual((await tok('https://evil.dev')).status, 400);
  assert.strictEqual((await (await tok('https://acme.dev')).json()).login, 'octo');
  assert.strictEqual((await f('/token', { method: 'POST', headers: { authorization: 'Bearer nope' }, body: JSON.stringify({ app: 'acme', grant }) })).status, 401);
  assert.strictEqual((await f('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant }) })).status, 200);
  assert.strictEqual((await tok('https://acme.dev')).status, 400, 'revoked');
  srv.close(); console.log('server tests lit');
})().catch(e => { console.error(e); process.exit(1); });
