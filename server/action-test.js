'use strict';
// Layer 3 tests: nothing leaves without a per-action user approval.
const assert = require('assert'), L = require('./lib'), E = require('../embed.js'), { createServer } = require('./server');
const SECRET = 'x'.repeat(40), KEY = 'k'.repeat(32);
(async () => {
  const cfg = { secret: SECRET, base: 'http://127.0.0.1:0', apps: { acme: { id: 'acme', origins: ['https://acme.dev'], send_to: ['https://api.acme.dev'], client_id: 'cid', client_secret: 'cs', app_key: KEY } } };
  const gh = [];
  const fake = async (url, o = {}) => {
    if (url.includes('access_token')) return { json: async () => ({ access_token: 'gho_t' }) };
    if (url === 'https://api.github.com/user' && !o.method) return { json: async () => ({ id: 7, login: 'octo' }) };
    gh.push({ url, ...o }); return { status: 201, text: async () => '{"ok":true}' };
  };
  const store = L.createStore(), srv = createServer(cfg, store, fake).listen(0); await new Promise(r => srv.on('listening', r));
  const base = 'http://127.0.0.1:' + srv.address().port, f = (p, o) => fetch(base + p, { redirect: 'manual', ...o });
  const form = { 'content-type': 'application/x-www-form-urlencoded' };
  // layers 1+2
  const a = await f('/authorize?app=acme&origin=https://acme.dev'), state = new URL(a.headers.get('location')).searchParams.get('state');
  const page = await (await f((await f('/callback?code=c&state=' + state)).headers.get('location'))).text();
  const cid = page.match(/name=id value="([^"]+)"/)[1], ccsrf = page.match(/name=csrf value="([^"]+)"/)[1];
  const cr = await f('/consent', { method: 'POST', headers: form, body: `id=${cid}&csrf=${ccsrf}&decision=allow` });
  const cookie = cr.headers.get('set-cookie').split(';')[0]; assert(/HttpOnly/.test(cr.headers.get('set-cookie')));
  const grant = (await cr.text()).match(/"grant":"([^"]+)"/)[1];
  const J = (p, b, k = KEY) => f(p, { method: 'POST', headers: { authorization: 'Bearer ' + k, 'content-type': 'application/json' }, body: JSON.stringify({ app: 'acme', ...b }) });
  const tk = await (await J('/token', { grant, origin: 'https://acme.dev' })).json();
  assert(!('access_token' in tk) && !JSON.stringify(tk).includes('gho_t'), 'company never gets the GitHub token');
  assert.strictEqual((await J('/token', { grant, origin: 'https://acme.dev' })).status, 400, 'grant single-use');
  const S = { session: tk.session, origin: 'https://acme.dev' };
  const REQ = { ...S, method: 'POST', path: '/repos/octo/x/issues', body: { title: 'hi' }, summary: 'Open an issue' };
  // grant/other tokens are not sessions
  assert.strictEqual((await J('/action', { ...REQ, session: grant })).status, 400);
  // queue an action
  const q1 = await J('/action', REQ); assert.strictEqual(q1.status, 202); const { action_id } = await q1.json();
  assert.strictEqual(gh.length, 0, 'nothing sent on queue');
  // no action without approval
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id })).status, 403);
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id, approval: tk.session })).status, 403, 'session is not an approval');
  assert.strictEqual(gh.length, 0);
  // approval screen: only the owning user, shows site/app/exact request
  assert.strictEqual((await f('/approve?id=' + action_id)).status, 403, 'no user cookie');
  const ap = await (await f('/approve?id=' + action_id, { headers: { cookie } })).text();
  assert(ap.includes('https://acme.dev') && ap.includes('POST https://api.github.com/repos/octo/x/issues') && ap.includes('&quot;title&quot;'));
  const csrf = ap.match(/name=csrf value="([^"]+)"/)[1];
  assert.strictEqual((await f('/approve', { method: 'POST', headers: form, body: `id=${action_id}&csrf=${csrf}&decision=allow` })).status, 400, 'POST needs user');
  const done = await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${action_id}&csrf=${csrf}&decision=allow` })).text();
  assert(done.includes(', "https://acme.dev")'), 'approval only posted to bound origin');
  const approval = done.match(/"approval":"([^"]+)"/)[1];
  // tampering: hash mismatch
  assert.strictEqual((await J('/action/execute', { ...REQ, body: { title: 'evil' }, action_id, approval })).status, 403);
  assert.strictEqual((await J('/action/execute', { ...REQ, path: '/user/repos', action_id, approval })).status, 403);
  // wrong origin
  assert.strictEqual((await J('/action/execute', { ...REQ, origin: 'https://evil.dev', action_id, approval })).status, 400);
  // wrong app key
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id, approval }, 'nope')).status, 401);
  assert.strictEqual(gh.length, 0, 'nothing sent on tamper/wrong origin');
  // happy path, exactly once
  const ex = await J('/action/execute', { ...REQ, action_id, approval }); assert.strictEqual(ex.status, 200);
  assert.strictEqual(gh.length, 1); assert.strictEqual(gh[0].url, 'https://api.github.com/repos/octo/x/issues'); assert.strictEqual(gh[0].body, '{"title":"hi"}');
  // replay
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id, approval })).status, 403); assert.strictEqual(gh.length, 1);
  // deny
  const { action_id: d2 } = await (await J('/action', REQ)).json();
  const ap2 = await (await f('/approve?id=' + d2, { headers: { cookie } })).text(), c2 = ap2.match(/name=csrf value="([^"]+)"/)[1];
  assert((await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${d2}&csrf=${c2}&decision=deny` })).text()).includes('doublehub:denied'));
  assert.strictEqual((await f('/approve?id=' + d2, { headers: { cookie } })).status, 400, 'denied action gone');
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id: d2, approval })).status, 403); assert.strictEqual(gh.length, 1);
  // expiry: action and approval
  const { action_id: d3 } = await (await J('/action', REQ)).json();
  store.putAction(d3, store.getAction(d3), 1000, 0);
  assert.strictEqual((await f('/approve?id=' + d3, { headers: { cookie } })).status, 400, 'expired action');
  const oldAppr = L.signGrant({ typ: 'approval', aid: 'z', app: 'acme', origin: 'https://acme.dev', sub: '7', h: 'h' }, SECRET, 60, Date.now() - 120000);
  assert.strictEqual((await J('/action/execute', { ...REQ, action_id: 'z', approval: oldAppr })).status, 403, 'expired approval');
  // bad paths rejected
  for (const path of ['https://evil.dev/x', '//evil.dev/x', '/repos/../x', 'repos']) assert.strictEqual((await J('/action', { ...REQ, path })).status, 400, path);
  // doublehub.send: approval + signed receipt; companies reject unsigned/tampered/replayed
  const dest = 'https://api.acme.dev/ingest', payload = { email: 'o@x.dev', n: 1 };
  const su = E.sendUrl(base.replace('127.0.0.1', 'localhost'), 'acme', 'https://acme.dev', dest, payload).replace(/^http:\/\/localhost/, 'http://127.0.0.1');
  assert.strictEqual((await f(new URL(su).pathname + new URL(su).search)).status, 403, 'send needs user');
  assert.strictEqual((await f(new URL(su).pathname + new URL(su).search.replace(encodeURIComponent(dest), encodeURIComponent('https://evil.dev/x')), { headers: { cookie } })).status, 403, 'dest allowlist');
  assert.strictEqual((await f(new URL(su).pathname + new URL(su).search.replace('acme.dev&', 'evil.dev&'), { headers: { cookie } })).status, 403, 'wrong origin');
  const sr = await f(new URL(su).pathname + new URL(su).search, { headers: { cookie } }); assert.strictEqual(sr.status, 302);
  const sid = new URL(sr.headers.get('location'), base).searchParams.get('id');
  const sp = await (await f('/approve?id=' + sid, { headers: { cookie } })).text(); assert(sp.includes(dest) && sp.includes('o@x.dev'));
  const sdone = await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${sid}&csrf=${sp.match(/name=csrf value="([^"]+)"/)[1]}&decision=allow` })).text();
  const receipt = sdone.match(/"receipt":"([^"]+)"/)[1];
  assert.strictEqual((await J('/receipt/verify', { receipt: 'a.b', payload, dest })).status, 403, 'unsigned');
  assert.strictEqual((await J('/receipt/verify', { receipt, payload: { ...payload, n: 2 }, dest })).status, 403, 'tampered payload');
  assert.strictEqual((await J('/receipt/verify', { receipt, payload, dest: 'https://api.acme.dev/other' })).status, 403, 'other dest');
  const v = await J('/receipt/verify', { receipt, payload, dest }); assert.strictEqual(v.status, 200); assert.strictEqual((await v.json()).sub, '7');
  assert.strictEqual((await J('/receipt/verify', { receipt, payload, dest })).status, 403, 'receipt replay');
  // audit log
  assert.strictEqual((await f('/audit')).status, 403);
  const au = (await (await f('/audit', { headers: { cookie, accept: 'application/json' } })).json()).entries.map(e => e.decision + ':' + e.kind);
  for (const want of ['approved:github', 'executed:github', 'denied:github', 'approved:send', 'blocked: request changed after approval:github']) assert(au.includes(want), want);
  assert((await (await f('/audit', { headers: { cookie } })).text()).includes('send to ' + dest));
  // embed accepts approval/receipt only from server+popup
  const so = 'https://auth.dh', pop = {};
  assert(E.acceptMessage({ origin: so, source: pop, data: { type: 'doublehub:receipt', receipt: 'a.b' } }, so, pop));
  assert(!E.acceptMessage({ origin: 'https://evil.dev', source: pop, data: { type: 'doublehub:approval', approval: 'a.b' } }, so, pop));
  srv.close(); console.log('action tests lit');
})().catch(e => { console.error(e); process.exit(1); });
