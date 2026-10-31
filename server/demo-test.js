'use strict';
// Demo company backend (DH_DEMO=1): full three-layer flow through /demo/* routes.
const assert = require('assert'), L = require('./lib'), { createServer } = require('./server');
const SECRET = 'x'.repeat(40), KEY = 'd'.repeat(32), O = 'https://fitzyracing1.github.io';
(async () => {
  const mk = demo => ({ secret: SECRET, base: 'http://127.0.0.1:0', demo, apps: { 'doublehub-demo': { id: 'doublehub-demo', origins: [O], send_to: ['http://127.0.0.1'], client_id: 'cid', client_secret: 'cs', app_key: KEY } } });
  const gh = [];
  const fake = async (url, o = {}) => {
    if (url.startsWith('http://127.0.0.1')) return fetch(url, o);
    if (url.includes('access_token')) return { json: async () => ({ access_token: 'gho_t' }) };
    if (url === 'https://api.github.com/user' && !o.method) return { json: async () => ({ id: 7, login: 'octo' }) };
    gh.push({ url, ...o }); return { status: 200, text: async () => '{"login":"octo"}' };
  };
  // off by default
  const off = createServer(mk(false), L.createStore(), fake).listen(0); await new Promise(r => off.on('listening', r));
  assert.strictEqual((await fetch('http://127.0.0.1:' + off.address().port + '/demo/token', { method: 'POST', headers: { origin: O } })).status, 404, 'demo off unless DH_DEMO=1');
  off.close();
  const cfg = mk(true), srv = createServer(cfg, L.createStore(), fake).listen(0); await new Promise(r => srv.on('listening', r));
  const base = 'http://127.0.0.1:' + srv.address().port, f = (p, o) => fetch(base + p, { redirect: 'manual', ...o });
  cfg.apps['doublehub-demo'].send_to = [base];
  const form = { 'content-type': 'application/x-www-form-urlencoded' };
  const D = (p, b, origin = O) => f(p, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify(b) });
  assert.strictEqual((await D('/demo/token', {}, 'https://evil.dev')).status, 403, 'other origins refused');
  const pre = await f('/demo/token', { method: 'OPTIONS', headers: { origin: O } });
  assert.strictEqual(pre.headers.get('access-control-allow-origin'), O);
  // layers 1+2
  const a = await f('/authorize?app=doublehub-demo&origin=' + O), state = new URL(a.headers.get('location')).searchParams.get('state');
  const page = await (await f((await f('/callback?code=c&state=' + state)).headers.get('location'))).text();
  const cid = page.match(/name=id value="([^"]+)"/)[1], ccsrf = page.match(/name=csrf value="([^"]+)"/)[1];
  const cr = await f('/consent', { method: 'POST', headers: form, body: `id=${cid}&csrf=${ccsrf}&decision=allow` });
  const cookie = cr.headers.get('set-cookie').split(';')[0], grant = (await cr.text()).match(/"grant":"([^"]+)"/)[1];
  const tk = await (await D('/demo/token', { grant })).json();
  assert.strictEqual(tk.login, 'octo'); assert(!JSON.stringify(tk).includes('gho_t'));
  // layer 3a: GET /user, only after approval
  const { action_id } = await (await D('/demo/action', { session: tk.session })).json();
  assert.strictEqual((await D('/demo/execute', { session: tk.session, action_id })).status, 403, 'no approval');
  assert.strictEqual(gh.length, 0);
  const ap = await (await f('/approve?id=' + action_id, { headers: { cookie } })).text(), csrf = ap.match(/name=csrf value="([^"]+)"/)[1];
  assert(ap.includes('GET https://api.github.com/user'));
  const approval = (await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${action_id}&csrf=${csrf}&decision=allow` })).text()).match(/"approval":"([^"]+)"/)[1];
  const ex = await (await D('/demo/execute', { session: tk.session, action_id, approval })).json();
  assert.strictEqual(ex.login, 'octo'); assert.strictEqual(gh.length, 1);
  assert.strictEqual((await D('/demo/execute', { session: tk.session, action_id, approval })).status, 403, 'single use');
  // layer 3b: doublehub.send to the demo endpoint
  const dest = base + '/demo/receive', payload = { hello: 'octo' };
  const sq = '/send?app=doublehub-demo&origin=' + encodeURIComponent(O) + '&dest=' + encodeURIComponent(dest) + '&payload=' + Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sid = new URL((await f(sq, { headers: { cookie } })).headers.get('location'), base).searchParams.get('id');
  const sp = await (await f('/approve?id=' + sid, { headers: { cookie } })).text(), sc = sp.match(/name=csrf value="([^"]+)"/)[1];
  const receipt = (await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${sid}&csrf=${sc}&decision=allow` })).text()).match(/"receipt":"([^"]+)"/)[1];
  assert.strictEqual((await D('/demo/receive', { payload: { hello: 'evil' }, receipt, dest })).status, 403, 'tampered payload rejected');
  const rv = await D('/demo/receive', { payload, receipt, dest }); assert.strictEqual(rv.status, 200); assert((await rv.json()).accepted);
  assert.strictEqual((await D('/demo/receive', { payload, receipt, dest })).status, 403, 'receipt replay');
  srv.close(); console.log('demo tests lit');
})().catch(e => { console.error(e); process.exit(1); });
