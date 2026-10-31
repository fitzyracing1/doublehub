'use strict';
// First-party backend (DH_FIRST_PARTY=1): sign in, approve site, approved GET /user, audit, sites, revoke via /app/*.
const assert = require('assert'), L = require('./lib'), { createServer } = require('./server');
const SECRET = 'x'.repeat(40), KEY = 'd'.repeat(32), O = 'https://fitzyracing1.github.io';
(async () => {
  const mk = on => ({ secret: SECRET, base: 'http://127.0.0.1:0', firstParty: on, apps: { doublehub: { id: 'doublehub', origins: [O], send_to: [], client_id: 'cid', client_secret: 'cs', app_key: KEY } } });
  const gh = [];
  const fake = async (url, o = {}) => {
    if (url.startsWith('http://127.0.0.1')) return fetch(url, o);
    if (url.includes('access_token')) return { json: async () => ({ access_token: 'gho_t' }) };
    if (url === 'https://api.github.com/user' && !o.method) return { json: async () => ({ id: 7, login: 'octo' }) };
    gh.push({ url, ...o }); return { status: 200, text: async () => '{"login":"octo","name":"Octo Cat","followers":3}' };
  };
  assert.strictEqual(L.loadConfig({ DH_FIRST_PARTY: '1' }).firstParty, true);
  assert.strictEqual(L.loadConfig({ DH_APPS: '{"doublehub":{}}', DH_APP_KEY_DOUBLEHUB: 'k', GITHUB_CLIENT_SECRET_DOUBLEHUB: 's' }).apps.doublehub.app_key, 'k');
  const off = createServer(mk(false), L.createStore(), fake).listen(0); await new Promise(r => off.on('listening', r));
  assert.strictEqual((await fetch('http://127.0.0.1:' + off.address().port + '/app/token', { method: 'POST', headers: { origin: O } })).status, 404, 'off unless DH_FIRST_PARTY=1');
  off.close();
  const srv = createServer(mk(true), L.createStore(), fake).listen(0); await new Promise(r => srv.on('listening', r));
  const base = 'http://127.0.0.1:' + srv.address().port, f = (p, o) => fetch(base + p, { redirect: 'manual', ...o });
  const form = { 'content-type': 'application/x-www-form-urlencoded' };
  const D = (p, b, origin = O) => f(p, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify(b) });
  assert.strictEqual((await D('/app/token', {}, 'https://evil.dev')).status, 403, 'other origins refused');
  assert.strictEqual((await f('/app/token', { method: 'OPTIONS', headers: { origin: O } })).headers.get('access-control-allow-origin'), O);
  // layer 1 (GitHub) + layer 2 (approve doublehub for this site)
  const a = await f('/authorize?app=doublehub&origin=' + O), state = new URL(a.headers.get('location')).searchParams.get('state');
  const page = await (await f((await f('/callback?code=c&state=' + state)).headers.get('location'))).text();
  const cid = page.match(/name=id value="([^"]+)"/)[1], ccsrf = page.match(/name=csrf value="([^"]+)"/)[1];
  const cr = await f('/consent', { method: 'POST', headers: form, body: `id=${cid}&csrf=${ccsrf}&decision=allow` });
  const cookie = cr.headers.get('set-cookie').split(';')[0], grant = (await cr.text()).match(/"grant":"([^"]+)"/)[1];
  const tk = await (await D('/app/token', { grant })).json();
  assert.strictEqual(tk.login, 'octo'); assert(!JSON.stringify(tk).includes('gho_t'));
  // identity: GET /user only after per-action approval
  const { action_id } = await (await D('/app/identity/request', { session: tk.session })).json();
  assert.strictEqual((await D('/app/identity', { session: tk.session, action_id })).status, 403, 'no approval');
  assert.strictEqual(gh.length, 0);
  const ap = await (await f('/approve?id=' + action_id, { headers: { cookie } })).text(), csrf = ap.match(/name=csrf value="([^"]+)"/)[1];
  assert(ap.includes('GET https://api.github.com/user'));
  const approval = (await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${action_id}&csrf=${csrf}&decision=allow` })).text()).match(/"approval":"([^"]+)"/)[1];
  const id = await (await D('/app/identity', { session: tk.session, action_id, approval })).json();
  assert.strictEqual(id.user.login, 'octo'); assert.strictEqual(id.user.name, 'Octo Cat'); assert.strictEqual(gh.length, 1);
  assert.strictEqual((await D('/app/identity', { session: tk.session, action_id, approval })).status, 403, 'single use');
  // audit + sites
  assert.strictEqual((await D('/app/audit', { session: 'junk' })).status, 401);
  const au = (await (await D('/app/audit', { session: tk.session })).json()).entries;
  assert.deepStrictEqual(au.map(e => e.decision), ['executed', 'approved']);
  const sites = (await (await D('/app/sites', { session: tk.session })).json()).sites;
  assert.deepStrictEqual(sites, [{ app: 'doublehub', origin: O, login: 'octo' }]);
  // revoke
  assert.strictEqual((await D('/app/revoke', { session: tk.session, app: 'doublehub', origin: 'https://other.dev' })).status, 404);
  assert.strictEqual((await D('/app/revoke', { session: tk.session, app: 'doublehub', origin: O })).status, 200);
  assert.strictEqual((await D('/app/sites', { session: tk.session })).status, 401, 'session ends once revoked');
  srv.close(); console.log('first-party tests lit');
})().catch(e => { console.error(e); process.exit(1); });
