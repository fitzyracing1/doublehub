'use strict';
// Low-risk pre-approval tests: opt-in, per site + pattern, time-limited, revocable, audited; risky calls always prompt.
const assert = require('assert'), L = require('./lib'), { createServer } = require('./server');
const SECRET = 'x'.repeat(40), KEY = 'k'.repeat(32);
(async () => {
  // classifier: allowlist only, unsure => risky
  assert.strictEqual(L.lowRiskPattern('GET', '/repos/octo/x', null), '/repos/:owner/:repo');
  assert.strictEqual(L.lowRiskPattern('GET', '/users/octo', null), '/users/:user');
  for (const [m, p, b] of [['POST', '/repos/octo/x', null], ['DELETE', '/repos/octo/x', null], ['PUT', '/repos/octo/x/topics', {}], ['PATCH', '/repos/octo/x', null],
    ['GET', '/user', null], ['GET', '/user/emails', null], ['GET', '/user/repos', null], ['GET', '/repos/octo/x/actions/secrets', null], ['GET', '/repos/octo/x/collaborators', null],
    ['GET', '/repos/octo/x/contents/a', null], ['GET', '/repos/octo/x/issues', null], ['GET', '/repos/octo/x?private=1', null], ['GET', '/repos/octo/x', { a: 1 }], ['GET', '/something/new', null]])
    assert.strictEqual(L.lowRiskPattern(m, p, b), null, m + ' ' + p);
  const cfg = { secret: SECRET, base: 'http://127.0.0.1:0', firstParty: true, apps: {
    acme: { id: 'acme', origins: ['https://acme.dev'], send_to: [], client_id: 'cid', client_secret: 'cs', app_key: KEY },
    doublehub: { id: 'doublehub', origins: ['https://dh.dev'], send_to: [], client_id: 'cid2', client_secret: 'cs2', app_key: 'd'.repeat(32) } } };
  const gh = []; let privateNext = false;
  const fake = async (url, o = {}) => {
    if (url.includes('access_token')) return { json: async () => ({ access_token: 'gho_t' }) };
    if (url === 'https://api.github.com/user' && !o.method) return { json: async () => ({ id: 7, login: 'octo' }) };
    if (url.startsWith('http://127.0.0.1')) return globalThis.fetch(url, o).then(async r => ({ status: r.status, json: () => r.json() }));
    gh.push({ url, ...o }); const body = privateNext ? '{"name":"x","private":true}' : '{"name":"x","private":false}';
    return { status: 200, text: async () => body };
  };
  const store = L.createStore(), srv = createServer(cfg, store, fake).listen(0); await new Promise(r => srv.on('listening', r));
  const base = 'http://127.0.0.1:' + srv.address().port, f = (p, o) => fetch(base + p, { redirect: 'manual', ...o });
  const form = { 'content-type': 'application/x-www-form-urlencoded' };
  const a = await f('/authorize?app=acme&origin=https://acme.dev'), state = new URL(a.headers.get('location')).searchParams.get('state');
  const page = await (await f((await f('/callback?code=c&state=' + state)).headers.get('location'))).text();
  const cr = await f('/consent', { method: 'POST', headers: form, body: `id=${page.match(/name=id value="([^"]+)"/)[1]}&csrf=${page.match(/name=csrf value="([^"]+)"/)[1]}&decision=allow` });
  const cookie = cr.headers.get('set-cookie').split(';')[0], grant = (await cr.text()).match(/"grant":"([^"]+)"/)[1];
  const J = (p, b) => f(p, { method: 'POST', headers: { authorization: 'Bearer ' + KEY, 'content-type': 'application/json' }, body: JSON.stringify({ app: 'acme', ...b }) });
  const S = { session: (await (await J('/token', { grant, origin: 'https://acme.dev' })).json()).session, origin: 'https://acme.dev' };
  const READ = { ...S, method: 'GET', path: '/repos/octo/x' }, READ2 = { ...S, method: 'GET', path: '/repos/octo/other' };
  const WRITE = { ...S, method: 'PATCH', path: '/repos/octo/x', body: { description: 'hi' } };
  const decide = async (id, extra = '') => { const ap = await (await f('/approve?id=' + id, { headers: { cookie } })).text();
    const r = await (await f('/approve', { method: 'POST', headers: { ...form, cookie }, body: `id=${id}&csrf=${ap.match(/name=csrf value="([^"]+)"/)[1]}&decision=allow${extra}` })).text();
    return { ap, approval: r.match(/"approval":"([^"]+)"/)[1] }; };
  const audit = () => store.auditFor('7').map(e => e.decision + ' ' + (e.method || '') + ' ' + (e.path || ''));

  // off by default: low-risk read still prompts; popup offers the checkbox
  const q1 = await J('/action', READ); assert.strictEqual(q1.status, 202); const id1 = (await q1.json()).action_id;
  const d1 = await decide(id1); assert(d1.ap.includes('name=preapprove') && d1.ap.includes('1 hour'), 'checkbox shown for low-risk');
  assert.strictEqual((await J('/action', READ)).status, 202, 'no grant without the checkbox');
  // risky popup has no checkbox
  const qw = await (await J('/action', WRITE)).json(); assert(!(await (await f('/approve?id=' + qw.action_id, { headers: { cookie } })).text()).includes('name=preapprove'));
  // forging the checkbox on a risky call grants nothing (server-side)
  await decide(qw.action_id, '&preapprove=1&ttl=86400'); assert.strictEqual(store.presFor('7').length, 0, 'risky call cannot be pre-approved');
  // opt in on a low-risk read, ttl clamped to 24h max
  const q2 = await (await J('/action', READ)).json(); await decide(q2.action_id, '&preapprove=1&ttl=999999');
  const pres = store.presFor('7'); assert.strictEqual(pres.length, 1); assert.strictEqual(pres[0].path, '/repos/:owner/:repo');
  assert(Date.parse(pres[0].expires_at) - Date.now() <= 86400e3 + 1000, 'max 24h');
  // within window: same pattern auto-approves (other repo too), executes, audited as pre-approved
  const p1 = await J('/action', READ2); assert.strictEqual(p1.status, 200); const pj = await p1.json(); assert(pj.preapproved && pj.approval);
  const ex = await J('/action/execute', { ...READ2, action_id: pj.action_id, approval: pj.approval }); assert.strictEqual(ex.status, 200);
  assert(audit().includes('pre-approved GET /repos/octo/other') && audit().includes('executed (pre-approved) GET /repos/octo/other'));
  // pre-approval approval cannot be reused for a different request
  const p1b = await (await J('/action', READ)).json();
  assert.strictEqual((await J('/action/execute', { ...WRITE, action_id: p1b.action_id, approval: p1b.approval })).status, 403);
  // private content never returned under pre-approval
  privateNext = true; const pp = await (await J('/action', READ)).json(); const n = gh.length;
  assert.strictEqual((await J('/action/execute', { ...READ, action_id: pp.action_id, approval: pp.approval })).status, 403); privateNext = false;
  assert(audit().some(x => x.startsWith('blocked: private content')));
  // risky call always prompts, even with a live grant
  assert.strictEqual((await J('/action', WRITE)).status, 202);
  assert.strictEqual((await J('/action', { ...S, method: 'GET', path: '/user' })).status, 202);
  assert.strictEqual((await J('/action', { ...S, method: 'GET', path: '/repos/octo/x/languages' })).status, 202, 'other pattern still prompts');
  // grant is per site: a different site's session gets nothing (consent store is keyed per origin)
  assert.strictEqual(store.getPre('acme', 'https://evil.dev', '7', 'GET', '/repos/:owner/:repo'), null);
  // expiry
  const k = store.presFor('7')[0]; store.grantPre('acme', 'https://acme.dev', '7', 'GET', '/repos/:owner/:repo', 1, Date.now() - 5000);
  assert.strictEqual((await J('/action', READ)).status, 202, 'expired grant prompts');
  // grant again, issue approval, then revoke before execute => blocked
  store.grantPre('acme', 'https://acme.dev', '7', 'GET', '/repos/:owner/:repo', 3600);
  const pr = await (await J('/action', READ)).json(); assert(pr.preapproved);
  assert(store.revokePre('7', store.presFor('7')[0].id));
  assert.strictEqual((await J('/action', READ)).status, 202, 'revoked grant prompts');
  assert.strictEqual((await J('/action/execute', { ...READ, action_id: pr.action_id, approval: pr.approval })).status, 403, 'revoked between issue and execute');
  // revoking the site removes its pre-approvals
  store.grantPre('acme', 'https://acme.dev', '7', 'GET', '/repos/:owner/:repo', 3600); assert.strictEqual(store.presFor('7').length, 1);
  await f('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant }) });
  assert.strictEqual(store.presFor('7').length, 0, 'site revoke drops pre-approvals');
  store.grantConsent('acme', 'https://acme.dev', '7', { token: 't', login: 'octo' });
  assert.strictEqual(store.getPre('acme', 'https://acme.dev', '7', 'GET', '/repos/:owner/:repo'), null, 'does not come back on reconnect');
  // audit has the grant entry
  assert(audit().some(x => x.startsWith('granted for 1440 min GET /repos/:owner/:repo')));
  srv.close(); console.log('pre-approval tests lit');
})().catch(e => { console.error(e); process.exit(1); });
