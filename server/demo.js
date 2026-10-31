'use strict';
// Built-in demo "company backend" for app 'doublehub-demo'. Only active when DH_DEMO=1.
// It holds the app key server-side and calls doublehub over loopback exactly like a real company server would.
const DEMO_APP = 'doublehub-demo';
function demoHandler(cfg, fetchImpl = globalThis.fetch) {
  return async (req, res, u, readBody) => {
    if (!u.pathname.startsWith('/demo/')) return false;
    const app = cfg.apps[DEMO_APP], origin = req.headers.origin || '';
    const ok = app && app.app_key && app.origins.includes(origin);
    const hdr = { 'content-type': 'application/json', 'cache-control': 'no-store',
      ...(ok ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'POST', vary: 'origin' } : {}) };
    const out = (code, body) => { res.writeHead(code, hdr); res.end(JSON.stringify(body)); return true; };
    if (!ok) return out(403, { error: 'demo not enabled for this origin' });
    if (req.method === 'OPTIONS') return out(204, {});
    if (req.method !== 'POST') return out(405, { error: 'POST only' });
    const b = JSON.parse((await readBody(req)) || '{}');
    const self = (p, body) => fetchImpl('http://127.0.0.1:' + req.socket.localPort + p, { method: 'POST',
      headers: { authorization: 'Bearer ' + app.app_key, 'content-type': 'application/json' }, body: JSON.stringify({ app: DEMO_APP, origin, ...body }) })
      .then(async r => ({ status: r.status, data: await r.json() }));
    const GET_USER = { method: 'GET', path: '/user' };
    let r;
    if (u.pathname === '/demo/token') { r = await self('/token', { grant: b.grant });
      return out(r.status, r.status === 200 ? { login: r.data.login, session: r.data.session } : r.data); }
    if (u.pathname === '/demo/action') { r = await self('/action', { session: b.session, ...GET_USER, summary: 'doublehub demo: read your GitHub login (GET /user)' });
      return out(r.status, r.status === 202 ? { action_id: r.data.action_id } : r.data); }
    if (u.pathname === '/demo/execute') { r = await self('/action/execute', { session: b.session, action_id: b.action_id, approval: b.approval, ...GET_USER });
      return out(r.status, r.status === 200 ? { github_status: r.data.status, login: r.data.data && r.data.data.login } : r.data); }
    if (u.pathname === '/demo/receive') { r = await self('/receipt/verify', { receipt: b.receipt, dest: b.dest, payload: b.payload });
      return out(r.status === 200 && r.data.valid ? 200 : 403, r.status === 200 && r.data.valid ? { accepted: true, payload: b.payload } : { accepted: false, error: r.data.error || 'invalid receipt' }); }
    return out(404, { error: 'not found' });
  };
}
module.exports = { demoHandler, DEMO_APP };
