'use strict';
// First-party backend for app 'doublehub' (the doublehub site itself). Only active when DH_FIRST_PARTY=1.
// Holds the app key server-side and calls doublehub over loopback exactly like any company backend would.
// Outbound GitHub calls still need a per-action user approval.
const APP = 'doublehub';
function firstPartyHandler(cfg, store, fetchImpl = globalThis.fetch) {
  return async (req, res, u, readBody) => {
    if (!u.pathname.startsWith('/app/')) return false;
    const app = cfg.apps[APP], origin = req.headers.origin || '';
    const ok = app && app.app_key && app.origins.includes(origin);
    const hdr = { 'content-type': 'application/json', 'cache-control': 'no-store',
      ...(ok ? { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'POST', vary: 'origin' } : {}) };
    const out = (code, body) => { res.writeHead(code, hdr); res.end(JSON.stringify(body)); return true; };
    if (!ok) return out(403, { error: 'origin not allowed' });
    if (req.method === 'OPTIONS') return out(204, {});
    if (req.method !== 'POST') return out(405, { error: 'POST only' });
    const b = JSON.parse((await readBody(req)) || '{}');
    const self = (p, body) => fetchImpl('http://127.0.0.1:' + req.socket.localPort + p, { method: 'POST',
      headers: { authorization: 'Bearer ' + app.app_key, 'content-type': 'application/json' }, body: JSON.stringify({ app: APP, origin, ...body }) })
      .then(async r => ({ status: r.status, data: await r.json() }));
    const GET_USER = { method: 'GET', path: '/user' };
    let r;
    if (u.pathname === '/app/token') { r = await self('/token', { grant: b.grant });
      return out(r.status, r.status === 200 ? { login: r.data.login, session: r.data.session } : r.data); }
    if (u.pathname === '/app/identity/request') { r = await self('/action', { session: b.session, ...GET_USER, summary: 'doublehub: show your GitHub profile on your dashboard (GET /user)' });
      return out(r.status, r.status === 202 ? { action_id: r.data.action_id } : r.data); }
    if (u.pathname === '/app/identity') { r = await self('/action/execute', { session: b.session, action_id: b.action_id, approval: b.approval, ...GET_USER });
      if (r.status !== 200) return out(r.status, r.data);
      const d = r.data.data || {};
      return out(200, { github_status: r.data.status, user: { login: d.login, name: d.name, avatar_url: d.avatar_url, html_url: d.html_url, public_repos: d.public_repos, followers: d.followers, created_at: d.created_at } }); }
    // Reads of doublehub's own records for the signed-in user (nothing leaves to GitHub).
    let c; try { c = L.verifyGrant(b.session, cfg.secret, { app: APP, origin: L.normOrigin(origin), isRevoked: x => store.isRevoked(x) }); if (c.typ !== 'session') throw new Error('not a session'); }
    catch (e) { return out(401, { error: 'session ' + e.message }); }
    if (u.pathname === '/app/audit') return out(200, { entries: store.auditFor(c.sub).reverse() });
    if (u.pathname === '/app/sites') return out(200, { sites: store.consentsFor(c.sub) });
    if (u.pathname === '/app/preapprovals') return out(200, { preapprovals: store.presFor(c.sub) });
    if (u.pathname === '/app/preapproval/revoke') { const v = store.revokePre(c.sub, String(b.id || '')); if (!v) return out(404, { error: 'no such pre-approval' });
      store.audit(c.sub, { app: v.app, origin: v.origin, kind: 'preapproval', decision: 'revoked', method: v.method, path: v.tpl }); return out(200, { revoked: true }); }
    if (u.pathname === '/app/revoke') {
      if (!cfg.apps[b.app] || !store.getConsent(b.app, L.normOrigin(b.origin || ''), c.sub)) return out(404, { error: 'no such connection' });
      store.revoke(b.app, L.normOrigin(b.origin), c.sub);
      store.audit(c.sub, { app: b.app, origin: L.normOrigin(b.origin), kind: 'consent', decision: 'revoked' });
      return out(200, { revoked: true });
    }
    return out(404, { error: 'not found' });
  };
}
const L = require('./lib');
module.exports = { firstPartyHandler, APP };
