'use strict';
// doublehub two-layer auth server. Zero dependencies: node server/server.js
const http = require('http');
const L = require('./lib');

function createServer(cfg = L.loadConfig(), store = L.createStore(), fetchImpl = globalThis.fetch) {
  const send = (res, code, body, type = 'application/json', extra = {}) => {
    res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", ...extra });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const readBody = req => new Promise((ok, no) => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e5) no(new Error('too big')); }); req.on('end', () => ok(d)); });
  const parse = (d, type) => type && type.includes('json') ? JSON.parse(d || '{}') : Object.fromEntries(new URLSearchParams(d));

  return http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url, cfg.base), q = u.searchParams;
      // Layer 1 start: popup lands here from embed.js
      if (u.pathname === '/authorize' && req.method === 'GET') {
        const app = cfg.apps[q.get('app')], origin = q.get('origin');
        if (!L.originAllowed(app, origin)) return send(res, 403, { error: 'origin not allowed for this app' });
        const state = L.rand(), { verifier, challenge } = L.pkce();
        store.putState(state, { app: app.id, origin: L.normOrigin(origin), verifier });
        const gh = new URL('https://github.com/login/oauth/authorize');
        gh.search = new URLSearchParams({ client_id: app.client_id, redirect_uri: cfg.base + '/callback', state,
          code_challenge: challenge, code_challenge_method: 'S256', ...(app.scopes ? { scope: app.scopes } : {}) });
        return send(res, 302, '', 'text/plain', { location: gh.toString() });
      }
      // Layer 1 finish: exchange code (needs client_secret, hence this server)
      if (u.pathname === '/callback' && req.method === 'GET') {
        const st = store.takeState(q.get('state') || '');
        if (!st) return send(res, 400, { error: 'bad or expired state' });
        const app = cfg.apps[st.app];
        const r = await fetchImpl('https://github.com/login/oauth/access_token', { method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ client_id: app.client_id, client_secret: app.client_secret, code: q.get('code'),
            redirect_uri: cfg.base + '/callback', code_verifier: st.verifier }) });
        const tok = await r.json();
        if (!tok.access_token) return send(res, 400, { error: 'github exchange failed' });
        const me = await (await fetchImpl('https://api.github.com/user', { headers: { authorization: 'Bearer ' + tok.access_token, 'user-agent': 'doublehub' } })).json();
        const id = L.rand();
        store.putPending(id, { app: app.id, origin: st.origin, sub: String(me.id), login: me.login, token: tok.access_token, csrf: L.rand() });
        return send(res, 302, '', 'text/plain', { location: '/consent?id=' + encodeURIComponent(id) });
      }
      // Layer 2: doublehub consent, bound to the embedding origin
      if (u.pathname === '/consent' && req.method === 'GET') {
        const p = store.getPending(q.get('id') || ''); if (!p) return send(res, 400, 'Expired. Close this window and try again.', 'text/plain');
        const app = cfg.apps[p.app];
        return send(res, 200, `<!doctype html><meta charset=utf-8><title>doublehub consent</title>
<body style="font:16px system-ui;max-width:480px;margin:40px auto">
<h2>Allow this site?</h2>
<p>Signed in to GitHub as <b>${L.esc(p.login)}</b>.</p>
<p><b>${L.esc(p.origin)}</b> wants to use <b>${L.esc(app.name || app.id)}</b> with access: <code>${L.esc(app.scopes || 'basic profile')}</code>.</p>
<p>This consent only applies to <b>${L.esc(p.origin)}</b>. You can revoke it any time.</p>
<form method=post action="/consent"><input type=hidden name=id value="${L.esc(q.get('id'))}"><input type=hidden name=csrf value="${L.esc(p.csrf)}">
<button name=decision value=allow>Allow</button> <button name=decision value=deny>Deny</button></form>`, 'text/html');
      }
      if (u.pathname === '/consent' && req.method === 'POST') {
        const b = parse(await readBody(req), req.headers['content-type']), p = store.getPending(b.id || '');
        if (!p || !L.safeEq(b.csrf || '', p.csrf)) return send(res, 400, 'Expired.', 'text/plain');
        store.dropPending(b.id);
        let msg;
        if (b.decision === 'allow') {
          store.grantConsent(p.app, p.origin, p.sub, { token: p.token, login: p.login });
          msg = { type: 'doublehub:grant', grant: L.signGrant({ app: p.app, origin: p.origin, sub: p.sub, login: p.login }, cfg.secret) };
        } else msg = { type: 'doublehub:denied' };
        // targetOrigin is the exact bound origin: another site can never receive it.
        return send(res, 200, `<!doctype html><meta charset=utf-8><p>Done. You can close this window.</p><script>
if (window.opener) window.opener.postMessage(${JSON.stringify(msg).replace(/</g, '\\u003c')}, ${JSON.stringify(p.origin).replace(/</g, '\\u003c')}); window.close();</script>`, 'text/html');
      }
      // Company backend redeems a grant for the GitHub token (both layers done)
      if (u.pathname === '/token' && req.method === 'POST') {
        const b = parse(await readBody(req), 'json'), app = cfg.apps[b.app];
        if (!app || !app.app_key || !L.safeEq((req.headers.authorization || '').replace(/^Bearer /, ''), app.app_key)) return send(res, 401, { error: 'unauthorized' });
        const c = L.verifyGrant(b.grant, cfg.secret, { app: app.id, origin: L.normOrigin(b.origin || ''), isRevoked: x => store.isRevoked(x) });
        const con = store.getConsent(c.app, c.origin, c.sub);
        return send(res, 200, { login: con.login, sub: c.sub, access_token: con.token });
      }
      // Revoke: user (holding the grant) or company withdraws consent for that origin
      if (u.pathname === '/revoke' && req.method === 'POST') {
        const b = parse(await readBody(req), req.headers['content-type']);
        let c; try { c = L.verifyGrant(b.grant, cfg.secret, { now: 0 }); } catch (e) { return send(res, 400, { error: e.message }); }
        store.revoke(c.app, c.origin, c.sub, c.jti);
        return send(res, 200, { revoked: true });
      }
      send(res, 404, { error: 'not found' });
    } catch (e) { send(res, 400, { error: e.message }); }
  });
}

module.exports = { createServer };
if (require.main === module) {
  const cfg = L.loadConfig();
  if (!cfg.secret || cfg.secret.length < 32) { console.error('Set DH_SECRET (32+ chars).'); process.exit(1); }
  createServer(cfg).listen(cfg.port, () => console.log('doublehub auth server on port ' + cfg.port));
}
