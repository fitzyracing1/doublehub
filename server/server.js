'use strict';
// doublehub three-layer auth server (GitHub login, per-site consent, per-action approval). Zero dependencies: node server/server.js
const http = require('http');
const L = require('./lib');
const { firstPartyHandler } = require('./firstparty');

const PAGE = `<meta name=viewport content="width=device-width,initial-scale=1"><style>:root{--bg:#f7f8fa;--card:#fff;--fg:#14171c;--muted:#59606b;--line:#e3e6eb;--accent:#4f46e5;--accent-fg:#fff;--code:#f1f3f6;color-scheme:light dark}@media (prefers-color-scheme:dark){:root{--bg:#0d1016;--card:#161a22;--fg:#e8eaee;--muted:#a3aab6;--line:#2a303b;--accent:#8b85ff;--accent-fg:#0d1016;--code:#0f131a}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;padding:24px 16px}main{max-width:560px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px}main.wide{max-width:960px}.brand{font-weight:700;color:var(--muted);font-size:.9rem;margin:0 0 .5rem}h2{margin:0 0 .8rem;letter-spacing:-.01em}a{color:var(--accent)}code,pre{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border-radius:6px;padding:.1rem .3rem;word-break:break-all}pre{display:block;border:1px solid var(--line);padding:.7rem;max-height:240px;overflow:auto;white-space:pre-wrap}small{color:var(--muted)}form{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}button{font:inherit;font-weight:600;border-radius:10px;padding:.65rem 1.2rem;min-height:44px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}button[value=allow]{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}:focus-visible{outline:3px solid var(--accent);outline-offset:2px}.tbl{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{border-bottom:1px solid var(--line);padding:.5rem;text-align:left}th{color:var(--muted);font-size:.8rem;text-transform:uppercase}</style>`;

function createServer(cfg = L.loadConfig(), store = L.createStore(), fetchImpl = globalThis.fetch) {
  const send = (res, code, body, type = 'application/json', extra = {}) => {
    res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", ...extra });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const readBody = req => new Promise((ok, no) => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e5) no(new Error('too big')); }); req.on('end', () => ok(d)); });
  const appAuth = (req, id) => { const app = cfg.apps[id];
    return app && app.app_key && L.safeEq((req.headers.authorization || '').replace(/^Bearer /, ''), app.app_key) ? app : null; };
  const session = (b, app) => { const c = L.verifyGrant(b.session, cfg.secret, { app: app.id, origin: L.normOrigin(b.origin || ''), isRevoked: x => store.isRevoked(x) });
    if (c.typ !== 'session') throw new Error('not a session'); return c; };
  const ghReq = (c, b) => { const method = String(b.method || '').toUpperCase();
    if (!L.METHODS.includes(method) || !L.safeApiPath(b.path)) throw new Error('bad method or path');
    return { kind: 'github', app: c.app, origin: c.origin, sub: c.sub, method, path: b.path, body: b.body === undefined ? null : b.body }; };
  const user = req => { try { const c = L.verifyGrant(decodeURIComponent(L.cookie(req, 'dh_u')), cfg.secret); return c.typ === 'user' ? c.sub : null; } catch { return null; } };
  const userCookie = sub => 'dh_u=' + L.signGrant({ typ: 'user', sub }, cfg.secret, 28800) + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=28800' + (cfg.base.startsWith('https:') ? '; Secure' : '');
  const parse = (d, type) => type && type.includes('json') ? JSON.parse(d || '{}') : Object.fromEntries(new URLSearchParams(d));

  const firstParty = cfg.firstParty ? firstPartyHandler(cfg, store, fetchImpl) : null;
  return http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url, cfg.base), q = u.searchParams;
      if (firstParty && await firstParty(req, res, u, readBody)) return;
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
${PAGE}<body><main><p class=brand>doublehub</p>
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
          msg = { type: 'doublehub:grant', grant: L.signGrant({ typ: 'grant', app: p.app, origin: p.origin, sub: p.sub, login: p.login }, cfg.secret) };
        } else msg = { type: 'doublehub:denied' };
        // targetOrigin is the exact bound origin: another site can never receive it.
        return send(res, 200, `<!doctype html><meta charset=utf-8>${PAGE}<body><main><p class=brand>doublehub</p><p>Done. You can close this window.</p></main><script>
if (window.opener) window.opener.postMessage(${JSON.stringify(msg).replace(/</g, '\\u003c')}, ${JSON.stringify(p.origin).replace(/</g, '\\u003c')}); window.close();</script>`, 'text/html', { 'set-cookie': userCookie(p.sub) });
      }
      // Company backend redeems a grant for a doublehub SESSION (never the GitHub token; the server keeps it).
      if (u.pathname === '/token' && req.method === 'POST') {
        const b = parse(await readBody(req), 'json'), app = appAuth(req, b.app); if (!app) return send(res, 401, { error: 'unauthorized' });
        const c = L.verifyGrant(b.grant, cfg.secret, { app: app.id, origin: L.normOrigin(b.origin || ''), isRevoked: x => store.isRevoked(x) });
        if (c.typ !== 'grant' || !store.useOnce(c.jti)) return send(res, 400, { error: 'grant not usable' });
        const con = store.getConsent(c.app, c.origin, c.sub);
        return send(res, 200, { login: con.login, sub: c.sub, session: L.signGrant({ typ: 'session', app: c.app, origin: c.origin, sub: c.sub }, cfg.secret, 3600) });
      }
      // Layer 3a: company asks to call GitHub on the user's behalf -> pending, needs user approval.
      if (u.pathname === '/action' && req.method === 'POST') {
        const b = parse(await readBody(req), 'json'), app = appAuth(req, b.app); if (!app) return send(res, 401, { error: 'unauthorized' });
        const c = session(b, app), r = ghReq(c, b);
        const id = L.rand(), h = L.reqHash(r), tpl = L.lowRiskPattern(r.method, r.path, r.body);
        // Pre-approval: only for low-risk patterns the human explicitly granted in an approval popup. Risky calls never match (tpl null).
        const pg = tpl && store.getPre(c.app, c.origin, c.sub, r.method, tpl);
        if (pg) {
          store.putAction(id, { kind: 'github', h, r, approved: true, csrf: L.rand(), preapproved: pg.id, app: c.app, origin: c.origin, sub: c.sub });
          store.audit(c.sub, { app: c.app, origin: c.origin, kind: 'github', decision: 'pre-approved', method: r.method, path: r.path, pattern: tpl, hash: h });
          return send(res, 200, { action_id: id, preapproved: true, approval: L.signGrant({ typ: 'approval', aid: id, app: c.app, origin: c.origin, sub: c.sub, h, pre: pg.id }, cfg.secret, 60), request_hash: h, expires_in: 60 });
        }
        store.putAction(id, { kind: 'github', h, r, tpl, summary: String(b.summary || '').slice(0, 500), csrf: L.rand(), app: c.app, origin: c.origin, sub: c.sub });
        return send(res, 202, { action_id: id, approve_url: cfg.base + '/approve?id=' + encodeURIComponent(id), request_hash: h, expires_in: 120 });
      }
      if (u.pathname === '/action/execute' && req.method === 'POST') {
        const b = parse(await readBody(req), 'json'), app = appAuth(req, b.app); if (!app) return send(res, 401, { error: 'unauthorized' });
        const c = session(b, app), r = ghReq(c, b), h = L.reqHash(r);
        let a; try { a = L.verifyGrant(b.approval, cfg.secret, { app: c.app, origin: c.origin }); } catch (e) { return send(res, 403, { error: 'approval ' + e.message }); }
        const act = store.getAction(b.action_id || '');
        if (a.typ !== 'approval' || a.aid !== b.action_id || a.sub !== c.sub || !act || act.kind !== 'github') return send(res, 403, { error: 'no matching approved action' });
        if (!L.safeEq(a.h, h) || !L.safeEq(act.h, h)) { store.audit(c.sub, { app: c.app, origin: c.origin, kind: 'github', decision: 'blocked: request changed after approval', method: r.method, path: r.path }); return send(res, 403, { error: 'request hash mismatch' }); }
        if (!store.useOnce(a.jti)) return send(res, 403, { error: 'approval already used' });
        store.takeAction(b.action_id);
        const con = store.getConsent(c.app, c.origin, c.sub); if (!con) return send(res, 403, { error: 'revoked' });
        if (a.pre && act.preapproved !== a.pre) return send(res, 403, { error: 'no matching approved action' });
        if (a.pre) { const tpl = L.lowRiskPattern(r.method, r.path, r.body); // server-side re-check: grant still live and call still low-risk
          if (!tpl || !store.getPre(c.app, c.origin, c.sub, r.method, tpl) || store.getPre(c.app, c.origin, c.sub, r.method, tpl).id !== a.pre) {
            store.audit(c.sub, { app: c.app, origin: c.origin, kind: 'github', decision: 'blocked: pre-approval no longer valid', method: r.method, path: r.path }); return send(res, 403, { error: 'pre-approval revoked or expired' }); } }
        const gr = await fetchImpl('https://api.github.com' + r.path, { method: r.method, headers: { authorization: 'Bearer ' + con.token, accept: 'application/vnd.github+json', 'user-agent': 'doublehub', ...(r.body != null ? { 'content-type': 'application/json' } : {}) }, ...(r.body != null ? { body: JSON.stringify(r.body) } : {}) });
        const txt = await gr.text(); let data; try { data = JSON.parse(txt); } catch { data = txt; }
        if (a.pre && L.looksPrivate(data)) { store.audit(c.sub, { app: c.app, origin: c.origin, kind: 'github', decision: 'blocked: private content needs your approval', method: r.method, path: r.path, hash: h, preapproved: true });
          return send(res, 403, { error: 'private content: ask the user with a normal approval' }); }
        store.audit(c.sub, { app: c.app, origin: c.origin, kind: 'github', decision: a.pre ? 'executed (pre-approved)' : 'executed', method: r.method, path: r.path, hash: h, status: gr.status, ...(a.pre ? { preapproved: true } : {}) });
        return send(res, 200, { status: gr.status, data });
      }
      // Layer 3b: site -> company server data. Opened as a popup by doublehub.send(dest, payload).
      if (u.pathname === '/send' && req.method === 'GET') {
        const app = cfg.apps[q.get('app')], origin = L.normOrigin(q.get('origin') || '');
        if (!L.originAllowed(app, origin)) return send(res, 403, 'Origin not allowed.', 'text/plain');
        let dest; try { dest = new URL(q.get('dest')); } catch { return send(res, 400, 'Bad destination.', 'text/plain'); }
        if (!app.send_to.includes(dest.origin)) return send(res, 403, 'Destination not allowed for this app.', 'text/plain');
        const raw = q.get('payload') || ''; if (raw.length > 8000) return send(res, 413, 'Payload too large.', 'text/plain');
        let payload; try { payload = JSON.parse(Buffer.from(raw, 'base64url').toString()); } catch { return send(res, 400, 'Bad payload.', 'text/plain'); }
        const sub = user(req); if (!sub || !store.getConsent(app.id, origin, sub)) return send(res, 403, 'Connect this site with doublehub first.', 'text/plain');
        const r = { kind: 'send', app: app.id, origin, sub, dest: dest.href, payload }, id = L.rand();
        store.putAction(id, { kind: 'send', h: L.reqHash(r), r, csrf: L.rand(), app: app.id, origin, sub });
        return send(res, 302, '', 'text/plain', { location: '/approve?id=' + encodeURIComponent(id) });
      }
      // The approval screen: only the signed-in doublehub user the action belongs to can decide.
      if (u.pathname === '/approve' && req.method === 'GET') {
        const act = store.getAction(q.get('id') || ''); if (!act) return send(res, 400, 'Expired. Nothing was sent.', 'text/plain');
        if (user(req) !== act.sub) return send(res, 403, 'This request belongs to another doublehub user. Nothing was sent.', 'text/plain');
        const app = cfg.apps[act.app], r = act.r, body = JSON.stringify(act.kind === 'send' ? r.payload : r.body, null, 2) || '(none)';
        const what = act.kind === 'send' ? `send this data to <b>${L.esc(r.dest)}</b>` : `call GitHub as you: <code>${L.esc(r.method)} https://api.github.com${L.esc(r.path)}</code>`;
        return send(res, 200, `<!doctype html><meta charset=utf-8><title>doublehub: approve action</title>
${PAGE}<body><main><p class=brand>doublehub</p>
<h2>Approve this one action?</h2>
<p>Site: <b>${L.esc(act.origin)}</b><br>App: <b>${L.esc(app.name || app.id)}</b></p>
<p>It wants to ${what}.</p>
${act.summary ? `<p>Site's description (unverified): <i>${L.esc(act.summary)}</i></p>` : ''}
<p>Exact data that will leave:</p><pre>${L.esc(body.slice(0, 4000))}${body.length > 4000 ? '\n... (' + body.length + ' bytes total)' : ''}</pre>
<p><small>Approval is single-use, for exactly this request, and expires in 1 minute. Request hash <code>${L.esc(act.h.slice(0, 16))}</code>.</small></p>
<form method=post action="/approve"><input type=hidden name=id value="${L.esc(q.get('id'))}"><input type=hidden name=csrf value="${L.esc(act.csrf)}">
${act.kind === 'github' && act.tpl ? `<p style="flex-basis:100%"><label><input type=checkbox name=preapprove value=1> Allow reads like this (<code>${L.esc(act.r.method + ' ' + act.tpl)}</code>) on this site for
<select name=ttl><option value=3600 selected>1 hour</option><option value=14400>4 hours</option><option value=86400>24 hours</option></select></label><br><small>Low-risk public read. Off unless you tick it. Revoke any time in Your doublehub. Writes, sends and private data always ask.</small></p>` : ''}
<button name=decision value=allow>Allow once</button> <button name=decision value=deny>Deny</button></form>
<p><a href="/audit">My activity log</a></p>`, 'text/html');
      }
      if (u.pathname === '/approve' && req.method === 'POST') {
        const b = parse(await readBody(req), req.headers['content-type']), act = store.getAction(b.id || '');
        if (!act || !L.safeEq(b.csrf || '', act.csrf) || user(req) !== act.sub) return send(res, 400, 'Expired. Nothing was sent.', 'text/plain');
        const base = { app: act.app, origin: act.origin, kind: act.kind, hash: act.h, ...(act.kind === 'send' ? { dest: act.r.dest } : { method: act.r.method, path: act.r.path }) };
        let msg;
        if (b.decision === 'allow') {
          if (act.kind === 'send') {
            store.takeAction(b.id);
            msg = { type: 'doublehub:receipt', id: b.id, receipt: L.signGrant({ typ: 'receipt', app: act.app, origin: act.origin, sub: act.sub, dest: act.r.dest, h: act.h }, cfg.secret, 120) };
          } else {
            if (act.approved) return send(res, 400, 'Already decided.', 'text/plain');
            act.approved = true;
            // Opt-in pre-approval, only from this human, CSRF-checked popup, and only if the server classifies the call low-risk.
            const tpl = L.lowRiskPattern(act.r.method, act.r.path, act.r.body);
            if (b.preapprove === '1' && tpl && tpl === act.tpl) {
              const ttl = Math.min(Math.max(parseInt(b.ttl, 10) || L.PREAPPROVE_DEFAULT_SEC, 60), L.PREAPPROVE_MAX_SEC);
              store.grantPre(act.app, act.origin, act.sub, act.r.method, tpl, ttl);
              store.audit(act.sub, { app: act.app, origin: act.origin, kind: 'preapproval', decision: 'granted for ' + Math.round(ttl / 60) + ' min', method: act.r.method, path: tpl });
            }
            msg = { type: 'doublehub:approval', id: b.id, approval: L.signGrant({ typ: 'approval', aid: b.id, app: act.app, origin: act.origin, sub: act.sub, h: act.h }, cfg.secret, 60) };
          }
          store.audit(act.sub, { ...base, decision: 'approved' });
        } else { store.takeAction(b.id); store.audit(act.sub, { ...base, decision: 'denied' }); msg = { type: 'doublehub:denied', id: b.id }; }
        return send(res, 200, `<!doctype html><meta charset=utf-8>${PAGE}<body><main><p class=brand>doublehub</p><p>${msg.type === 'doublehub:denied' ? 'Denied. Nothing was sent.' : 'Approved once.'} You can close this window.</p></main><script>
if (window.opener) window.opener.postMessage(${JSON.stringify(msg).replace(/</g, '\\u003c')}, ${JSON.stringify(act.origin).replace(/</g, '\\u003c')}); window.close();</script>`, 'text/html');
      }
      // Company server verifies a doublehub.send receipt (single-use). Reject any data without a valid one.
      if (u.pathname === '/receipt/verify' && req.method === 'POST') {
        const b = parse(await readBody(req), 'json'), app = appAuth(req, b.app); if (!app) return send(res, 401, { error: 'unauthorized' });
        let c; try { c = L.verifyGrant(b.receipt, cfg.secret, { app: app.id }); } catch (e) { return send(res, 403, { valid: false, error: e.message }); }
        const h = L.reqHash({ kind: 'send', app: c.app, origin: c.origin, sub: c.sub, dest: b.dest, payload: b.payload });
        if (c.typ !== 'receipt' || c.dest !== b.dest || !L.safeEq(c.h, h)) return send(res, 403, { valid: false, error: 'payload does not match receipt' });
        if (!store.useOnce(c.jti)) return send(res, 403, { valid: false, error: 'receipt already used' });
        return send(res, 200, { valid: true, sub: c.sub, origin: c.origin });
      }
      // The user's own log of every approved/denied/blocked action.
      if (u.pathname === '/audit' && req.method === 'GET') {
        const sub = user(req); if (!sub) return send(res, 403, 'Sign in with doublehub first.', 'text/plain');
        const rows = store.auditFor(sub).reverse();
        if ((req.headers.accept || '').includes('application/json')) return send(res, 200, { entries: rows });
        return send(res, 200, `<!doctype html><meta charset=utf-8><title>doublehub activity</title>${PAGE}<body><main class=wide><p class=brand>doublehub</p>
<h2>Everything that left (or tried to leave) through doublehub</h2><div class=tbl><table><tr><th>When</th><th>Decision</th><th>Site</th><th>App</th><th>What</th></tr>
${rows.map(e => `<tr><td>${L.esc(e.at)}</td><td>${L.esc(e.decision)}</td><td>${L.esc(e.origin)}</td><td>${L.esc(e.app)}</td><td>${L.esc(e.kind === 'send' ? 'send to ' + e.dest : e.kind === 'preapproval' ? 'pre-approve ' + e.method + ' ' + e.path : e.method + ' ' + e.path)}</td></tr>`).join('')}</table></div></main>`, 'text/html');
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
