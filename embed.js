/* doublehub embed widget.
 * <script src="https://fitzyracing1.github.io/doublehub/embed.js" data-server="https://YOUR-DOUBLEHUB-SERVER" data-app="acme"></script>
 * Fires window event 'doublehub:grant' with {detail:{grant}}. Send the grant to YOUR backend, which redeems it at /token for a session.
 * Every outbound action then needs a user approval: doublehub.approve(actionId) for GitHub calls, doublehub.send(dest, payload) for data to your server.
 * No demo fallback: missing, placeholder, or example.com data-server shows "Sign-in not configured".
 */
(function (root) {
  'use strict';
  // Only accept messages from the exact doublehub server origin, from the popup we opened, of a known type.
  function acceptMessage(ev, serverOrigin, popup) {
    if (!ev || ev.origin !== serverOrigin) return null;
    if (popup && ev.source !== popup) return null;
    var d = ev.data;
    if (!d || typeof d !== 'object') return null;
    if (d.type === 'doublehub:grant' && typeof d.grant === 'string' && /^[\w-]+\.[\w-]+$/.test(d.grant)) return d;
    var tok = function (t) { return typeof t === 'string' && /^[\w-]+\.[\w-]+$/.test(t); };
    if (d.type === 'doublehub:approval' && tok(d.approval)) return d;
    if (d.type === 'doublehub:receipt' && tok(d.receipt)) return d;
    if (d.type === 'doublehub:denied') return d;
    return null;
  }
  function serverOriginOf(s) { var u = new URL(s); if (u.protocol !== 'https:' && u.hostname !== 'localhost') throw new Error('doublehub server must be https'); return u.origin; }
  // Real server URL only. Placeholders (docs) and example.com are not a demo backend.
  function isConfigured(server, app) {
    if (!app || typeof app !== 'string' || !String(app).trim()) return false;
    if (!server || typeof server !== 'string') return false;
    var s = String(server).trim();
    if (!s || /YOUR[-_]?DOUBLEHUB[-_]?SERVER/i.test(s)) return false;
    try {
      var host = (new URL(s).hostname || '').toLowerCase();
      if (host === 'example.com' || /\.example\.(com|org|net)$/.test(host) || host === 'example.org' || host === 'example.net') return false;
      serverOriginOf(s);
      return true;
    } catch (e) { return false; }
  }
  var NOT_CONFIGURED = 'Sign-in not configured';
  function widgetState(ds) {
    ds = ds || {};
    if (isConfigured(ds.server, ds.app)) return { ready: true, disabled: false, label: ds.label || 'Sign in with GitHub' };
    return { ready: false, disabled: true, label: NOT_CONFIGURED };
  }
  function authorizeUrl(server, app, origin) {
    return serverOriginOf(server) + '/authorize?app=' + encodeURIComponent(app) + '&origin=' + encodeURIComponent(origin);
  }
  function start(opts) {
    if (!isConfigured(opts && opts.server, opts && opts.app)) return Promise.reject(new Error('doublehub server is not configured'));
    var so = serverOriginOf(opts.server);
    var popup = root.open(authorizeUrl(opts.server, opts.app, root.location.origin), 'doublehub', 'width=520,height=680');
    return new Promise(function (ok, no) {
      function onMsg(ev) {
        var d = acceptMessage(ev, so, popup); if (!d) return;
        root.removeEventListener('message', onMsg);
        d.type === 'doublehub:grant' ? ok(d.grant) : no(new Error('denied'));
      }
      root.addEventListener('message', onMsg);
    });
  }
  function popupFor(so, url, want) {
    var popup = root.open(url, 'doublehub-approve', 'width=560,height=720');
    return new Promise(function (ok, no) {
      function onMsg(ev) {
        var d = acceptMessage(ev, so, popup); if (!d) return;
        root.removeEventListener('message', onMsg);
        d.type === want ? ok(d) : no(new Error('denied: nothing was sent'));
      }
      root.addEventListener('message', onMsg);
    });
  }
  // Layer 3a: user approves ONE GitHub action the company queued via POST /action. Resolves to the single-use approval.
  function approve(opts) {
    var so = serverOriginOf(opts.server);
    return popupFor(so, so + '/approve?id=' + encodeURIComponent(opts.actionId), 'doublehub:approval').then(function (d) { return d.approval; });
  }
  function b64u(str) { return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function sendUrl(server, app, origin, dest, payload) {
    return serverOriginOf(server) + '/send?app=' + encodeURIComponent(app) + '&origin=' + encodeURIComponent(origin) +
      '&dest=' + encodeURIComponent(dest) + '&payload=' + b64u(JSON.stringify(payload));
  }
  // Layer 3b: nothing goes to the company server until the user approves this exact payload+destination.
  // POSTs {payload, receipt} to dest; the company MUST verify the receipt at /receipt/verify and reject data without one.
  function send(opts, dest, payload) {
    var so = serverOriginOf(opts.server);
    return popupFor(so, sendUrl(opts.server, opts.app, root.location.origin, dest, payload), 'doublehub:receipt').then(function (d) {
      return root.fetch(dest, { method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include',
        body: JSON.stringify({ payload: payload, receipt: d.receipt, dest: dest }) }).then(function (r) { return { receipt: d.receipt, response: r }; });
    });
  }
  var api = { acceptMessage: acceptMessage, authorizeUrl: authorizeUrl, sendUrl: sendUrl, start: start, approve: approve, send: send, isConfigured: isConfigured, widgetState: widgetState };
  if (typeof module !== 'undefined') { module.exports = api; return; }
  root.doublehub = api;
  var s = document.currentScript;
  if (s && s.dataset.server && s.dataset.app && isConfigured(s.dataset.server, s.dataset.app)) { var o = { server: s.dataset.server, app: s.dataset.app };
    api.send = function (dest, payload) { return send(o, dest, payload); };
    api.approve = function (actionId) { return approve({ server: o.server, actionId: actionId }); }; }
  if (s && (s.dataset.server || s.dataset.app || s.dataset.label)) {
    var st = widgetState(s.dataset);
    var b = document.createElement('button'); b.type = 'button'; b.textContent = st.label;
    if (st.disabled) { b.disabled = true; b.setAttribute('aria-disabled', 'true');
      b.title = 'Set data-server to your doublehub HTTPS URL and data-app to your app id.'; }
    else b.onclick = function () { start({ server: s.dataset.server, app: s.dataset.app }).then(function (g) {
      root.dispatchEvent(new CustomEvent('doublehub:grant', { detail: { grant: g } })); b.textContent = 'Connected'; },
      function () { b.textContent = 'Not connected'; }); };
    s.parentNode.insertBefore(b, s.nextSibling);
  }
})(typeof window !== 'undefined' ? window : globalThis);
