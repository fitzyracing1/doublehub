/* doublehub embed widget.
 * <script src="https://fitzyracing1.github.io/doublehub/embed.js" data-server="https://auth.example.com" data-app="acme"></script>
 * Fires window event 'doublehub:grant' with {detail:{grant}}. Send the grant to YOUR backend, which redeems it at /token.
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
    if (d.type === 'doublehub:denied') return d;
    return null;
  }
  function serverOriginOf(s) { var u = new URL(s); if (u.protocol !== 'https:' && u.hostname !== 'localhost') throw new Error('doublehub server must be https'); return u.origin; }
  function authorizeUrl(server, app, origin) {
    return serverOriginOf(server) + '/authorize?app=' + encodeURIComponent(app) + '&origin=' + encodeURIComponent(origin);
  }
  function start(opts) {
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
  var api = { acceptMessage: acceptMessage, authorizeUrl: authorizeUrl, start: start };
  if (typeof module !== 'undefined') { module.exports = api; return; }
  root.doublehub = api;
  var s = document.currentScript;
  if (s && s.dataset.server && s.dataset.app) {
    var b = document.createElement('button'); b.type = 'button'; b.textContent = s.dataset.label || 'Connect with GitHub (doublehub)';
    b.onclick = function () { start({ server: s.dataset.server, app: s.dataset.app }).then(function (g) {
      root.dispatchEvent(new CustomEvent('doublehub:grant', { detail: { grant: g } })); b.textContent = 'Connected'; },
      function () { b.textContent = 'Not connected'; }); };
    s.parentNode.insertBefore(b, s.nextSibling);
  }
})(typeof window !== 'undefined' ? window : globalThis);
