'use strict';
// Pure helpers for the doublehub two-layer auth server. Zero dependencies.
const crypto = require('crypto');
const b64u = b => Buffer.from(b).toString('base64url');

function rand(n = 32) { return crypto.randomBytes(n).toString('base64url'); }

// PKCE (RFC 7636, S256)
function pkce() { const verifier = rand(32); return { verifier, challenge: challengeFor(verifier) }; }
function challengeFor(v) { return b64u(crypto.createHash('sha256').update(v).digest()); }

// Normalise an origin; returns null if not a clean http(s) origin.
function normOrigin(o) {
  try { const u = new URL(o); if (!/^https?:$/.test(u.protocol)) return null;
    if (u.origin !== o.replace(/\/$/, '')) return null; return u.origin; } catch { return null; }
}
// Exact-match allowlist. No wildcards, no prefix matching.
function originAllowed(app, origin) {
  const o = normOrigin(origin || ''); return !!(app && o && (app.origins || []).includes(o));
}

function safeEq(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

// Short-lived HMAC-SHA256 signed grant: base64url(json).base64url(sig)
function signGrant(claims, secret, ttlSec = 300, now = Date.now()) {
  if (!secret || secret.length < 32) throw new Error('DH_SECRET must be at least 32 chars');
  const body = b64u(JSON.stringify({ ...claims, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + ttlSec, jti: rand(12) }));
  return body + '.' + b64u(crypto.createHmac('sha256', secret).update(body).digest());
}
function verifyGrant(token, secret, { origin, app, now = Date.now(), isRevoked = () => false } = {}) {
  const [body, sig, extra] = String(token || '').split('.');
  if (!body || !sig || extra !== undefined) throw new Error('malformed');
  if (!safeEq(sig, b64u(crypto.createHmac('sha256', secret).update(body).digest()))) throw new Error('bad signature');
  const c = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (Math.floor(now / 1000) >= c.exp) throw new Error('expired');
  if (origin !== undefined && c.origin !== origin) throw new Error('origin mismatch');
  if (app !== undefined && c.app !== app) throw new Error('app mismatch');
  if (isRevoked(c)) throw new Error('revoked');
  return c;
}

// In-memory stores (swap for Redis/DB in production).
function createStore() {
  const pending = new Map(), consents = new Map(), revokedJti = new Set();
  return {
    putState(state, v, ttlMs = 600000, now = Date.now()) { pending.set('s:' + state, { ...v, exp: now + ttlMs }); },
    // single-use: always deleted on read
    takeState(state, now = Date.now()) { const k = 's:' + state, v = pending.get(k); pending.delete(k); return v && v.exp > now ? v : null; },
    putPending(id, v) { pending.set('c:' + id, { ...v, exp: Date.now() + 600000 }); },
    getPending(id) { const v = pending.get('c:' + id); return v && v.exp > Date.now() ? v : null; },
    dropPending(id) { pending.delete('c:' + id); },
    consentKey: (app, origin, sub) => app + '|' + origin + '|' + sub,
    grantConsent(app, origin, sub, data) { consents.set(this.consentKey(app, origin, sub), data); },
    getConsent(app, origin, sub) { return consents.get(this.consentKey(app, origin, sub)); },
    revoke(app, origin, sub, jti) { consents.delete(this.consentKey(app, origin, sub)); if (jti) revokedJti.add(jti); },
    isRevoked(c) { return revokedJti.has(c.jti) || !consents.has(this.consentKey(c.app, c.origin, c.sub)); },
  };
}

// Config from env: DH_APPS='{"acme":{"client_id":"Iv1..","origins":["https://acme.dev"],"scopes":"read:user"}}'
// Secrets: GITHUB_CLIENT_SECRET_ACME, DH_APP_KEY_ACME (company backend key for /token). Never in the repo.
function loadConfig(env = process.env) {
  const apps = JSON.parse(env.DH_APPS || '{}');
  for (const [id, a] of Object.entries(apps)) {
    const k = id.toUpperCase().replace(/[^A-Z0-9]/g, '_');
    a.id = id; a.client_secret = env['GITHUB_CLIENT_SECRET_' + k]; a.app_key = env['DH_APP_KEY_' + k];
    a.origins = (a.origins || []).map(normOrigin).filter(Boolean);
  }
  return { apps, secret: env.DH_SECRET, base: (env.DH_BASE_URL || 'http://localhost:8787').replace(/\/$/, ''), port: +env.PORT || 8787 };
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

module.exports = { rand, pkce, challengeFor, normOrigin, originAllowed, signGrant, verifyGrant, createStore, loadConfig, safeEq, esc };
