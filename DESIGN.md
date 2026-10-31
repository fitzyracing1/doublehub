# doublehub three-layer auth

## The idea
A company drops the doublehub widget on its own page. A visitor has to pass **two separate locks** before the company gets their GitHub identity/token:

1. **Layer 1 – GitHub.** The visitor signs in with GitHub and authorizes the company's GitHub App (OAuth user authorization, with `state` + PKCE).
2. **Layer 2 – doublehub.** The visitor sees a doublehub consent page that names the exact site (origin) asking, the app, and the access. They click Allow for *that site only*. Consent is stored per (app, origin, user) and can be revoked.

3. **Layer 3 – every action.** *On each site and app, doublehub requires an authorization for everything that leaves it.* The company never receives the GitHub token. Every GitHub API call it wants to make, and every piece of data the page sends to the company's server, needs the user's explicit, single-use approval of that exact request.

After layers 1+2 doublehub hands the page a short-lived signed **grant**; the company's backend redeems it (once, with its own app key) for a doublehub **session**, not a token.

## Flow
```
company page (embed.js) --popup--> doublehub server /authorize?app&origin
   origin checked against the app's allowlist (exact match)
   state + PKCE verifier stored server-side --> github.com/login/oauth/authorize
GitHub --> /callback?code&state  (state single-use, 10 min; code exchanged with client_secret + code_verifier)
       --> /consent  (Layer 2 page: "https://acme.dev wants ... Allow / Deny", CSRF token)
Allow  --> consent saved; grant = HMAC-SHA256({app, origin, sub, login, exp=5min, jti})
       --> popup postMessage(grant, "https://acme.dev")  // exact targetOrigin
embed.js accepts only messages from the server origin, from its own popup, with a known shape
company backend --> POST /token {app, origin, grant} + Bearer app key --> session (1h, HMAC, origin+app+user bound; grant single-use)
/revoke {grant} --> consent deleted, grant jti blacklisted
```

## Layer 3: per-action outbound approval

### A. Company calls GitHub as the user
```
company backend --> POST /action {app, origin, session, method, path, body, summary} + app key
   server builds R = {app, origin, sub, method, path, body}; H = sha256(canonical JSON R)
   stores pending action (2 min) --> 202 {action_id, approve_url, request_hash}
page: doublehub.approve(action_id) --> popup /approve?id
   only the doublehub user who owns the action (HttpOnly dh_u cookie set at consent) can view/decide
   screen shows site, app, "POST https://api.github.com/<path>", exact body, company's (unverified) summary
Allow once --> approval = HMAC({typ:approval, aid, app, origin, sub, h:H, exp=60s, jti}) postMessage'd to the bound origin only
Deny       --> action deleted, audited; nothing is ever sent
company backend --> POST /action/execute {same request + action_id + approval} + app key
   recompute H from the submitted request; must equal approval.h AND stored action.h
   approval jti single-use; action deleted; consent still present
   server calls GitHub with the token it holds, returns {status, data}
```
Methods: GET/POST/PUT/PATCH/DELETE. Paths must be relative API paths (no scheme, `//`, or `..`), so the token only ever goes to `https://api.github.com`.

### B. Page sends data to the company's server
```
doublehub.send(dest, payload) --> popup /send?app&origin&dest&payload(base64url JSON, <=8KB)
   origin on the app allowlist, dest origin on the app's send_to allowlist, user signed in with consent for this site
   --> /approve: shows site, app, destination URL and exact payload
Allow once --> receipt = HMAC({typ:receipt, app, origin, sub, dest, h:sha256(R), exp=120s, jti}) to the bound origin
embed.js POSTs {payload, receipt, dest} to dest
company server --> POST /receipt/verify {app, receipt, payload, dest} + app key --> {valid, sub, origin}  (single-use)
```
**Companies must reject any incoming data that does not carry a receipt that `/receipt/verify` accepts.** doublehub can't physically stop a page's own JavaScript from calling `fetch`; the guarantee is that the company's server only *accepts* user-approved data, and the receipt proves which user approved what. A page that skips doublehub produces unsigned data, which a compliant company drops.

### Binding / replay
Approvals and receipts are bound to origin + app + user + exact request hash, expire in 60/120s, and are single-use (jti). Changing one byte of method/path/body/payload/dest after approval → hash mismatch → 403 and an audit entry (`blocked: request changed after approval`). Tokens are typed (`grant`/`session`/`approval`/`receipt`/`user`) so none can stand in for another.

### "Always allow"
Not included. Every action needs a fresh click. If ever added it must be off by default, scoped to one exact action type for one site, and revocable from the audit page.

### Audit log
Every approved / denied / executed / blocked action is recorded per user (in memory, like consents). `GET /audit` (signed in via the `dh_u` cookie) shows it as a page; `Accept: application/json` returns JSON.

## Threat model – why the layers help
- **Stolen embed on another site.** If evil.dev copies the script tag, `/authorize` refuses because evil.dev isn't on the app's allowlist. Even if it were somehow reached, consent and grants are bound to an origin; the popup only posts to the bound origin, and `/token` rejects a grant presented for a different origin.
- **Consent can't be reused across sites.** Allowing acme.dev says nothing about other.dev — each origin needs its own Layer 2.
- **Code interception / CSRF on login.** `state` is random, server-stored, single-use, expiring. PKCE (S256) means a stolen `code` is useless without the verifier, which never leaves the server.
- **Grant theft.** Grants live 5 minutes, are signed (tamper = rejected), origin-bound, and redeeming one also needs the company's secret app key, so a leaked grant alone yields nothing. Revocation is checked on every redeem.
- **Clickjacking the consent page.** `X-Frame-Options: DENY` + `frame-ancestors 'none'`; consent POST requires a CSRF token.
- **GitHub token in the browser or at the company.** Never. It stays on the doublehub server; the company only gets per-action results.
- **Company acts silently as the user.** Impossible through doublehub: no approval, no request. Tampering after approval breaks the hash; replay hits the used-jti set.

## Why a backend is needed
GitHub's OAuth code exchange requires the `client_secret`, which can't live in a static page. So `server/` is a tiny zero-dependency Node server (`node server/server.js`) that the **company self-hosts** or **doublehub hosts**. The static site (GitHub Pages) still serves the manifest builder and `embed.js`.

## Config (env only – no secrets in the repo)
| var | meaning |
|---|---|
| `DH_SECRET` | 32+ char HMAC key for grants |
| `DH_BASE_URL` | public https URL of the server (GitHub callback = `$DH_BASE_URL/callback`) |
| `DH_APPS` | JSON: `{"acme":{"client_id":"Iv1...","name":"Acme","origins":["https://acme.dev"],"scopes":"","send_to":["https://api.acme.dev"]}}` (`send_to` = company servers `doublehub.send` may target) |
| `GITHUB_CLIENT_SECRET_ACME` | the GitHub App's client secret |
| `DH_APP_KEY_ACME` | key the company backend uses for `/token`, `/action`, `/action/execute`, `/receipt/verify` |
| `PORT` | default 8787 |

## Limits / next steps
- Stores are in memory: restart = consents, pending actions, used-jti set and audit log lost; multiple instances need Redis/DB.
- Breaking change: `/token` no longer returns `access_token`; companies must move to `/action`.
- The approval screen shows the exact request; for large bodies it truncates the display at 4KB (the hash still covers everything). The company's `summary` is shown as unverified text.
- `doublehub.send` puts the payload in the popup URL (≤8KB), so it can appear in server access logs; a postMessage handoff would avoid that.
- The user cookie lives 8h; after that the user must reconnect to approve. Popup blockers require calling `approve`/`send` from a click.
- No rate limiting yet; put it behind a proxy that does.
- Users revoke with a grant they hold; a "manage my sites" page (signed in via GitHub) would be a nice add.
