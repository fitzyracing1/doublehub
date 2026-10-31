# doublehub two-layer auth

## The idea
A company drops the doublehub widget on its own page. A visitor has to pass **two separate locks** before the company gets their GitHub identity/token:

1. **Layer 1 – GitHub.** The visitor signs in with GitHub and authorizes the company's GitHub App (OAuth user authorization, with `state` + PKCE).
2. **Layer 2 – doublehub.** The visitor sees a doublehub consent page that names the exact site (origin) asking, the app, and the access. They click Allow for *that site only*. Consent is stored per (app, origin, user) and can be revoked.

Only then does doublehub hand the page a short-lived signed **grant**, which the company's backend redeems (with its own app key) for the user's token.

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
company backend --> POST /token {app, origin, grant} + Bearer app key --> GitHub token
/revoke {grant} --> consent deleted, grant jti blacklisted
```

## Threat model – why two layers help
- **Stolen embed on another site.** If evil.dev copies the script tag, `/authorize` refuses because evil.dev isn't on the app's allowlist. Even if it were somehow reached, consent and grants are bound to an origin; the popup only posts to the bound origin, and `/token` rejects a grant presented for a different origin.
- **Consent can't be reused across sites.** Allowing acme.dev says nothing about other.dev — each origin needs its own Layer 2.
- **Code interception / CSRF on login.** `state` is random, server-stored, single-use, expiring. PKCE (S256) means a stolen `code` is useless without the verifier, which never leaves the server.
- **Grant theft.** Grants live 5 minutes, are signed (tamper = rejected), origin-bound, and redeeming one also needs the company's secret app key, so a leaked grant alone yields nothing. Revocation is checked on every redeem.
- **Clickjacking the consent page.** `X-Frame-Options: DENY` + `frame-ancestors 'none'`; consent POST requires a CSRF token.
- **GitHub token in the browser.** Never. It stays on the server until the company backend redeems it.

## Why a backend is needed
GitHub's OAuth code exchange requires the `client_secret`, which can't live in a static page. So `server/` is a tiny zero-dependency Node server (`node server/server.js`) that the **company self-hosts** or **doublehub hosts**. The static site (GitHub Pages) still serves the manifest builder and `embed.js`.

## Config (env only – no secrets in the repo)
| var | meaning |
|---|---|
| `DH_SECRET` | 32+ char HMAC key for grants |
| `DH_BASE_URL` | public https URL of the server (GitHub callback = `$DH_BASE_URL/callback`) |
| `DH_APPS` | JSON: `{"acme":{"client_id":"Iv1...","name":"Acme","origins":["https://acme.dev"],"scopes":""}}` |
| `GITHUB_CLIENT_SECRET_ACME` | the GitHub App's client secret |
| `DH_APP_KEY_ACME` | key the company backend uses for `/token` |
| `PORT` | default 8787 |

## Limits / next steps
- Stores are in memory: restart = consents lost; multiple instances need Redis/DB.
- No rate limiting yet; put it behind a proxy that does.
- Users revoke with a grant they hold; a "manage my sites" page (signed in via GitHub) would be a nice add.
