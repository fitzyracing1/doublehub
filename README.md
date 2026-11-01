# doublehub

**Turn your service into a GitHub App install link in 2 minutes.**

For companies and orgs that want GitHub users to connect to their service. Fill in one form, and you get your own GitHub App, an install link and an "Install on GitHub" badge. No backend needed.

**[Make your GitHub App →](https://fitzyracing1.github.io/doublehub/#maker)**

## How it works

1. **Describe your service.** Enter its name, URL, optional webhook URL, and only the permissions/events you need (just `metadata: read` by default). Pick a personal or org owner.
2. **GitHub creates the app.** Click **Create my GitHub App**. The [manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest) is POSTed to GitHub, which creates the app on your own account or org.
3. **Share the install link.** Use `https://github.com/apps/<slug>/installations/new` or the copyable "Install on GitHub" Markdown badge.

**Security:** visitors sign in with GitHub, then approve doublehub separately on each site (revocable any time), and every call that leaves needs their explicit OK.

After creation GitHub redirects with a `code`; exchange it within 1 hour via `POST /app-manifests/{code}/conversions` to get the app's ID, private key and webhook secret (needs your own `redirect_url` handler, or set them later in app settings).

## CLI (Node, zero dependencies)

```sh
node cli.js --name "Acme Lights" --url https://acme.dev \
  --webhook https://acme.dev/hook --perm checks=write --event check_suite --org acme
```
Prints manifest JSON to stdout; create URL, install link and badge to stderr. `node cli.js --help` lists permissions and events.

## Test
`node test.js`

## Two-layer auth widget (embed)
Put this on your page. Visitors authorize GitHub (layer 1), then approve doublehub for your site (layer 2):

```html
<script src="https://fitzyracing1.github.io/doublehub/embed.js"
        data-server="https://YOUR-DOUBLEHUB-SERVER" data-app="acme"></script>
<script>
addEventListener('doublehub:grant', e => fetch('/api/doublehub', {method:'POST', body: e.detail.grant}));
</script>
```
Your backend redeems the grant at `POST /token` with its app key and gets a doublehub **session** (never the GitHub token).

### Layer 3: approve everything that leaves
Every outbound action needs the user's explicit, single-use approval:
```js
// GitHub call: your backend POSTs /action {app, origin, session, method, path, body, summary} -> {action_id}
const approval = await doublehub.approve(action_id);   // popup shows site, app, exact request
// your backend POSTs /action/execute {same request, action_id, approval} -> doublehub runs it

// Data to your own server (dest must be in the app's send_to list):
await doublehub.send('https://api.acme.dev/ingest', { email });  // popup, then POST {payload, receipt, dest}
```
Your server **must reject data without a receipt** that `POST /receipt/verify` accepts. Users see every approved/denied action at `GET /audit`. No "always allow" by default.

**Optional low-risk pre-approval (off by default).** To cut consent fatigue, the approval popup for a *low-risk* call (a `GET` with no body or query on an allowlisted public-metadata endpoint, e.g. `/repos/:owner/:repo`, `/users/:user`) offers a checkbox: "Allow reads like this on octo/hello for 1 hour" (up to 24h). The grant is per user, per site, per method + path template, and only for the one owner/repo (or user/org) you approved: a grant for one repo never covers another repo or owner (enforced server-side). It shows in "Your doublehub" with Revoke, and is dropped when the site is revoked. While it lasts, `POST /action` returns `200 {preapproved: true, approval}` instead of `202`, so no popup; the call is still logged as `pre-approved`. Everything else is risky and always prompts, enforced server-side: writes, `doublehub.send`, `/user`, secrets, contents, permissions, unknown endpoints, and any pre-approved response that turns out to be private (blocked). Grants can only be created by the signed-in human in the popup, never by the site or an agent. Details in DESIGN.md. Run the server with `node server/server.js` (config via env, see DESIGN.md). Tests: `npm test`.

## The doublehub site is a doublehub app

https://fitzyracing1.github.io/doublehub/ signs you in with doublehub itself, as app `doublehub`:
1. Sign in with GitHub (layer 1).
2. Approve doublehub for this site (layer 2).
3. Dashboard: your GitHub identity (a `GET /user` call you approve each time), your doublehub activity log, and your connected sites with Revoke. Every outbound call goes through per-action approval.

The App maker works for everyone, signed in or not.

The site's backend is built into the server (`server/firstparty.js`, `/app/*` routes) and only runs when `DH_FIRST_PARTY=1`.

Steps to turn it on (the owner of the Railway project does this):
1. Create a GitHub OAuth App at https://github.com/settings/applications/new. Homepage: `https://fitzyracing1.github.io/doublehub/`. Authorization callback URL: `https://doublehub-production.up.railway.app/callback`. Copy the Client ID and generate a client secret.
2. Set these Railway variables on service `doublehub`:
   - `DH_APPS={"doublehub":{"name":"doublehub","client_id":"CLIENT_ID","origins":["https://fitzyracing1.github.io"]}}`
   - `GITHUB_CLIENT_SECRET_DOUBLEHUB=<client secret>`
   - `DH_APP_KEY_DOUBLEHUB=<32+ random chars, e.g. openssl rand -hex 32>`
   - `DH_FIRST_PARTY=1`
3. Redeploy, then open https://fitzyracing1.github.io/doublehub/.

## License

Apache License 2.0. See [LICENSE](LICENSE). Copyright 2026 Joshua Almeida.
