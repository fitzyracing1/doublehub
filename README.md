# doublehub

A static page (`index.html`, works on GitHub Pages, no backend) that lets any company turn its service into a public GitHub App using GitHub's [manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).

1. Enter service name, URL, optional webhook URL, pick permissions/events (least privilege: only `metadata: read` by default), choose personal or org owner.
2. Click **Create my GitHub App** — the manifest is POSTed to `https://github.com/settings/apps/new` or `https://github.com/organizations/<org>/settings/apps/new`. You create the app on your own account.
3. Share the install link `https://github.com/apps/<slug>/installations/new` and the copyable "Install on GitHub" Markdown badge.

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
Your backend redeems the grant at `POST /token` with its app key. Run the server with `node server/server.js` (config via env, see DESIGN.md). Tests: `node test.js && node server/test.js`.
