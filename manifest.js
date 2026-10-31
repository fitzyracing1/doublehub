// Shared manifest builder (browser + node). Fields per GitHub App manifest docs.
(function (root) {
  const PERMS = {
    metadata: ['read', 'See basic repo info (names, visibility) — always required'],
    contents: ['read', 'Read code and files'],
    checks: ['write', 'Post check results (lit/dark) on commits'],
    statuses: ['write', 'Set commit status lights'],
    pull_requests: ['write', 'Comment on and read pull requests'],
    issues: ['write', 'Open and comment on issues'],
    actions: ['read', 'Read CI workflow runs'],
    deployments: ['read', 'Read deployments'],
    members: ['read', 'See org members (org-level)'],
    email_addresses: ['read', 'See the user\'s email (user-level)']
  };
  const EVENTS = ['push', 'pull_request', 'check_run', 'check_suite', 'workflow_run', 'issues', 'issue_comment', 'installation_target', 'deployment_status', 'release'];
  function slugify(n) { return String(n).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''); }
  function build(o) {
    if (!o.name) throw new Error('name is required');
    if (!/^https?:\/\//.test(o.url || '')) throw new Error('url must start with http(s)://');
    if (o.name.length > 34) throw new Error('name must be 34 characters or fewer');
    const perms = { metadata: 'read' };
    for (const [k, v] of Object.entries(o.permissions || {})) if (PERMS[k] && v) perms[k] = v;
    const m = { name: o.name, url: o.url, public: o.public !== false, default_permissions: perms };
    if (o.description) m.description = o.description;
    if (o.webhook) {
      if (!/^https:\/\//.test(o.webhook)) throw new Error('webhook must be https://');
      m.hook_attributes = { url: o.webhook, active: true };
      m.default_events = (o.events || []).filter(e => EVENTS.includes(e));
    } else m.default_events = [];
    m.redirect_url = o.redirect || 'https://fitzyracing1.github.io/doublehub/callback.html';
    if (o.callbacks && o.callbacks.length) m.callback_urls = o.callbacks;
    if (o.setup) m.setup_url = o.setup;
    return m;
  }
  function createUrl(org) { return org ? `https://github.com/organizations/${encodeURIComponent(org)}/settings/apps/new` : 'https://github.com/settings/apps/new'; }
  function installUrl(name) { return `https://github.com/apps/${slugify(name)}/installations/new`; }
  function badge(name) { return `[![Install on GitHub](https://img.shields.io/badge/Install%20on-GitHub-181717?logo=github)](${installUrl(name)})`; }
  const api = { PERMS, EVENTS, build, createUrl, installUrl, badge, slugify };
  if (typeof module !== 'undefined') module.exports = api; else root.GHAppManifest = api;
})(this);
