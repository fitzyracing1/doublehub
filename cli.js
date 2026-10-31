#!/usr/bin/env node
// Usage: node cli.js --name "Acme Bot" --url https://acme.dev [--webhook https://acme.dev/hook]
//   [--perm contents=read --perm checks=write] [--event push] [--org acme] [--private] [--description ".."]
const M = require('./manifest.js');
const a = process.argv.slice(2), o = { permissions: {}, events: [] }; let org;
for (let i = 0; i < a.length; i++) {
  const f = a[i], v = a[i + 1];
  if (f === '--private') { o.public = false; continue; }
  if (f === '-h' || f === '--help') { console.log('flags: --name --url --webhook --description --perm k=v --event e --org o --private\nperms: ' + Object.keys(M.PERMS).join(',') + '\nevents: ' + M.EVENTS.join(',')); process.exit(0); }
  i++;
  if (f === '--name') o.name = v; else if (f === '--url') o.url = v; else if (f === '--webhook') o.webhook = v;
  else if (f === '--description') o.description = v; else if (f === '--org') org = v;
  else if (f === '--perm') { const [k, p] = v.split('='); o.permissions[k] = p; }
  else if (f === '--event') o.events.push(v);
  else { console.error('unknown flag ' + f); process.exit(2); }
}
try {
  const m = M.build(o);
  console.log(JSON.stringify(m, null, 2));
  console.error(`\nCreate at: ${M.createUrl(org)}  (POST form field "manifest")\nInstall link (after creation): ${M.installUrl(o.name)}\nBadge: ${M.badge(o.name)}`);
} catch (e) { console.error('error: ' + e.message); process.exit(1); }
