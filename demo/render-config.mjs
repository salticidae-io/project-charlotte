import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [templatePath, outputPath, statePath, worker, phpCgi, acmeEnabled, upstreamPort] = process.argv.slice(2);
if (!templatePath || !outputPath || !statePath || !worker || !upstreamPort) {
  throw new Error('usage: render-config.mjs TEMPLATE OUTPUT STATE WORKER [PHP_CGI] ACME_ENABLED UPSTREAM_PORT');
}

const quote = (value) => JSON.stringify(value);
const state = path.resolve(statePath);
const roots = {
  '@@FALLBACK_ROOT@@': quote(path.join(state, 'sites/fallback')),
  '@@STATIC_ROOT@@': quote(path.join(state, 'sites/static')),
  '@@CGI_ROOT@@': quote(path.join(state, 'sites/cgi')),
  '@@WORKER@@': quote(worker),
  '@@ACME_ENABLED@@': acmeEnabled === '1' ? 'true' : 'false',
  '@@UPSTREAM_PORT@@': upstreamPort,
};

let template = await readFile(templatePath, 'utf8');
for (const [token, replacement] of Object.entries(roots)) {
  template = template.replaceAll(token, replacement);
}
const phpVhost = phpCgi
  ? `  - server_names: [php.charlotte.test]\n    root: ${quote(path.join(state, 'sites/php'))}\n    user: ${quote(worker)}\n    fastcgi_app:\n      - extension: php\n        command: [${quote(phpCgi)}]\n    listing: false`
  : '  # PHP FastCGI scene is unavailable: php-cgi was not found.';
template = template.replace('@@PHP_VHOST@@', phpVhost);

if (template.includes('@@')) {
  throw new Error('unexpanded placeholder in rendered vhost config');
}
await writeFile(outputPath, template, { mode: 0o644 });