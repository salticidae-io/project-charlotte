import https from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';

const [root, issuerOutput] = process.argv.slice(2);
if (!root) throw new Error('usage: wait-for-pebble.mjs CA_ROOT [ISSUER_PEM_OUTPUT]');
const ca = await readFile(root);

function get(port, path) {
  return new Promise((resolve) => {
    const request = https.get({
      hostname: 'localhost',
      family: 4,
      port,
      path,
      headers: { 'User-Agent': 'charlotte-demo-readiness' },
      ca,
      timeout: 500,
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
    });
    request.on('error', () => resolve(null));
    request.on('timeout', () => {
      request.destroy();
      resolve(null);
    });
  });
}

for (let attempt = 0; attempt < 50; attempt += 1) {
  const directory = await get(14000, '/dir');
  if (directory?.status === 200) {
    if (!issuerOutput) process.exit(0);
    // Pebble generates a fresh issuing hierarchy on every start; the browser
    // must trust that hierarchy, not the fixed CA of Pebble's own listener.
    const issuers = await Promise.all([get(15000, '/roots/0'), get(15000, '/intermediates/0')]);
    if (issuers.every((issuer) => issuer?.status === 200 && issuer.body.includes('BEGIN CERTIFICATE'))) {
      await writeFile(issuerOutput, issuers.map((issuer) => issuer.body.trim()).join('\n') + '\n', { mode: 0o644 });
      process.exit(0);
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
}
process.exit(1);
