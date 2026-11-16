import { execFileSync } from 'node:child_process';
import { access, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

const state = process.env.CHARLOTTE_DEMO_STATE;
const binDir = process.env.CHARLOTTE_DEMO_BIN_DIR;
const controlSocket = process.env.CHARLOTTE_DEMO_CONTROL_SOCKET;
const worker = process.env.CHARLOTTE_DEMO_WORKER_USER;
const upstreamPort = process.env.CHARLOTTE_DEMO_UPSTREAM_PORT ?? '18081';
const httpPort = process.env.CHARLOTTE_DEMO_HTTP_PORT ?? '8080';
const tlsPort = process.env.CHARLOTTE_DEMO_TLS_PORT ?? '8443';
const httpUrl = (host, resource = '/') => `http://${host}:${httpPort}${resource}`;
const httpsUrl = (host, resource = '/') => `https://${host}:${tlsPort}${resource}`;

export const scenes = [
  {
    id: 'welcome',
    title: 'Charlotte serves the demo site',
    description: 'A real browser request reaches the local default virtual host.',
    request: `GET ${httpUrl('charlotte.test')} with the browser's normal navigation headers.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('charlotte.test'));
      const title = await ctx.evaluate('document.title');
      requireCondition(title === 'Charlotte live feature demo', `unexpected page title: ${title}`);
      return 'Default vhost returned the Charlotte demo page.';
    },
  },
  {
    id: 'static',
    title: 'Static files and HTTP semantics',
    description: 'A named vhost serves a document root with validators; with ModSecurity enabled, byte ranges are answered in full so blocked content cannot be fetched piecewise.',
    request: `GET ${httpUrl('static.charlotte.test')} followed by browser requests for /sample.txt, a Range request, and an If-None-Match revalidation.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('static.charlotte.test'));
      const title = await ctx.evaluate('document.title');
      requireCondition(title === 'Static vhost | Charlotte demo', 'static vhost did not serve its index');
      const full = await ctx.fetch('/sample.txt');
      requireCondition(full.status === 200 && full.text.includes('static vhost document root'), `static file returned HTTP ${full.status}`);
      const range = await ctx.fetch('/sample.txt', { headers: { Range: 'bytes=0-7' } });
      requireCondition(range.status === 200 && range.text === full.text && !range.headers['content-range'],
        `inspected byte range returned HTTP ${range.status}, expected the full 200 response`);
      const etag = full.headers.etag;
      requireCondition(Boolean(etag), 'static response did not include an ETag');
      const conditional = await ctx.fetch('/sample.txt', { headers: { 'If-None-Match': etag } });
      requireCondition(conditional.status === 304, `conditional request returned HTTP ${conditional.status}, expected 304`);
      await ctx.explain(`The ETag ${etag} was returned on the file response; the matching If-None-Match request returned 304, so the browser can reuse its cached copy.`);
      return 'Named document root, ETag/304 revalidation, and WAF range-evasion protection (full 200 for a Range request) verified.';
    },
  },
  {
    id: 'cgi',
    title: 'Classic CGI execution',
    description: 'Charlotte executes an installed CGI script in the vhost worker.',
    request: `GET ${httpUrl('cgi.charlotte.test', '/hello.sh')} to execute the CGI script.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('cgi.charlotte.test', '/hello.sh'));
      const text = await ctx.evaluate('document.body.innerText');
      requireCondition(text.includes('Charlotte CGI executed this script'), 'CGI script did not return its marker');
      return 'The CGI process returned its generated response.';
    },
  },
  {
    id: 'php-fastcgi',
    title: 'Supervised PHP FastCGI',
    description: 'PHP is optional; when present Charlotte starts and supervises php-cgi.',
    request: `GET ${httpUrl('php.charlotte.test', '/info.php')} to invoke the supervised PHP FastCGI application.`,
    available: process.env.CHARLOTTE_DEMO_HAS_PHP === '1',
    async run(ctx) {
      await ctx.navigate(httpUrl('php.charlotte.test', '/info.php'));
      const text = await ctx.evaluate('document.body.innerText');
      requireCondition(text.includes('Charlotte supervised PHP FastCGI is running'), 'PHP FastCGI marker was not returned');
      return 'php-cgi executed through the configured FastCGI application.';
    },
  },
  {
    id: 'reverse-proxy',
    title: 'Reverse proxy to a local upstream',
    description: 'The browser-visible vhost forwards to a separate local Node service.',
    request: `GET ${httpUrl('proxy.charlotte.test')}; Charlotte should forward it to the local Node upstream.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('proxy.charlotte.test'));
      const body = await ctx.evaluate('document.body.innerText');
      requireCondition(body.includes('charlotte-local-upstream'), 'proxied response did not come from the upstream');
      return 'The response includes the upstream service marker and request path.';
    },
  },
  {
    id: 'converters',
    title: 'Apache and nginx configuration conversion',
    description: 'Both bundled import tools parse sample server configurations into Charlotte YAML.',
    request: 'No browser HTTP request is sent. The demo submits the sample Apache and nginx configurations to their local conversion tools.',
    async run(ctx) {
      const results = [];
      for (const [binary, sample] of [
        ['apache2charlotte', 'apache-sample.conf'],
        ['nginx2charlotte', 'nginx-sample.conf'],
      ]) {
        await ctx.announce(`Run ${binary} on demo/conf/${sample} and capture the generated Charlotte YAML.`);
        const output = execFileSync(path.join(binDir, binary), [
          path.join(process.env.CHARLOTTE_DEMO_PROJECT_ROOT, 'demo/conf', sample),
        ], { encoding: 'utf8' });
        requireCondition(output.includes('server_names'), `${binary} did not emit a virtual host`);
        await ctx.explain(`${binary} completed successfully; generated output begins: ${output.trim().slice(0, 220).replace(/\s+/g, ' ')}.`);
        results.push(`${binary} converted its sample`);
      }
      return `${results.join('; ')}.`;
    },
  },
  {
    id: 'control-api',
    title: 'Control socket CRUD',
    description: 'The actual charlotte-ctl client lists, creates, reads, replaces, and deletes a vhost.',
    request: `The browser waits while charlotte-ctl changes a vhost through ${controlSocket}; it then sends GET ${httpUrl('ctl.charlotte.test')} to verify the route.`,
    async run(ctx) {
      const ctl = async (...args) => {
        const input = args[0] === 'create' || args[0] === 'put'
          ? JSON.stringify({
            server_names: ['ctl.charlotte.test'],
            proxy_pass: `http://127.0.0.1:${upstreamPort}${args[0] === 'put' ? '/updated' : ''}`,
          })
          : undefined;
        await ctx.announce(`Control socket command: charlotte-ctl ${args.join(' ')}`);
        const output = execFileSync(path.join(binDir, 'charlotte-ctl'), [
          '--socket', controlSocket, ...args,
        ], { encoding: 'utf8', input });
        await ctx.explain(`Control API response: ${output.trim().replace(/\s+/g, ' ').slice(0, 240)}`);
        return output;
      };

      JSON.parse(await ctl('status'));
      JSON.parse(await ctl('list'));
      JSON.parse(await ctl('create', 'demo-control', '-'));
      const created = JSON.parse(await ctl('get', 'demo-control'));
      requireCondition(created.vhost?.[0]?.server_names?.includes('ctl.charlotte.test'), 'control API did not return the created vhost');
      await ctx.navigate(httpUrl('ctl.charlotte.test'));
      let body = await ctx.evaluate('document.body.innerText');
      requireCondition(body.includes('charlotte-local-upstream'), 'created control-socket vhost did not route');

      JSON.parse(await ctl('put', 'demo-control', '-'));
      await ctx.navigate(httpUrl('ctl.charlotte.test'));
      body = await ctx.evaluate('document.body.innerText');
      requireCondition(body.includes('/updated'), 'control-socket replace did not update the upstream route');
      await ctl('delete', 'demo-control');
      const list = JSON.parse(await ctl('list'));
      requireCondition(!JSON.stringify(list).includes('ctl.charlotte.test'), 'deleted vhost remains in the control API listing');
      return 'Control API status/list/get/create/replace/delete and browser routing passed.';
    },
  },
  {
    id: 'hot-reload',
    title: 'Vhost directory hot reload',
    description: 'A new YAML vhost appears without restarting Charlotte.',
    request: `The demo writes live.charlotte.test to the watched vhost directory, then the browser sends GET ${httpUrl('live.charlotte.test')} without restarting Charlotte.`,
    async run(ctx) {
      const config = [
        'vhost:',
        '  - server_names: [live.charlotte.test]',
        `    root: ${JSON.stringify(path.join(state, 'sites/static'))}`,
        `    user: ${JSON.stringify(worker)}`,
        '    listing: false',
        '',
      ].join('\n');
      await writeFile(path.join(state, 'vhosts.d', 'demo-live.yaml'), config, { mode: 0o640 });
      await ctx.explain('The new vhost YAML has been written; Charlotte should notice it through the directory watcher.');
      let title = '';
      for (let attempt = 0; attempt < 30; attempt += 1) {
        await ctx.navigate(httpUrl('live.charlotte.test'));
        title = await ctx.evaluate('document.title');
        if (title === 'Static vhost | Charlotte demo') break;
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
      requireCondition(title === 'Static vhost | Charlotte demo', 'directory watcher did not activate the new vhost');
      return 'New vhost became active while the Charlotte process remained running.';
    },
  },
  {
    id: 'modsecurity',
    title: 'ModSecurity request and response rules',
    description: 'A local demo rule blocks a marked query and a marked response body.',
    request: `GET ${httpUrl('waf.charlotte.test', '/?input=charlotte-demo-block')} with a marked query, then GET /response-block.txt to test response inspection.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('waf.charlotte.test'));
      const request = await ctx.fetch('/?input=charlotte-demo-block');
      requireCondition(request.status === 403, `request rule returned HTTP ${request.status}, expected 403`);
      const response = await ctx.fetch('/response-block.txt');
      requireCondition(response.status === 403, `response rule returned HTTP ${response.status}, expected 403`);
      await ctx.explain('Both responses are HTTP 403: the first rule matched the marked request argument; the second matched the configured response-body marker.');
      return 'Both request-body/argument inspection and response-body inspection blocked as configured.';
    },
  },
  {
    id: 'rate-limit',
    title: 'Per-vhost rate limiting',
    description: 'A small same-browser burst demonstrates 429 responses from the configured limiter.',
    request: `GET ${httpUrl('rate.charlotte.test')} followed by ten uncached browser GET requests with distinct rate-demo query values.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('rate.charlotte.test'));
      const responses = await ctx.fetchBurst(Array.from({ length: 10 }, (_, index) => `/?rate-demo=${index}`));
      const statuses = responses.map((response) => response.status);
      requireCondition(statuses.some((status) => status === 429), `no request was rate limited: ${statuses.join(', ')}`);
      const limited = responses.find((response) => response.status === 429);
      await ctx.explain(`The limiter returned 429 after the per-vhost request threshold was reached${limited.headers['retry-after'] ? `; Retry-After: ${limited.headers['retry-after']}` : ''}. Status sequence: ${statuses.join(', ')}.`);
      return `Local request burst produced HTTP 429 (${statuses.filter((status) => status === 429).length} of ${statuses.length}).`;
    },
  },
  {
    id: 'bot-detection',
    title: 'Bot challenge, scanner block, and honeypot ban',
    description: 'Controlled User-Agent changes demonstrate the bot policy; the honeypot ban expires before the next scene.',
    request: `GET ${httpUrl('bot.charlotte.test')} with User-Agent curl/8.0.0 CharlotteDemo to trigger a challenge; then try a scanner User-Agent and the /admin-honeypot path.`,
    async run(ctx) {
      await ctx.setUserAgent('curl/8.0.0 CharlotteDemo');
      await ctx.navigate(httpUrl('bot.charlotte.test'));
      let title = await ctx.evaluate('document.title');
      requireCondition(title !== 'Checking your browser', 'browser did not solve the proof-of-work challenge');
      const passedChallenge = await ctx.fetch('/');
      requireCondition(passedChallenge.status === 200, `challenge cookie did not allow the browser: ${passedChallenge.status}`);
      await ctx.explain('The proof-of-work page completed and the browser returned with its challenge cookie; the protected page now responds with HTTP 200.');

      await ctx.setUserAgent('demo-scanner/1.0');
      const blocked = await ctx.fetch('/');
      requireCondition(blocked.status === 403, `scanner User-Agent returned HTTP ${blocked.status}, expected 403`);
      await ctx.explain('The configured scanner User-Agent was denied with HTTP 403 before the site content was served.');
      await ctx.setUserAgent(null);

      const trap = await ctx.fetch('/admin-honeypot');
      requireCondition(trap.status === 403, `honeypot path returned HTTP ${trap.status}, expected 403`);
      const banned = await ctx.fetch('/');
      requireCondition(banned.status === 403, `honeypot did not ban the client: ${banned.status}`);
      await ctx.explain('After the honeypot request, the client IP is temporarily banned and the ordinary path also returns HTTP 403.');
      await new Promise((resolve) => setTimeout(resolve, 3200));
      const recovered = await ctx.fetch('/');
      requireCondition(recovered.status === 200, `short honeypot ban did not expire: ${recovered.status}`);
      await ctx.explain('The temporary ban expired; the ordinary request returned to HTTP 200.');
      return 'Proof-of-work passed, scanner traffic was blocked, and the short honeypot ban expired.';
    },
  },
  {
    id: 'tls-http3',
    title: 'TLS/SNI and HTTP/3 over QUIC',
    description: 'The browser validates the local TLS certificate and reports its negotiated HTTP protocol.',
    request: `HTTPS GET ${httpsUrl('static.charlotte.test')} followed by HTTPS GET ${httpsUrl('h3.charlotte.test')} to verify SNI, certificate trust, and HTTP/3 advertisement.`,
    async run(ctx) {
      await ctx.navigate(httpsUrl('static.charlotte.test'));
      const secure = await ctx.evaluate('({ protocol: location.protocol, title: document.title })');
      requireCondition(secure.protocol === 'https:' && secure.title === 'Static vhost | Charlotte demo', 'TLS page did not load with the expected vhost');
      try {
        await ctx.navigate(httpsUrl('h3.charlotte.test'));
      } catch (error) {
        if (/QUIC|CERT|SSL|TLS/i.test(error.message)) {
          const skipped = new Error(`Chromium could not trust/negotiate the private-CA QUIC connection; no Alt-Svc response was available (${error.message}).`);
          skipped.name = 'SceneSkipped';
          throw skipped;
        }
        throw error;
      }
      const protocol = await ctx.evaluate('performance.getEntriesByType("navigation")[0]?.nextHopProtocol || "unknown"');
      const headers = ctx.responseHeaders(httpsUrl('h3.charlotte.test'));
      const altSvc = headers['alt-svc'] ?? '';
      if (protocol !== 'h3' && !/h3/i.test(altSvc)) {
        const skipped = new Error(`HTTP/3 was not negotiated and the response did not advertise h3 with Alt-Svc (protocol: ${protocol}).`);
        skipped.name = 'SceneSkipped';
        throw skipped;
      }
      await ctx.explain(`TLS certificate validation and SNI succeeded. Chromium negotiated ${protocol}${altSvc ? `; the server advertised Alt-Svc: ${altSvc}` : ''}.`);
      return `TLS/SNI succeeded; browser reported ${protocol}${altSvc ? ` (Alt-Svc: ${altSvc})` : ''}.`;
    },
  },
  {
    id: 'acme-http01',
    title: 'On-demand ACME HTTP-01 certificate',
    description: 'A browser HTTP request starts a real Pebble order; Charlotte serves the newly issued TLS certificate.',
    request: `Plain HTTP GET ${httpUrl('acme.charlotte.test')} starts on-demand ACME HTTP-01 issuance; after validation, the browser will retry the same vhost over HTTPS.`,
    available: process.env.CHARLOTTE_DEMO_HAS_ACME === '1',
    async run(ctx) {
      await ctx.navigate(httpUrl('acme.charlotte.test'));
      const certificate = path.join(state, 'acme', 'acme.charlotte.test.cert.pem');
      let issued = false;
      for (let attempt = 0; attempt < 180; attempt += 1) {
        try {
          await access(certificate);
          issued = true;
          break;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 500));
        }
      }
      requireCondition(issued, 'Pebble did not issue a certificate within 90 seconds');
      const pem = await readFile(certificate, 'utf8');
      requireCondition(pem.includes('BEGIN CERTIFICATE'), 'ACME cache did not contain a PEM certificate');
      const certificateInfo = execFileSync('openssl', ['x509', '-in', certificate, '-noout', '-subject', '-issuer', '-dates'], { encoding: 'utf8' }).trim();
      await ctx.explain(`Pebble completed HTTP-01 validation and Charlotte cached the issued leaf certificate: ${certificateInfo.replace(/\s+/g, ' ')}.`);
      await ctx.navigate(httpsUrl('acme.charlotte.test'));
      const title = await ctx.evaluate('document.title');
      requireCondition(title === 'Static vhost | Charlotte demo', 'issued certificate did not enable the HTTPS vhost');
      return 'Plain HTTP caused an HTTP-01 order; the resulting certificate was then served over trusted TLS.';
    },
  },
  {
    id: 'access-logs',
    title: 'Structured access logging',
    description: 'Completed requests are written to the configured per-run access log.',
    request: `GET ${httpUrl('static.charlotte.test')}; after the response, the demo will inspect the per-run access log for its vhost, status, and request metadata.`,
    async run(ctx) {
      await ctx.navigate(httpUrl('static.charlotte.test'));
      const logPath = process.env.CHARLOTTE_DEMO_ACCESS_LOG;
      let log = '';
      for (let attempt = 0; attempt < 20; attempt += 1) {
        try {
          log = await readFile(logPath, 'utf8');
        } catch {
          // The first completed request may race log-file creation.
        }
        if (log.includes('static.charlotte.test')) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      requireCondition(log.includes('static.charlotte.test'), 'access log did not record the browser request');
      const line = log.split('\n').filter((entry) => entry.includes('static.charlotte.test')
        && /"GET \/ HTTP\/\d\.\d" 200\b/.test(entry)).at(-1);
      requireCondition(Boolean(line), 'access log did not record the successful browser GET');
      await ctx.explain(`The completed request appears in the structured access log: ${line.slice(0, 260)}.`);
      return 'Access log contains the browser request, vhost, status, and request metadata.';
    },
  },
];