import { EventEmitter } from 'node:events';
import { createInterface } from 'node:readline';
import net from 'node:net';
import crypto from 'node:crypto';
import { scenes } from './scenes.mjs';

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

class DevToolsConnection extends EventEmitter {
  constructor(url) {
    super();
    this.url = new URL(url);
    this.socket = net.createConnection(Number(this.url.port), this.url.hostname);
    this.socket.setNoDelay(true);
    this.buffer = Buffer.alloc(0);
    this.handshakeBuffer = Buffer.alloc(0);
    this.upgraded = false;
    this.nextId = 0;
    this.pending = new Map();
    this.fragments = [];
    this.opened = new Promise((resolve, reject) => {
      this.resolveOpen = resolve;
      this.rejectOpen = reject;
    });
    this.socket.on('connect', () => this.handshake());
    this.socket.on('data', (chunk) => this.receive(chunk));
    this.socket.on('error', (error) => {
      if (!this.upgraded) this.rejectOpen(error);
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
      this.emit('connectionError', error);
    });
    this.socket.on('close', () => {
      const error = new Error('DevTools WebSocket closed');
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
      this.emit('connectionClosed');
    });
  }

  handshake() {
    const key = crypto.randomBytes(16).toString('base64');
    this.socket.write([
      `GET ${this.url.pathname}${this.url.search} HTTP/1.1`,
      `Host: ${this.url.host}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
      '\r\n',
    ].join('\r\n'));
  }

  receive(chunk) {
    if (!this.upgraded) {
      this.handshakeBuffer = Buffer.concat([this.handshakeBuffer, chunk]);
      const boundary = this.handshakeBuffer.indexOf('\r\n\r\n');
      if (boundary < 0) return;
      const headers = this.handshakeBuffer.subarray(0, boundary).toString('ascii');
      if (!/^HTTP\/1\.1 101\b/.test(headers)) {
        const error = new Error(`DevTools WebSocket handshake failed: ${headers.split('\r\n')[0]}`);
        this.rejectOpen(error);
        this.socket.destroy();
        return;
      }
      this.upgraded = true;
      this.resolveOpen();
      const remainder = this.handshakeBuffer.subarray(boundary + 4);
      this.handshakeBuffer = Buffer.alloc(0);
      if (remainder.length) this.receiveFrames(remainder);
      return;
    }
    this.receiveFrames(chunk);
  }

  receiveFrames(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 2) {
      const first = this.buffer[0];
      const second = this.buffer[1];
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < offset + 2) return;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) return;
        const largeLength = this.buffer.readBigUInt64BE(offset);
        if (largeLength > 16_777_216n) throw new Error('DevTools frame exceeds 16 MiB');
        length = Number(largeLength);
        offset += 8;
      }
      let mask;
      if (masked) {
        if (this.buffer.length < offset + 4) return;
        mask = this.buffer.subarray(offset, offset + 4);
        offset += 4;
      }
      if (this.buffer.length < offset + length) return;
      const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
      this.buffer = this.buffer.subarray(offset + length);
      if (mask) for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index & 3];

      if (opcode === 8) {
        this.socket.end();
        return;
      }
      if (opcode === 9) {
        this.writeFrame(10, payload);
        continue;
      }
      if (opcode === 1) {
        this.fragments = [payload];
        if (first & 0x80) this.dispatchMessage(payload);
      } else if (opcode === 0 && this.fragments.length) {
        this.fragments.push(payload);
        if (first & 0x80) {
          this.dispatchMessage(Buffer.concat(this.fragments));
          this.fragments = [];
        }
      }
    }
  }

  dispatchMessage(payload) {
    let message;
    try {
      message = JSON.parse(payload.toString('utf8'));
    } catch (error) {
      this.emit('connectionError', error);
      return;
    }
    if (message.id !== undefined) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(message.error.message ?? JSON.stringify(message.error)));
      else pending.resolve(message.result ?? {});
    } else if (message.method) {
      this.emit('event', message.method, message.params ?? {});
    }
  }

  writeFrame(opcode, payload) {
    const mask = crypto.randomBytes(4);
    let header;
    if (payload.length < 126) {
      header = Buffer.alloc(2);
      header[1] = 0x80 | payload.length;
    } else if (payload.length < 65_536) {
      header = Buffer.alloc(4);
      header[1] = 0x80 | 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    header[0] = 0x80 | opcode;
    const masked = Buffer.from(payload);
    for (let index = 0; index < masked.length; index += 1) masked[index] ^= mask[index & 3];
    this.socket.write(Buffer.concat([header, mask, masked]));
  }

  async send(method, params = {}) {
    await this.opened;
    const id = ++this.nextId;
    const payload = Buffer.from(JSON.stringify({ id, method, params }));
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`DevTools command timed out: ${method}`));
      }, 15_000);
      this.pending.set(id, { resolve, reject, timer });
    });
    this.writeFrame(1, payload);
    return response;
  }

  waitForEvent(method, timeout = 15_000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.off('event', onEvent);
        reject(new Error(`DevTools event timed out: ${method}`));
      }, timeout);
      const onEvent = (name, params) => {
        if (name !== method) return;
        clearTimeout(timer);
        this.off('event', onEvent);
        resolve(params);
      };
      this.on('event', onEvent);
    });
  }

  close() {
    this.socket.destroy();
  }
}

async function openTarget(port) {
  const endpoint = `http://127.0.0.1:${port}/json/new?about:blank`;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(endpoint, { method: 'PUT' });
      if (response.ok) return response.json();
    } catch {
      // Chromium may need a moment to open the remote debugging endpoint.
    }
    await sleep(200);
  }
  throw new Error(`Chromium DevTools did not become ready on port ${port}`);
}

async function closeBrowser(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/version`);
  if (!response.ok) return;
  const version = await response.json();
  const connection = new DevToolsConnection(version.webSocketDebuggerUrl);
  await connection.opened;
  try {
    await connection.send('Browser.close');
  } finally {
    connection.close();
  }
}

class BrowserDriver {
  constructor(connection, target, options) {
    this.cdp = connection;
    this.target = target;
    this.responses = new Map();
    this.responseHistory = new Map();
    this.auto = options.auto;
    this.speed = options.speed;
    this.userAgent = null;
    this.overlay = { title: '', description: '', status: 'RUNNING', detail: '', current: 0, total: 0, request: '', responses: [] };
    this.cdp.on('event', (method, params) => {
      if (method === 'Network.responseReceived') {
        const headers = {};
        for (const [name, value] of Object.entries(params.response.headers ?? {})) {
          headers[name.toLowerCase()] = String(value);
        }
        const response = {
          url: params.response.url,
          status: params.response.status,
          statusText: params.response.statusText,
          headers,
        };
        this.responses.set(params.response.url, response);
        const history = this.responseHistory.get(params.response.url) ?? [];
        history.push(response);
        this.responseHistory.set(params.response.url, history);
      }
    });
  }

  async initialize() {
    await this.cdp.send('Page.enable');
    await this.cdp.send('Runtime.enable');
    await this.cdp.send('Network.enable');
    await this.cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
    this.defaultUserAgent = await this.evaluate('navigator.userAgent');
  }

  async evaluate(expression) {
    const result = await this.cdp.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
    }
    return result.result?.value;
  }

  async navigate(url) {
    const userAgent = this.userAgent ? `; User-Agent: ${this.userAgent}` : '';
    await this.announce(`GET ${url}${userAgent}`);
    const responseStart = this.responseHistory.get(url)?.length ?? 0;
    const result = await this.cdp.send('Page.navigate', { url });
    if (result.errorText) throw new Error(`browser navigation failed: ${result.errorText}`);
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      try {
        const state = await this.evaluate(`({ url: location.href, title: document.title, ready: document.readyState })`);
        if (state.ready === 'complete' && state.url !== 'about:blank' && state.title !== 'Checking your browser') {
          const response = this.responses.get(state.url) ?? {};
          const body = await this.evaluate('document.body?.innerText ?? ""');
          await this.renderOverlay();
          const responses = this.responseHistory.get(url)?.slice(responseStart) ?? [];
          if (responses.length) {
            for (const [index, item] of responses.entries()) {
              const responseBody = index === responses.length - 1 && item.url === state.url ? body : '';
              await this.explain(`${item.url === url ? '' : `${item.url}: `}${describeResponse(item, undefined, responseBody)}`);
            }
          } else {
            await this.explain(describeResponse(response, undefined, body));
          }
          return state;
        }
      } catch {
        // A navigation can replace the execution context between polling calls.
      }
      await sleep(100);
    }
    throw new Error(`browser did not finish loading ${url}`);
  }

  async fetch(resource, options = {}) {
    const url = new URL(resource, await this.evaluate('location.href')).toString();
    const requestOptions = { cache: 'no-store', ...options };
    const method = String(requestOptions.method ?? 'GET').toUpperCase();
    const requestHeaders = requestOptions.headers && Object.keys(requestOptions.headers).length
      ? `; headers: ${JSON.stringify(requestOptions.headers)}` : '';
    await this.announce(`${method} ${url}${requestHeaders}${this.userAgent ? `; User-Agent: ${this.userAgent}` : ''}`);
    const expression = `(async () => {
      const response = await fetch(${JSON.stringify(url)}, ${JSON.stringify(requestOptions)});
      const text = await response.text();
      return { status: response.status, statusText: response.statusText, text, headers: Object.fromEntries(response.headers.entries()) };
    })()`;
    const response = await this.evaluate(expression);
    const networkResponse = this.responses.get(url) ?? {};
    await this.explain(describeResponse({ ...networkResponse, ...response, headers: { ...networkResponse.headers, ...response.headers } }));
    return response;
  }

  async fetchBurst(resources, options = {}) {
    const baseUrl = await this.evaluate('location.href');
    const urls = resources.map((resource) => new URL(resource, baseUrl).toString());
    const requestOptions = { cache: 'no-store', ...options };
    const method = String(requestOptions.method ?? 'GET').toUpperCase();
    const requestHeaders = requestOptions.headers && Object.keys(requestOptions.headers).length
      ? `; headers: ${JSON.stringify(requestOptions.headers)}` : '';
    await this.announce(`${urls.map((url) => `${method} ${url}`).join(', ')} sent concurrently${requestHeaders}`);
    const expression = `(async () => Promise.all(${JSON.stringify(urls)}.map(async (url) => {
      const response = await fetch(url, ${JSON.stringify(requestOptions)});
      const text = await response.text();
      return { url, status: response.status, statusText: response.statusText, text, headers: Object.fromEntries(response.headers.entries()) };
    })))()`;
    const responses = await this.evaluate(expression);
    for (const response of responses) {
      const networkResponse = this.responses.get(response.url) ?? {};
      const details = { ...networkResponse, ...response, headers: { ...networkResponse.headers, ...response.headers } };
      await this.explain(`${new URL(response.url).pathname}${new URL(response.url).search}: ${describeResponse(details)}`);
    }
    return responses;
  }

  async fetchWithHeaders(resource, headers, options = {}) {
    await this.cdp.send('Network.setExtraHTTPHeaders', { headers });
    try {
      return await this.fetch(resource, options);
    } finally {
      await this.cdp.send('Network.setExtraHTTPHeaders', { headers: {} });
    }
  }

  async setUserAgent(userAgent) {
    await this.cdp.send('Emulation.setUserAgentOverride', {
      userAgent: userAgent ?? this.defaultUserAgent,
    });
    this.userAgent = userAgent;
    if (userAgent) await this.announce(`The next browser request will use User-Agent: ${userAgent}`);
  }

  responseHeaders(url) {
    return this.responses.get(new URL(url).toString())?.headers ?? {};
  }

  async announce(text) {
    this.overlay.request = text;
    console.log(`  → About to send: ${text}`);
    await this.renderOverlay();
    if (this.auto) await sleep(1800 / this.speed);
  }

  async explain(text) {
    this.overlay.responses.push(text);
    console.log(`  ← Server response: ${text}`);
    await this.renderOverlay();
  }

  async showOverlay({ title, description, status, detail, current, total }) {
    if (this.overlay.title !== title) {
      this.overlay.request = '';
      this.overlay.responses = [];
    }
    Object.assign(this.overlay, { title, description, status, detail: detail ?? '', current, total });
    await this.renderOverlay();
  }

  async renderOverlay() {
    const payload = JSON.stringify(this.overlay);
    try {
    await this.evaluate(`(() => {
      const data = ${payload};
      let panel = document.getElementById('charlotte-demo-panel');
      if (!panel) {
        panel = document.createElement('aside');
        panel.id = 'charlotte-demo-panel';
        let markup = '<style>#charlotte-demo-panel{position:fixed;z-index:2147483647;top:14px;left:14px;width:min(680px,calc(100vw - 60px));max-height:82vh;overflow:auto;padding:16px 18px;border:1px solid #6f88b5;border-radius:12px;background:rgba(12,20,36,.96);color:#f4f7ff;font:14px/1.45 system-ui,sans-serif;box-shadow:0 12px 40px #0008}#charlotte-demo-panel strong{display:block;font-size:17px;margin-bottom:4px}#charlotte-demo-panel .meta{color:#bdc9df;font-size:12px;margin-bottom:8px}#charlotte-demo-panel .section-title{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#9eb8e6;font-weight:700;margin:12px 0 4px}#charlotte-demo-panel .request{white-space:pre-wrap;overflow-wrap:anywhere;background:#182641;padding:8px;border-radius:6px}#charlotte-demo-panel .responses{max-height:34vh;overflow:auto}#charlotte-demo-panel .response{white-space:pre-wrap;overflow-wrap:anywhere;border-left:2px solid #7fe0a1;padding:5px 8px;margin:5px 0;background:#142237}#charlotte-demo-panel .state{font-weight:700;color:#7fe0a1;margin-top:8px}#charlotte-demo-panel .state.fail{color:#ff8585}#charlotte-demo-panel button{margin-top:10px;padding:6px 12px;border:0;border-radius:6px;background:#a9c5ff;color:#111;cursor:pointer;font-weight:700}</style><strong id="demo-title"></strong><div class="meta" id="demo-meta"></div><div id="demo-description"></div><div class="section-title">About to send</div><div class="request" id="demo-request"></div><div class="section-title">Server response</div><div class="responses" id="demo-responses"></div><div class="state" id="demo-state"></div><button id="demo-next">Next scene →</button>';
        if (window.trustedTypes) {
          try {
            markup = window.trustedTypes.createPolicy('charlotte-demo-overlay', { createHTML: (value) => value }).createHTML(markup);
          } catch {
            return;
          }
        }
        try {
          panel.innerHTML = markup;
        } catch {
          return;
        }
        document.documentElement.append(panel);
        window.__charlotteDemoNext = 0;
        panel.querySelector('#demo-next').addEventListener('click', () => { window.__charlotteDemoNext += 1; });
        window.addEventListener('keydown', (event) => {
          if ((event.code === 'Space' || event.key === 'ArrowRight') && !['INPUT', 'TEXTAREA'].includes(event.target?.tagName)) {
            event.preventDefault();
            window.__charlotteDemoNext += 1;
          }
        });
      }
      panel.querySelector('#demo-title').textContent = data.title;
      panel.querySelector('#demo-meta').textContent = 'SCENE ' + data.current + ' / ' + data.total;
      panel.querySelector('#demo-description').textContent = data.description;
      panel.querySelector('#demo-request').textContent = data.request || 'Preparing the scene request…';
      const responseList = panel.querySelector('#demo-responses');
      responseList.replaceChildren(...data.responses.map((text) => {
        const line = document.createElement('div');
        line.className = 'response';
        line.textContent = text;
        return line;
      }));
      const state = panel.querySelector('#demo-state');
      state.textContent = data.status + (data.detail ? ' — ' + data.detail : '');
      state.className = 'state' + (data.status === 'FAIL' ? ' fail' : '');
      panel.querySelector('#demo-next').textContent = data.status === 'FINAL' ? 'Finish' : 'Next scene →';
    })()`);
    } catch {
      // Error pages may not allow script injection; terminal narration is retained.
    }
  }
}

function describeResponse(response, headerNames, body = response.text ?? '') {
  const statusText = response.statusText ? ` ${response.statusText}` : '';
  const headers = response.headers ?? {};
  const selectedHeaders = headerNames ?? [
    'content-type', 'etag', 'last-modified', 'content-range', 'retry-after', 'set-cookie', 'alt-svc',
    'location', 'x-charlotte-demo-upstream',
  ];
  const headerDetails = selectedHeaders
    .map((name) => [name, headers[name.toLowerCase()]])
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${name}: ${value}`);
  const normalizedBody = String(body ?? '').replace(/\s+/g, ' ').trim();
  const excerpt = normalizedBody ? ` · body: “${normalizedBody.slice(0, 220)}${normalizedBody.length > 220 ? '…' : ''}”` : '';
  return `HTTP ${response.status ?? 'response'}${statusText}${headerDetails.length ? ` · ${headerDetails.join(' · ')}` : ''}${excerpt}`;
}

function parseArguments(args) {
  const options = { auto: false, headless: false, speed: 1, only: null };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--auto') options.auto = true;
    else if (argument === '--headless') options.headless = true;
    else if (argument === '--only') options.only = args[++index];
    else if (argument === '--speed') options.speed = Number(args[++index]);
    else if (argument === '--help' || argument === '-h') options.help = true;
    else throw new Error(`unknown option: ${argument}`);
  }
  if (!Number.isFinite(options.speed) || options.speed <= 0) throw new Error('--speed must be a positive number');
  return options;
}

async function waitForPresenter(driver, readline) {
  const startingCount = Number(await driver.evaluate('window.__charlotteDemoNext || 0'));
  process.stdout.write('Press Enter, Space, or → for the next scene.\n');
  let resolveEnter;
  const enterPressed = new Promise((resolve) => { resolveEnter = resolve; });
  const onLine = () => resolveEnter();
  readline.once('line', onLine);
  while (true) {
    if (Number(await driver.evaluate('window.__charlotteDemoNext || 0')) > startingCount) {
      readline.off('line', onLine);
      return;
    }
    const completed = await Promise.race([enterPressed.then(() => true), sleep(150).then(() => false)]);
    if (completed) return;
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node demo/director.mjs [--auto] [--headless] [--only SCENE] [--speed MULTIPLIER]\n');
    return;
  }
  if (!process.stdin.isTTY) options.auto = true;
  let selected = scenes;
  if (options.only) {
    selected = scenes.filter((scene) => scene.id === options.only);
    if (selected.length === 0) throw new Error(`unknown scene id: ${options.only}`);
  }

  const port = Number(process.env.CHARLOTTE_DEMO_CHROME_DEBUG_PORT ?? 9222);
  const target = await openTarget(port);
  const cdp = new DevToolsConnection(target.webSocketDebuggerUrl);
  await cdp.opened;
  const driver = new BrowserDriver(cdp, target, options);
  await driver.initialize();
  const readline = options.auto ? null : createInterface({ input: process.stdin, output: process.stdout, terminal: false });
  const results = [];
  let failed = false;

  try {
    for (let index = 0; index < selected.length; index += 1) {
      const scene = selected[index];
      const position = index + 1;
      let status = 'RUNNING';
      let detail = '';
      console.log(`[${position}/${selected.length}] ${scene.title}`);
      if (scene.available === false) {
        status = 'SKIP';
        detail = 'Optional runtime or local CA is unavailable.';
      } else {
        try {
          await driver.showOverlay({ ...scene, status, current: position, total: selected.length });
          await driver.announce(scene.request);
          detail = await scene.run(driver) ?? 'Checks passed.';
          status = 'PASS';
          console.log(`  PASS: ${detail}`);
        } catch (error) {
          if (error.name === 'SceneSkipped') {
            status = 'SKIP';
            detail = error.message;
            console.log(`  SKIP: ${detail}`);
          } else {
            status = 'FAIL';
            detail = error.message;
            failed = true;
            console.error(`  FAIL: ${detail}`);
          }
        }
      }
      results.push({ id: scene.id, status, detail });
      try {
        await driver.showOverlay({ ...scene, status, detail, current: position, total: selected.length });
      } catch (error) {
        console.error(`  overlay update failed: ${error.message}`);
      }
      if (options.auto) await sleep(1000 / options.speed);
      else await waitForPresenter(driver, readline);
    }

    const passed = results.filter((result) => result.status === 'PASS').length;
    const skipped = results.filter((result) => result.status === 'SKIP').length;
    const failedCount = results.filter((result) => result.status === 'FAIL').length;
    await driver.showOverlay({
      title: 'Demo complete',
      description: `${passed} passed · ${skipped} skipped · ${failedCount} failed`,
      status: 'FINAL',
      detail: failed ? 'Review the failed scene output in the terminal.' : 'All available scene checks passed.',
      current: selected.length,
      total: selected.length,
    });
    console.log(`Demo complete: ${passed} passed, ${skipped} skipped, ${failedCount} failed.`);
    if (failed) process.exitCode = 1;
    if (options.auto) await sleep(1000 / options.speed);
    else await waitForPresenter(driver, readline);
  } finally {
    if (readline) readline.close();
    try {
      await closeBrowser(port);
    } catch (error) {
      console.error(`demo: Chromium graceful shutdown failed: ${error.message}`);
    }
    cdp.close();
  }
}

main().catch((error) => {
  console.error(`demo director: ${error.message}`);
  process.exitCode = 1;
});