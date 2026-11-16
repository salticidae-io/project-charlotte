import http from 'node:http';
import dgram from 'node:dgram';
import net from 'node:net';

const upstreamPort = Number(process.env.CHARLOTTE_DEMO_UPSTREAM_PORT ?? 18081);
const dnsPort = Number(process.env.CHARLOTTE_DEMO_DNS_PORT ?? 1053);

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

const upstream = http.createServer((request, response) => {
  const forwardedHeaders = Object.entries(request.headers)
    .filter(([name]) => name.startsWith('x-forwarded-') || name === 'via')
    .map(([name, value]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join('');
  if ((request.headers.accept ?? '').includes('text/html')) {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'x-charlotte-demo-upstream': 'local-node',
    });
    response.end(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Local upstream | Charlotte demo</title>
<body><main><h1>Response from charlotte-local-upstream</h1>
<p>Charlotte forwarded this browser request to the separate Node service.</p>
<dl><dt>Method</dt><dd>${escapeHtml(request.method)}</dd>
<dt>Path</dt><dd>${escapeHtml(request.url)}</dd>
<dt>Host</dt><dd>${escapeHtml(request.headers.host)}</dd>${forwardedHeaders}</dl></main></body></html>`);
    return;
  }
  response.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'x-charlotte-demo-upstream': 'local-node',
  });
  response.end(JSON.stringify({
    service: 'charlotte-local-upstream',
    host: request.headers.host,
    path: request.url,
    method: request.method,
  }));
});

upstream.listen(upstreamPort, '127.0.0.1');

function answerQuery(query) {
  if (query.length < 17) return null;
  const questions = query.readUInt16BE(4);
  if (questions < 1) return null;

  const labels = [];
  let offset = 12;
  while (offset < query.length) {
    const length = query[offset++];
    if (length === 0) break;
    if ((length & 0xc0) !== 0 || offset + length > query.length) return null;
    labels.push(query.toString('ascii', offset, offset + length));
    offset += length;
  }
  if (offset + 4 > query.length) return null;
  const questionEnd = offset + 4;
  const name = labels.join('.').toLowerCase();
  const type = query.readUInt16BE(offset);
  const klass = query.readUInt16BE(offset + 2);
  const isDemoName = name === 'charlotte.test' || name.endsWith('.charlotte.test');
  const hasAddress = isDemoName && type === 1 && klass === 1;

  const answer = hasAddress
    ? Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 127, 0, 0, 1])
    : Buffer.alloc(0);
  const response = Buffer.alloc(12 + questionEnd - 12 + answer.length);
  query.copy(response, 0, 0, questionEnd);
  response.writeUInt16BE(query.readUInt16BE(0), 0);
  response.writeUInt16BE(0x8180, 2);
  response.writeUInt16BE(1, 4);
  response.writeUInt16BE(hasAddress ? 1 : 0, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(0, 10);
  if (answer.length) answer.copy(response, questionEnd);
  return response;
}

const dns = dgram.createSocket('udp4');
dns.on('message', (query, remote) => {
  try {
    const response = answerQuery(query);
    if (response) dns.send(response, remote.port, remote.address);
  } catch (error) {
    process.stderr.write(`demo DNS responder: ${error.message}\n`);
  }
});
dns.bind(dnsPort, '127.0.0.1');

// Pebble resolves challenge hostnames over TCP, so DNS is served on both transports.
const dnsTcp = net.createServer((socket) => {
  let pending = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 2) {
      const length = pending.readUInt16BE(0);
      if (pending.length < 2 + length) break;
      const query = pending.subarray(2, 2 + length);
      pending = pending.subarray(2 + length);
      try {
        const response = answerQuery(query);
        if (!response) {
          socket.destroy();
          return;
        }
        const prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(response.length, 0);
        socket.write(Buffer.concat([prefix, response]));
      } catch (error) {
        process.stderr.write(`demo DNS responder: ${error.message}\n`);
        socket.destroy();
        return;
      }
    }
  });
  socket.on('error', () => {});
});
dnsTcp.listen(dnsPort, '127.0.0.1');

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    upstream.close();
    dns.close();
    dnsTcp.close();
    process.exit(0);
  });
}