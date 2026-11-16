import dgram from 'node:dgram';

const upstreamPort = Number(process.argv[2] ?? 18081);
const dnsPort = Number(process.argv[3] ?? 1053);

function makeQuery() {
  const labels = ['check', 'charlotte', 'test'];
  const name = Buffer.concat([
    ...labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0xface, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(4);
  question.writeUInt16BE(1, 0);
  question.writeUInt16BE(1, 2);
  return Buffer.concat([header, name, question]);
}

async function checkDns() {
  const socket = dgram.createSocket('udp4');
  const query = makeQuery();
  const response = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('demo DNS timeout')), 500);
    socket.once('message', (message) => {
      clearTimeout(timer);
      resolve(message);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.send(query, dnsPort, '127.0.0.1');
  }).finally(() => socket.close());
  return response.readUInt16BE(0) === 0xface
    && response.readUInt16BE(6) === 1
    && response.subarray(-4).equals(Buffer.from([127, 0, 0, 1]));
}

for (let attempt = 0; attempt < 50; attempt += 1) {
  try {
    const response = await fetch(`http://127.0.0.1:${upstreamPort}/ready`, {
      signal: AbortSignal.timeout(500),
    });
    const body = await response.json();
    if (response.headers.get('x-charlotte-demo-upstream') === 'local-node'
      && body.service === 'charlotte-local-upstream'
      && await checkDns()) {
      process.exit(0);
    }
  } catch {
    // Both listeners may still be starting.
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
}
process.exit(1);