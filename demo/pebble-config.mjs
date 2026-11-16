import { writeFile } from 'node:fs/promises';
import path from 'node:path';

const [destination, certificate, privateKey, httpPort = '8080', tlsPort = '8443'] = process.argv.slice(2);
if (!destination || !certificate || !privateKey) {
  throw new Error('usage: pebble-config.mjs DESTINATION CERTIFICATE PRIVATE_KEY [HTTP_PORT] [TLS_PORT]');
}

const config = {
  pebble: {
    listenAddress: '127.0.0.1:14000',
    managementListenAddress: '127.0.0.1:15000',
    certificate: path.resolve(certificate),
    privateKey: path.resolve(privateKey),
    httpPort: Number(httpPort),
    tlsPort: Number(tlsPort),
    ocspResponderURL: '',
    externalAccountBindingRequired: false,
  },
};
await writeFile(destination, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });