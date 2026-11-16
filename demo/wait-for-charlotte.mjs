import http from 'node:http';

const port = Number(process.argv[2] ?? 8080);

function request() {
  return new Promise((resolve) => {
    const req = http.get({
      hostname: '127.0.0.1',
      port,
      path: '/',
      headers: {
        Host: 'charlotte.test',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Fetch-Mode': 'navigate',
      },
      timeout: 500,
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve(response.statusCode === 200 && body.includes('Charlotte live feature demo')));
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

for (let attempt = 0; attempt < 80; attempt += 1) {
  if (await request()) process.exit(0);
  await new Promise((resolve) => setTimeout(resolve, 100));
}
process.exit(1);