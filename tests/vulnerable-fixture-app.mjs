import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { URL } from 'node:url';
import zlib from 'node:zlib';
import { startVulnerableApp } from './fixtures/vulnerable-app/server.mjs';

const app = await startVulnerableApp();
let callbackServer;

try {
  const landing = await request(`${app.httpUrl}/`);
  assert.equal(landing.statusCode, 200);
  assert.match(landing.text, /ProxyForge vulnerable fixture/);
  assert.match(landing.text, /__fixtureRoutes/);

  const login = await request(`${app.httpUrl}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=analyst&role=user',
  });
  assert.equal(login.statusCode, 200);
  const userCookies = cookieHeader(login.headers['set-cookie']);
  const userSession = JSON.parse(login.text);
  assert.equal(userSession.role, 'user');
  assert.match(userCookies, /pf_session=/);
  assert.match(userCookies, /pf_csrf=/);

  const adminLogin = await request(`${app.httpUrl}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=admin&role=admin',
  });
  const adminCookies = cookieHeader(adminLogin.headers['set-cookie']);

  const httpsProfile = await request(`${app.httpsUrl}/api/profile`, {
    headers: { cookie: userCookies },
    rejectUnauthorized: false,
  });
  assert.equal(httpsProfile.statusCode, 200);
  assert.match(httpsProfile.text, /fixture-token-/);

  const csrfBlocked = await request(`${app.httpUrl}/csrf/transfer`, {
    method: 'POST',
    headers: { cookie: userCookies, 'content-type': 'application/json' },
    body: '{"amount":25}',
  });
  assert.equal(csrfBlocked.statusCode, 403);

  const csrfAllowed = await request(`${app.httpUrl}/csrf/transfer`, {
    method: 'POST',
    headers: {
      cookie: userCookies,
      'content-type': 'application/json',
      'x-csrf-token': userSession.csrf,
    },
    body: '{"amount":25}',
  });
  assert.equal(csrfAllowed.statusCode, 200);
  assert.match(csrfAllowed.text, /bodySha256/);

  const adminDenied = await request(`${app.httpUrl}/api/admin/users/admin-1`, {
    headers: { cookie: userCookies },
  });
  assert.equal(adminDenied.statusCode, 403);

  const adminAllowed = await request(`${app.httpUrl}/api/admin/users/admin-1`, {
    headers: { cookie: adminCookies },
  });
  assert.equal(adminAllowed.statusCode, 200);

  const idor = await request(`${app.httpUrl}/api/idor/orders/ord-admin`, {
    headers: { cookie: userCookies },
  });
  assert.equal(idor.statusCode, 200);
  assert.equal(idor.headers['x-fixture-vulnerability'], 'idor');
  assert.equal(JSON.parse(idor.text).authorizationBypassCandidate, true);

  const reflected = await request(`${app.httpUrl}/reflected?input=%3Cscript%3Ealert(1)%3C/script%3E`);
  assert.equal(reflected.statusCode, 200);
  assert.match(reflected.text, /<script>alert\(1\)<\/script>/);

  const redirect = await request(`${app.httpUrl}/redirect?next=https://evil.example.test/callback`);
  assert.equal(redirect.statusCode, 302);
  assert.equal(redirect.headers.location, 'https://evil.example.test/callback');

  const cors = await request(`${app.httpUrl}/cors`, {
    headers: { origin: 'https://attacker.example.test' },
  });
  assert.equal(cors.statusCode, 200);
  assert.equal(cors.headers['access-control-allow-origin'], 'https://attacker.example.test');
  assert.equal(cors.headers['access-control-allow-credentials'], 'true');

  const graphql = await request(`${app.httpUrl}/graphql`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"query":"{ __schema { queryType { name } } }"}',
  });
  assert.equal(graphql.statusCode, 200);
  assert.match(graphql.text, /__schema/);

  const jwt = await request(`${app.httpUrl}/jwt`);
  assert.equal(jwt.statusCode, 200);
  const token = JSON.parse(jwt.text).token;
  assert.equal(token.split('.').length, 3);

  const callbackHits = [];
  callbackServer = http.createServer((request_, response) => {
    callbackHits.push(request_.url);
    response.writeHead(204);
    response.end();
  });
  await listen(callbackServer);
  const callbackPort = callbackServer.address().port;
  const callbackToken = `oast-${Date.now()}`;
  const ssrf = await request(`${app.httpUrl}/ssrf?url=${encodeURIComponent(`http://127.0.0.1:${callbackPort}/hit/${callbackToken}`)}`);
  assert.equal(ssrf.statusCode, 200);
  assert.deepEqual(callbackHits, [`/hit/${callbackToken}`]);
  assert.equal(app.state.ssrfCalls.length, 1);

  const binary = await request(`${app.httpUrl}/binary`);
  assert.equal(binary.statusCode, 200);
  assert.equal(binary.body.length, 256);
  assert.equal(binary.body[255], 255);

  const chunked = await request(`${app.httpUrl}/chunked`);
  assert.equal(chunked.statusCode, 200);
  assert.match(chunked.text, /chunk-one[\s\S]*chunk-three/);

  const gzip = await request(`${app.httpUrl}/gzip`);
  assert.equal(gzip.statusCode, 200);
  assert.equal(gzip.headers['content-encoding'], 'gzip');
  assert.match(zlib.gunzipSync(gzip.body).toString('utf8'), /gzip-secret-fixture/);

  const boundary = '----proxyforgefixture';
  const multipartBody = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="proof"; filename="proof.bin"',
    'Content-Type: application/octet-stream',
    '',
    'proof-body',
    `--${boundary}--`,
    '',
  ].join('\r\n');
  const upload = await request(`${app.httpUrl}/upload`, {
    method: 'POST',
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
    body: multipartBody,
  });
  assert.equal(upload.statusCode, 200);
  assert.equal(JSON.parse(upload.text).filenameObserved, true);

  const xxe = await request(`${app.httpUrl}/xxe`, {
    method: 'POST',
    headers: { 'content-type': 'application/xml' },
    body: '<!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>',
  });
  assert.equal(xxe.statusCode, 200);
  assert.equal(JSON.parse(xxe.text).externalEntityObserved, true);

  await exerciseWebSocket(app.wsUrl);

  console.log('vulnerable-fixture-app: verified HTTP, HTTPS, auth, CSRF, CORS, GraphQL, JWT, OAST, IDOR, multipart, binary, gzip, chunked, XXE syntax, and WebSocket fixture coverage');
} finally {
  if (callbackServer?.listening) await closeServer(callbackServer);
  await app.close();
}

function request(urlString, options = {}) {
  const url = new URL(urlString);
  const transport = url.protocol === 'https:' ? https : http;
  const body = options.body ? Buffer.from(options.body) : undefined;
  const headers = {
    ...(options.headers ?? {}),
    ...(body ? { 'content-length': body.length } : {}),
  };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`request timeout: ${urlString}`));
    }, options.timeoutMs ?? 3000);
    const request_ = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      method: options.method ?? 'GET',
      path: `${url.pathname}${url.search}`,
      headers,
      rejectUnauthorized: options.rejectUnauthorized ?? true,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const responseBody = Buffer.concat(chunks);
        resolve({
          statusCode: response.statusCode,
          headers: response.headers,
          body: responseBody,
          text: responseBody.toString('utf8'),
        });
        clearTimeout(timer);
      });
    });
    request_.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    if (body) request_.write(body);
    request_.end();
  });
}

async function exerciseWebSocket(wsUrl) {
  const url = new URL(wsUrl);
  const socket = net.connect(Number(url.port), url.hostname);
  try {
    await once(socket, 'connect');
    const reader = createSocketReader(socket);
    const key = randomBytes(16).toString('base64');
    socket.write([
      `GET ${url.pathname} HTTP/1.1`,
      `Host: ${url.host}`,
      'Connection: Upgrade',
      'Upgrade: websocket',
      'Sec-WebSocket-Version: 13',
      `Sec-WebSocket-Key: ${key}`,
      '',
      '',
    ].join('\r\n'));
    const handshake = await reader.readUntil('\r\n\r\n');
    assert.match(handshake.toString('utf8'), /101 Switching Protocols/);

    socket.write(encodeClientFrame(Buffer.from(JSON.stringify({ op: 'ping', nonce: 'fixture' })), 1));
    const pong = JSON.parse((await readFrame(reader)).payload.toString('utf8'));
    assert.equal(pong.op, 'pong');
    assert.equal(pong.received.nonce, 'fixture');

    const binary = Buffer.from([0, 1, 2, 3, 254, 255]);
    socket.write(encodeClientFrame(binary, 2));
    const echoed = await readFrame(reader);
    assert.equal(echoed.opcode, 2);
    assert.deepEqual(echoed.payload, binary);
  } finally {
    socket.destroy();
  }
}

function encodeClientFrame(payload, opcode = 1) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const headerLength = body.length < 126 ? 6 : body.length <= 0xffff ? 8 : 14;
  const frame = Buffer.alloc(headerLength + body.length);
  frame[0] = 0x80 | opcode;
  const maskOffset = body.length < 126 ? 2 : body.length <= 0xffff ? 4 : 10;
  if (body.length < 126) {
    frame[1] = 0x80 | body.length;
  } else if (body.length <= 0xffff) {
    frame[1] = 0x80 | 126;
    frame.writeUInt16BE(body.length, 2);
  } else {
    frame[1] = 0x80 | 127;
    frame.writeUInt32BE(0, 2);
    frame.writeUInt32BE(body.length, 6);
  }
  const mask = randomBytes(4);
  mask.copy(frame, maskOffset);
  for (let index = 0; index < body.length; index += 1) {
    frame[maskOffset + 4 + index] = body[index] ^ mask[index % 4];
  }
  return frame;
}

async function readFrame(reader) {
  const first = await reader.readExactly(2);
  const opcode = first[0] & 0x0f;
  let length = first[1] & 0x7f;
  if (length === 126) {
    length = (await reader.readExactly(2)).readUInt16BE(0);
  } else if (length === 127) {
    const extended = await reader.readExactly(8);
    length = extended.readUInt32BE(0) * 2 ** 32 + extended.readUInt32BE(4);
  }
  const payload = await reader.readExactly(length);
  return { opcode, payload };
}

function createSocketReader(socket) {
  let buffer = Buffer.alloc(0);
  const pending = new Set();
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (const flush of pending) flush();
  });

  function readExactly(byteCount) {
    if (buffer.length >= byteCount) return Promise.resolve(take(byteCount));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(flush);
        reject(new Error(`socket read timeout waiting for ${byteCount} bytes`));
      }, 3000);
      const flush = () => {
        if (buffer.length < byteCount) return;
        pending.delete(flush);
        clearTimeout(timer);
        resolve(take(byteCount));
      };
      pending.add(flush);
      flush();
    });
  }

  function readUntil(delimiter) {
    const delimiterBytes = Buffer.from(delimiter);
    const index = buffer.indexOf(delimiterBytes);
    if (index !== -1) return Promise.resolve(take(index + delimiterBytes.length));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(flush);
        reject(new Error(`socket read timeout waiting for ${delimiter}`));
      }, 3000);
      const flush = () => {
        const nextIndex = buffer.indexOf(delimiterBytes);
        if (nextIndex === -1) return;
        pending.delete(flush);
        clearTimeout(timer);
        resolve(take(nextIndex + delimiterBytes.length));
      };
      pending.add(flush);
      flush();
    });
  }

  function take(byteCount) {
    const chunk = buffer.subarray(0, byteCount);
    buffer = buffer.subarray(byteCount);
    return chunk;
  }

  return { readExactly, readUntil };
}

function cookieHeader(setCookieHeaders = []) {
  return setCookieHeaders.map((value) => value.split(';')[0]).join('; ');
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function once(emitter, event) {
  return new Promise((resolve, reject) => {
    emitter.once(event, resolve);
    emitter.once('error', reject);
  });
}
