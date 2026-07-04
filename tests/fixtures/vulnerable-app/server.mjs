import { createHmac, randomBytes, createHash } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';
import { URL, URLSearchParams } from 'node:url';
import zlib from 'node:zlib';

const require = createRequire(import.meta.url);
const forge = require('node-forge');

const maxBodyBytes = 2 * 1024 * 1024;

export async function startVulnerableApp() {
  const state = {
    sessions: new Map(),
    ssrfCalls: [],
    websocketMessages: [],
  };
  const sockets = new Set();
  const handler = (request, response) => {
    handleRequest(request, response, state).catch((error) => {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'fixture_error', message: error.message }));
    });
  };

  const httpServer = http.createServer(handler);
  httpServer.on('connection', trackSocket(sockets));
  httpServer.on('upgrade', (request, socket) => handleWebSocketUpgrade(request, socket, state));

  const certificate = createSelfSignedCertificate();
  const httpsServer = https.createServer(certificate, handler);
  httpsServer.on('connection', trackSocket(sockets));

  await listen(httpServer);
  await listen(httpsServer);

  const httpPort = httpServer.address().port;
  const httpsPort = httpsServer.address().port;
  return {
    httpServer,
    httpsServer,
    httpUrl: `http://127.0.0.1:${httpPort}`,
    httpsUrl: `https://127.0.0.1:${httpsPort}`,
    wsUrl: `ws://127.0.0.1:${httpPort}/ws`,
    state,
    certificate,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await Promise.all([closeServer(httpServer), closeServer(httpsServer)]);
    },
  };
}

async function handleRequest(request, response, state) {
  const url = new URL(request.url ?? '/', `http://${request.headers.host ?? '127.0.0.1'}`);

  if (request.method === 'OPTIONS') {
    writeCorsPreflight(request, response);
    return;
  }

  if (request.method === 'GET' && url.pathname === '/') {
    sendHtml(response, 200, [
      '<main>',
      '<h1>ProxyForge vulnerable fixture</h1>',
      '<a href="/login">login</a>',
      '<a href="/reflected?input=fixture">reflected</a>',
      '<a href="/redirect?next=https://evil.example.test/callback">redirect</a>',
      '<script>window.__fixtureRoutes=["/graphql","/jwt","/ws","/api/idor/orders/ord-admin"];</script>',
      '</main>',
    ].join(''));
    return;
  }

  if (request.method === 'GET' && url.pathname === '/login') {
    const csrf = token('csrf');
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'set-cookie': `pf_login_csrf=${csrf}; Path=/; SameSite=Lax`,
    });
    response.end(`<form method="post" action="/login"><input name="csrf" value="${csrf}"><input name="username"><button>login</button></form>`);
    return;
  }

  if (request.method === 'POST' && url.pathname === '/login') {
    const body = new URLSearchParams((await readBody(request)).toString('utf8'));
    const username = body.get('username') || 'analyst';
    const requestedRole = body.get('role') === 'admin' ? 'admin' : 'user';
    const sessionId = token('sid');
    const csrf = token('csrf');
    state.sessions.set(sessionId, {
      id: sessionId,
      csrf,
      role: requestedRole,
      userId: requestedRole === 'admin' ? 'admin-1' : 'user-1001',
      username,
      createdAt: new Date().toISOString(),
    });
    sendJson(response, 200, {
      ok: true,
      role: requestedRole,
      csrf,
      sessionPreview: sessionId.slice(0, 12),
    }, {
      'set-cookie': [
        `pf_session=${sessionId}; HttpOnly; Path=/; SameSite=Lax`,
        `pf_csrf=${csrf}; Path=/; SameSite=Lax`,
      ],
    });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/profile') {
    const session = resolveSession(request, state);
    if (!session) {
      sendJson(response, 401, { error: 'login_required' });
      return;
    }
    sendJson(response, 200, {
      id: session.userId,
      username: session.username,
      role: session.role,
      csrf: session.csrf,
      apiToken: `fixture-token-${session.id}`,
      note: 'Raw tokens are intentionally present for execution-path fidelity tests.',
    });
    return;
  }

  if (request.method === 'GET' && url.pathname.startsWith('/api/admin/users/')) {
    const session = resolveSession(request, state);
    if (!session) {
      sendJson(response, 401, { error: 'login_required' });
      return;
    }
    if (session.role !== 'admin') {
      sendJson(response, 403, { error: 'admin_required', observedRole: session.role });
      return;
    }
    sendJson(response, 200, { id: url.pathname.split('/').pop(), role: 'admin', secret: 'admin-record-fixture' });
    return;
  }

  if (request.method === 'GET' && url.pathname.startsWith('/api/idor/orders/')) {
    const session = resolveSession(request, state);
    if (!session) {
      sendJson(response, 401, { error: 'login_required' });
      return;
    }
    sendJson(response, 200, {
      orderId: url.pathname.split('/').pop(),
      ownerId: 'admin-1',
      observedAs: session.userId,
      authorizationBypassCandidate: session.role !== 'admin',
    }, {
      'x-fixture-vulnerability': 'idor',
    });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/csrf/transfer') {
    const session = resolveSession(request, state);
    const body = (await readBody(request)).toString('utf8');
    const supplied = request.headers['x-csrf-token'];
    if (!session || supplied !== session.csrf) {
      sendJson(response, 403, { error: 'csrf_failed', supplied: supplied ?? null });
      return;
    }
    sendJson(response, 200, {
      ok: true,
      transferId: token('xfer'),
      bodySha256: createHash('sha256').update(body).digest('hex'),
    });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/reflected') {
    const input = url.searchParams.get('input') ?? '';
    sendHtml(response, 200, `<h1>Search</h1><output>${input}</output>`, {
      'x-fixture-vulnerability': 'reflected-input',
    });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/redirect') {
    response.writeHead(302, {
      location: url.searchParams.get('next') || '/',
      'x-fixture-vulnerability': 'open-redirect',
    });
    response.end();
    return;
  }

  if (request.method === 'GET' && url.pathname === '/cors') {
    sendJson(response, 200, { ok: true, origin: request.headers.origin ?? null }, {
      'access-control-allow-origin': request.headers.origin || '*',
      'access-control-allow-credentials': 'true',
      'x-fixture-vulnerability': 'cors-reflection',
    });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/graphql') {
    const body = (await readBody(request)).toString('utf8');
    if (body.includes('__schema')) {
      sendJson(response, 200, {
        data: {
          __schema: {
            queryType: { name: 'Query' },
            mutationType: { name: 'Mutation' },
            types: [{ name: 'Order' }, { name: 'User' }],
          },
        },
      }, { 'x-fixture-vulnerability': 'graphql-introspection' });
      return;
    }
    sendJson(response, 200, { data: { viewer: { id: 'user-1001' } } });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/jwt') {
    const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = base64url(JSON.stringify({
      sub: 'user-1001',
      role: 'support_admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
    }));
    const signature = createHmac('sha256', 'fixture-secret').update(`${header}.${payload}`).digest('base64url');
    sendJson(response, 200, { token: `${header}.${payload}.${signature}` });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/ssrf') {
    const callbackUrl = url.searchParams.get('url');
    if (!callbackUrl || !isAllowedLocalCallback(callbackUrl)) {
      sendJson(response, 400, { error: 'local_http_callback_required' });
      return;
    }
    const callback = await callLocalHttp(callbackUrl);
    state.ssrfCalls.push({ callbackUrl, statusCode: callback.statusCode, at: new Date().toISOString() });
    sendJson(response, 200, {
      ok: true,
      callbackUrl,
      callbackStatus: callback.statusCode,
    }, { 'x-fixture-vulnerability': 'ssrf-local-callback' });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/xxe') {
    const body = (await readBody(request)).toString('utf8');
    sendJson(response, 200, {
      parsed: true,
      externalEntityObserved: /<!ENTITY|SYSTEM/i.test(body),
      note: 'Fixture detects XXE syntax without reading local files.',
    }, { 'x-fixture-vulnerability': 'xxe-syntax' });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/binary') {
    const bytes = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
    response.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': bytes.length,
    });
    response.end(bytes);
    return;
  }

  if (request.method === 'GET' && url.pathname === '/chunked') {
    response.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'transfer-encoding': 'chunked',
    });
    response.write('chunk-one\n');
    response.write('chunk-two\n');
    response.end('chunk-three\n');
    return;
  }

  if (request.method === 'GET' && url.pathname === '/gzip') {
    const zipped = zlib.gzipSync(Buffer.from('gzip fixture body with token=gzip-secret-fixture'));
    response.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'content-encoding': 'gzip',
      'content-length': zipped.length,
    });
    response.end(zipped);
    return;
  }

  if (request.method === 'POST' && url.pathname === '/upload') {
    const body = await readBody(request);
    sendJson(response, 200, {
      contentType: request.headers['content-type'] ?? '',
      bytes: body.length,
      filenameObserved: body.includes(Buffer.from('filename="proof.bin"')),
      sha256: createHash('sha256').update(body).digest('hex'),
    });
    return;
  }

  sendJson(response, 404, { error: 'not_found', path: url.pathname });
}

function handleWebSocketUpgrade(request, socket, state) {
  const url = new URL(request.url ?? '/', `http://${request.headers.host ?? '127.0.0.1'}`);
  if (url.pathname !== '/ws') {
    socket.end('HTTP/1.1 404 Not Found\r\n\r\n');
    return;
  }
  const key = request.headers['sec-websocket-key'];
  if (!key) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }
  const accept = createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    '',
  ].join('\r\n'));
  socket.on('data', (chunk) => {
    for (const frame of decodeWebSocketFrames(chunk)) {
      state.websocketMessages.push({
        opcode: frame.opcode,
        payloadPreview: frame.opcode === 1 ? frame.payload.toString('utf8') : frame.payload.toString('hex'),
      });
      if (frame.opcode === 8) {
        socket.write(encodeWebSocketFrame(Buffer.alloc(0), 8));
        socket.end();
        return;
      }
      if (frame.opcode === 1) {
        const text = frame.payload.toString('utf8');
        if (text.trim().startsWith('{')) {
          const parsed = JSON.parse(text);
          socket.write(encodeWebSocketFrame(Buffer.from(JSON.stringify({
            op: parsed.op === 'ping' ? 'pong' : 'echo',
            received: parsed,
          })), 1));
          return;
        }
        socket.write(encodeWebSocketFrame(Buffer.from(`echo:${text}`), 1));
        return;
      }
      socket.write(encodeWebSocketFrame(frame.payload, frame.opcode));
    }
  });
}

function decodeWebSocketFrames(chunk) {
  const frames = [];
  let offset = 0;
  while (offset + 2 <= chunk.length) {
    const first = chunk[offset++];
    const second = chunk[offset++];
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let length = second & 0x7f;
    if (length === 126) {
      if (offset + 2 > chunk.length) break;
      length = chunk.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (offset + 8 > chunk.length) break;
      const high = chunk.readUInt32BE(offset);
      const low = chunk.readUInt32BE(offset + 4);
      length = high * 2 ** 32 + low;
      offset += 8;
    }
    const mask = masked ? chunk.subarray(offset, offset + 4) : Buffer.alloc(0);
    if (masked) offset += 4;
    if (offset + length > chunk.length) break;
    const payload = Buffer.from(chunk.subarray(offset, offset + length));
    offset += length;
    if (masked) {
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    frames.push({ opcode, payload });
  }
  return frames;
}

function encodeWebSocketFrame(payload, opcode = 1) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const headerLength = body.length < 126 ? 2 : body.length <= 0xffff ? 4 : 10;
  const frame = Buffer.alloc(headerLength + body.length);
  frame[0] = 0x80 | opcode;
  if (body.length < 126) {
    frame[1] = body.length;
    body.copy(frame, 2);
  } else if (body.length <= 0xffff) {
    frame[1] = 126;
    frame.writeUInt16BE(body.length, 2);
    body.copy(frame, 4);
  } else {
    frame[1] = 127;
    frame.writeUInt32BE(0, 2);
    frame.writeUInt32BE(body.length, 6);
    body.copy(frame, 10);
  }
  return frame;
}

function createSelfSignedCertificate() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomBytes(16).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const attrs = [{ name: 'commonName', value: 'ProxyForge Vulnerable Fixture' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' },
      ],
    },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
}

function resolveSession(request, state) {
  const cookies = parseCookies(request.headers.cookie ?? '');
  return state.sessions.get(cookies.pf_session);
}

function parseCookies(cookieHeader) {
  return Object.fromEntries(String(cookieHeader)
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const index = part.indexOf('=');
      return index === -1 ? [part, ''] : [part.slice(0, index), part.slice(index + 1)];
    }));
}

async function readBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBodyBytes) throw new Error('request body too large for fixture');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function sendHtml(response, statusCode, html, headers = {}) {
  response.writeHead(statusCode, {
    'content-type': 'text/html; charset=utf-8',
    ...headers,
  });
  response.end(html);
}

function writeCorsPreflight(request, response) {
  response.writeHead(204, {
    'access-control-allow-origin': request.headers.origin || '*',
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, x-csrf-token, authorization',
  });
  response.end();
}

function isAllowedLocalCallback(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  } catch {
    return false;
  }
}

function callLocalHttp(value) {
  return new Promise((resolve, reject) => {
    const request = http.get(value, (response) => {
      response.resume();
      response.on('end', () => resolve({ statusCode: response.statusCode ?? 0 }));
    });
    request.setTimeout(1500, () => {
      request.destroy(new Error('fixture callback timeout'));
    });
    request.on('error', reject);
  });
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function token(prefix) {
  return `${prefix}_${randomBytes(12).toString('hex')}`;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function trackSocket(sockets) {
  return (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  };
}
