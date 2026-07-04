// Tests: SOCKS5 inbound proxy — greeting, auth method negotiation, CONNECT
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import net from 'node:net';

const require = createRequire(import.meta.url);
const { SocksServer } = require('../dist-electron/traffic/socksInbound.js');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function connectTcp(port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

function readBytes(socket, count) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    const onData = (chunk) => {
      chunks.push(chunk);
      received += chunk.length;
      if (received >= count) {
        socket.removeListener('data', onData);
        socket.removeListener('error', onError);
        resolve(Buffer.concat(chunks).slice(0, count));
      }
    };
    const onError = (err) => {
      socket.removeListener('data', onData);
      reject(err);
    };
    socket.on('data', onData);
    socket.once('error', onError);
  });
}

function writeAndRead(socket, data, expectedBytes) {
  const p = readBytes(socket, expectedBytes);
  socket.write(data);
  return p;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve) => {
    server.close(() => resolve());
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

const socks = new SocksServer();

try {
  // ── Test 1: No-auth greeting ───────────────────────────────────────────────
  await socks.start({ port: 0, host: '127.0.0.1', requireAuth: false });
  const { port: socksPort } = socks.address();

  {
    const s = await connectTcp(socksPort);
    // VER=5, NMETHODS=1, METHOD=0x00 (NO AUTH)
    const greeting = Buffer.from([0x05, 0x01, 0x00]);
    const reply = await writeAndRead(s, greeting, 2);
    assert.equal(reply[0], 0x05, 'Server version should be 5');
    assert.equal(reply[1], 0x00, 'Server should select NO AUTH method');
    s.destroy();
  }

  // ── Test 2: Server advertises user/pass, client offers it, no-auth accepted too ─
  {
    const s = await connectTcp(socksPort);
    // Offer both NO AUTH and USER/PASS
    const greeting = Buffer.from([0x05, 0x02, 0x00, 0x02]);
    const reply = await writeAndRead(s, greeting, 2);
    assert.equal(reply[0], 0x05);
    // Server prefers NO_AUTH when requireAuth=false
    assert.equal(reply[1], 0x00, 'Server should pick NO AUTH when not requiring auth');
    s.destroy();
  }

  // ── Test 3: No acceptable method ──────────────────────────────────────────
  {
    const s = await connectTcp(socksPort);
    // Only offer GSSAPI (0x01) — not supported
    const greeting = Buffer.from([0x05, 0x01, 0x01]);
    const reply = await writeAndRead(s, greeting, 2);
    assert.equal(reply[0], 0x05);
    assert.equal(reply[1], 0xff, 'Server should respond 0xff when no acceptable method');
    s.destroy();
  }

  await socks.stop();

  // ── Test 4: Auth-required server — correct credentials ────────────────────
  const authSocks = new SocksServer();
  await authSocks.start({
    port: 0,
    host: '127.0.0.1',
    requireAuth: true,
    username: 'proxyuser',
    password: 's3cr3t',
  });
  const { port: authPort } = authSocks.address();

  {
    const s = await connectTcp(authPort);
    // Greeting offering USER/PASS
    const greetReply = await writeAndRead(s, Buffer.from([0x05, 0x01, 0x02]), 2);
    assert.equal(greetReply[0], 0x05);
    assert.equal(greetReply[1], 0x02, 'Auth server should select USER/PASS method');

    // Sub-negotiation: VER=1, ULEN, UNAME, PLEN, PASSWD
    const uname = Buffer.from('proxyuser');
    const passwd = Buffer.from('s3cr3t');
    const authMsg = Buffer.concat([
      Buffer.from([0x01, uname.length]),
      uname,
      Buffer.from([passwd.length]),
      passwd,
    ]);
    const authReply = await writeAndRead(s, authMsg, 2);
    assert.equal(authReply[0], 0x01, 'Auth sub-version should be 1');
    assert.equal(authReply[1], 0x00, 'Auth should succeed (status=0)');
    s.destroy();
  }

  // ── Test 5: Auth-required server — wrong credentials ──────────────────────
  {
    const s = await connectTcp(authPort);
    await writeAndRead(s, Buffer.from([0x05, 0x01, 0x02]), 2);

    const uname = Buffer.from('wrong');
    const passwd = Buffer.from('bad');
    const authMsg = Buffer.concat([
      Buffer.from([0x01, uname.length]),
      uname,
      Buffer.from([passwd.length]),
      passwd,
    ]);
    const authReply = await writeAndRead(s, authMsg, 2);
    assert.equal(authReply[1], 0x01, 'Auth should fail with status=1 for bad credentials');
    s.destroy();
  }

  await authSocks.stop();

  // ── Test 6: CONNECT command — domain address type ─────────────────────────
  // Stand up a target TCP echo server
  const target = net.createServer((sock) => {
    sock.on('data', (d) => sock.write(`echo:${d}`));
  });
  const targetPort = await listen(target);

  const connectSocks = new SocksServer();
  const connections = [];
  connectSocks.onConnection = (info) => connections.push(info);
  await connectSocks.start({ port: 0, host: '127.0.0.1', requireAuth: false });
  const { port: connectPort } = connectSocks.address();

  {
    const s = await connectTcp(connectPort);

    // Greeting
    await writeAndRead(s, Buffer.from([0x05, 0x01, 0x00]), 2);

    // CONNECT to 127.0.0.1:targetPort via domain ATYP
    const host = Buffer.from('127.0.0.1');
    const request = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
      host,
      (() => { const b = Buffer.allocUnsafe(2); b.writeUInt16BE(targetPort, 0); return b; })(),
    ]);

    // Reply is at least 10 bytes (VER REP RSV ATYP BND.ADDR(4) BND.PORT(2))
    const reply = await writeAndRead(s, request, 10);
    assert.equal(reply[0], 0x05, 'Reply version should be 5');
    assert.equal(reply[1], 0x00, 'CONNECT should succeed (REP=0)');

    // Now the tunnel is open — send data and expect echo
    const echoReply = await new Promise((resolve, reject) => {
      const chunks = [];
      s.on('data', (chunk) => {
        chunks.push(chunk);
        const all = Buffer.concat(chunks).toString('utf8');
        if (all.includes('echo:hello')) resolve(all);
      });
      s.once('error', reject);
      s.write('hello');
    });

    assert.match(echoReply, /echo:hello/, 'Data should be tunneled through SOCKS5 CONNECT');
    s.destroy();

    assert.equal(connections.length, 1, 'onConnection callback should have been called');
    assert.equal(connections[0].targetHost, '127.0.0.1');
    assert.equal(connections[0].targetPort, targetPort);
  }

  await connectSocks.stop();
  await close(target);

  console.log('PASS traffic-socks-inbound');
} catch (err) {
  await socks.stop().catch(() => undefined);
  console.error('FAIL traffic-socks-inbound:', err.message);
  process.exit(1);
}
