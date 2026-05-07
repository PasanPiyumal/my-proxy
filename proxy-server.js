const net = require('node:net');

const LISTEN_PORT = Number.parseInt(process.env.PROXY_PORT || '1080', 10);
const USERNAME = process.env.PROXY_USERNAME || 'proxyuser';
const PASSWORD = process.env.PROXY_PASSWORD || 'proxypass';

const SOCKS_VERSION = 0x05;
const AUTH_VERSION = 0x01;
const METHOD_USERNAME_PASSWORD = 0x02;
const CMD_CONNECT = 0x01;

const REPLY = {
  SUCCESS: 0x00,
  GENERAL_FAILURE: 0x01,
  CONNECTION_NOT_ALLOWED: 0x02,
  NETWORK_UNREACHABLE: 0x03,
  HOST_UNREACHABLE: 0x04,
  CONNECTION_REFUSED: 0x05,
  TTL_EXPIRED: 0x06,
  COMMAND_NOT_SUPPORTED: 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED: 0x08,
};

function parseAddress(buffer, offset) {
  if (buffer.length <= offset) return null;

  const atyp = buffer[offset];
  let next = offset + 1;

  if (atyp === 0x01) {
    if (buffer.length < next + 4 + 2) return null;
    const host = `${buffer[next]}.${buffer[next + 1]}.${buffer[next + 2]}.${buffer[next + 3]}`;
    next += 4;
    const port = buffer.readUInt16BE(next);
    next += 2;
    return { atyp, host, port, nextOffset: next };
  }

  if (atyp === 0x03) {
    if (buffer.length < next + 1) return null;
    const len = buffer[next];
    next += 1;
    if (buffer.length < next + len + 2) return null;
    const host = buffer.slice(next, next + len).toString('utf8');
    next += len;
    const port = buffer.readUInt16BE(next);
    next += 2;
    return { atyp, host, port, nextOffset: next };
  }

  if (atyp === 0x04) {
    if (buffer.length < next + 16 + 2) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(buffer.readUInt16BE(next + i).toString(16));
    }
    const host = parts.join(':');
    next += 16;
    const port = buffer.readUInt16BE(next);
    next += 2;
    return { atyp, host, port, nextOffset: next };
  }

  return { atyp, unsupported: true };
}

function encodeBoundAddress(socket) {
  const addr = socket.localAddress || '0.0.0.0';
  const port = socket.localPort || 0;

  if (net.isIPv4(addr)) {
    const ip = addr.split('.').map((octet) => Number.parseInt(octet, 10));
    return Buffer.from([0x01, ...ip, (port >> 8) & 0xff, port & 0xff]);
  }

  if (net.isIPv6(addr)) {
    const raw = addr.replace('::', ':0:').split(':');
    const expanded = [];
    for (const chunk of raw) {
      if (chunk === '') continue;
      expanded.push(chunk);
    }
    while (expanded.length < 8) expanded.splice(expanded.length - 1, 0, '0');
    const bytes = [];
    for (const part of expanded.slice(0, 8)) {
      const value = Number.parseInt(part || '0', 16);
      bytes.push((value >> 8) & 0xff, value & 0xff);
    }
    return Buffer.from([0x04, ...bytes, (port >> 8) & 0xff, port & 0xff]);
  }

  return Buffer.from([0x01, 0, 0, 0, 0, (port >> 8) & 0xff, port & 0xff]);
}

function sendSocksReply(client, code, boundSocket) {
  const bound = boundSocket
    ? encodeBoundAddress(boundSocket)
    : Buffer.from([0x01, 0, 0, 0, 0, 0, 0]);
  client.write(Buffer.concat([Buffer.from([SOCKS_VERSION, code, 0x00]), bound]));
}

function createConnectionHandler() {
  return function onClientConnected(client) {
    let state = 'greeting';
    let buffered = Buffer.alloc(0);
    let upstream = null;

    client.on('error', () => {
      if (upstream) upstream.destroy();
    });

    client.on('close', () => {
      if (upstream) upstream.destroy();
    });

    client.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);

      while (true) {
        if (state === 'greeting') {
          if (buffered.length < 2) return;

          const ver = buffered[0];
          const methodCount = buffered[1];
          if (buffered.length < 2 + methodCount) return;

          if (ver !== SOCKS_VERSION) {
            client.end();
            return;
          }

          const methods = buffered.slice(2, 2 + methodCount);
          buffered = buffered.slice(2 + methodCount);

          if (!methods.includes(METHOD_USERNAME_PASSWORD)) {
            client.write(Buffer.from([SOCKS_VERSION, 0xff]));
            client.end();
            return;
          }

          client.write(Buffer.from([SOCKS_VERSION, METHOD_USERNAME_PASSWORD]));
          state = 'auth';
          continue;
        }

        if (state === 'auth') {
          if (buffered.length < 2) return;

          const ver = buffered[0];
          const userLen = buffered[1];
          if (buffered.length < 2 + userLen + 1) return;

          const userStart = 2;
          const passLenIndex = userStart + userLen;
          const passLen = buffered[passLenIndex];
          if (buffered.length < passLenIndex + 1 + passLen) return;

          const username = buffered.slice(userStart, userStart + userLen).toString('utf8');
          const password = buffered
            .slice(passLenIndex + 1, passLenIndex + 1 + passLen)
            .toString('utf8');

          buffered = buffered.slice(passLenIndex + 1 + passLen);

          const valid = ver === AUTH_VERSION && username === USERNAME && password === PASSWORD;
          client.write(Buffer.from([AUTH_VERSION, valid ? 0x00 : 0x01]));

          if (!valid) {
            client.end();
            return;
          }

          state = 'request';
          continue;
        }

        if (state === 'request') {
          if (buffered.length < 4) return;

          const ver = buffered[0];
          const cmd = buffered[1];
          const atyp = buffered[3];

          if (ver !== SOCKS_VERSION) {
            client.end();
            return;
          }

          if (cmd !== CMD_CONNECT) {
            sendSocksReply(client, REPLY.COMMAND_NOT_SUPPORTED);
            client.end();
            return;
          }

          const parsed = parseAddress(buffered, 3);
          if (!parsed) return;

          if (parsed.unsupported || parsed.atyp !== atyp) {
            sendSocksReply(client, REPLY.ADDRESS_TYPE_NOT_SUPPORTED);
            client.end();
            return;
          }

          buffered = buffered.slice(parsed.nextOffset);

          const sourceIp = client.remoteAddress || 'unknown';
          const sourcePort = client.remotePort || 0;
          console.log(
            `${new Date().toISOString()} | src=${sourceIp}:${sourcePort} -> dest=${parsed.host}:${parsed.port}`,
          );

          upstream = net.createConnection({ host: parsed.host, port: parsed.port });

          upstream.once('connect', () => {
            sendSocksReply(client, REPLY.SUCCESS, upstream);

            if (buffered.length > 0) {
              upstream.write(buffered);
              buffered = Buffer.alloc(0);
            }

            state = 'tunnel';
            client.pipe(upstream);
            upstream.pipe(client);
          });

          upstream.once('error', (err) => {
            const code = err && err.code === 'ECONNREFUSED'
              ? REPLY.CONNECTION_REFUSED
              : REPLY.HOST_UNREACHABLE;
            sendSocksReply(client, code);
            client.end();
          });

          upstream.once('close', () => {
            client.end();
          });

          return;
        }

        return;
      }
    });
  };
}

const server = net.createServer(createConnectionHandler());

server.on('error', (err) => {
  console.error('SOCKS5 server error:', err);
});

server.listen(LISTEN_PORT, () => {
  console.log(`SOCKS5 proxy listening on 0.0.0.0:${LISTEN_PORT}`);
  console.log(`Authentication username: ${USERNAME}`);
  console.log(`Authentication password: ${PASSWORD}`);
});
