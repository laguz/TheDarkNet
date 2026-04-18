const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const Hypercore = require('hypercore');
const Hyperswarm = require('hyperswarm');
const b4a = require('b4a');
const { nip19, getPublicKey } = require('nostr-tools');

const appDir = path.join(os.homedir(), 'Library', 'Application Support', 'TheDarkNet');

// Read seed from nsec
function readSeed() {
  const nsecPath = path.join(appDir, 'nsec');
  let nsec = process.env.TDN_NSEC || '';
  if (!nsec) {
    try {
      nsec = fs.readFileSync(nsecPath, 'utf8').trim();
    } catch (err) {
      console.error('Failed to read nsec file', err);
      process.exit(1);
    }
  }

  let seed;
  if (nsec.startsWith('nsec1')) {
    const decoded = nip19.decode(nsec);
    if (decoded.type !== 'nsec') {
      console.error('Invalid nsec prefix');
      process.exit(1);
    }
    seed = b4a.from(decoded.data, 'hex');
  } else {
    seed = b4a.from(nsec, 'hex');
  }
  return seed;
}

const seed = readSeed();
const npubHex = getPublicKey(seed);

console.log('Hyperd sidecar starting for npub:', npubHex);

// Initialize Hypercore + Hyperswarm
const dataDir = path.join(appDir, 'hyperd-data');
const core = new Hypercore(dataDir, {
  keyPair: { secretKey: seed, publicKey: b4a.from(npubHex, 'hex') }
});

const swarm = new Hyperswarm({ preferIpv6: true });
swarm.on('connection', (conn, info) => {
  const remotePub = b4a.toString(info.publicKey, 'hex');
  console.log('New connection from:', remotePub);
  // Just keeping the connection alive is enough for Holepunch
  // WireGuard will use the UDP endpoint discovered.
  conn.on('error', () => {});
});

const topic = b4a.alloc(32).fill('thedarknet-mesh-v1');
const discovery = swarm.join(topic);

// Unix Server for Agent
const sockPath = path.join(appDir, 'hyperd.sock');
if (fs.existsSync(sockPath)) {
  fs.unlinkSync(sockPath);
}

const server = net.createServer((socket) => {
  socket.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg === 'get-peers') {
      const peers = [];
      for (const [key, peer] of swarm.connections.entries()) {
        if (!peer.remotePublicKey) continue;
        const npub = b4a.toString(peer.remotePublicKey, 'hex');

        // Use hyperswarm/dht connection info to get the UDP endpoint
        // It's accessible via peer.remoteHost / peer.remotePort if available,
        // but hyperswarm wraps it. Let's look into info or connection.
        // Actually info.serverAddress is populated if it's a server connection, but we want the UDP endpoint.
        // Hyperswarm connections are noise streams over hyperdht.
        // HyperDHT connection has `remoteHost` and `remotePort`.

        const host = peer.rawStream?.remoteHost || peer.remoteHost;
        const port = peer.rawStream?.remotePort || peer.remotePort;

        if (host && port) {
          const endpoint = `${host}:${port}`;
          peers.push({ npub, endpoint });
        }
      }
      socket.write(JSON.stringify(peers) + '\n');
    }
  });
});

server.listen(sockPath, () => {
  console.log('Listening on unix socket:', sockPath);
});

process.on('SIGINT', () => {
  swarm.destroy();
  server.close();
  process.exit(0);
});
