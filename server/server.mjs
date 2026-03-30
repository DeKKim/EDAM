import express from 'express';
import cors from 'cors';
import net from 'net';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 8787);

function isValidIp(ip) {
  // Minimal validation: accept IPv4 or IPv6 literal.
  return typeof ip === 'string' && ip.length > 0 && ip.length < 80 && (ip.includes('.') || ip.includes(':'));
}

function isValidPort(p) {
  return Number.isInteger(p) && p > 0 && p <= 65535;
}

function checkTcpPort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;

    const finish = (open) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(open);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));

    // IPv6 needs host to be literal; net.connect handles both.
    socket.connect(port, ip);
  });
}

async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let idx = 0;

  async function runner() {
    while (true) {
      const current = idx++;
      if (current >= items.length) return;
      results[current] = await worker(items[current], current);
    }
  }

  const workers = Array.from({ length: Math.max(1, limit) }, () => runner());
  await Promise.all(workers);
  return results;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/port-scan', async (req, res) => {
  const {
    ips = [],
    ports = [],
    timeoutMs = 800,
    concurrency = 120,
  } = req.body || {};

  const ipList = Array.isArray(ips) ? ips.filter(isValidIp).slice(0, 200) : [];
  const portList = Array.isArray(ports)
    ? ports.map((p) => Number(p)).filter(isValidPort).slice(0, 200)
    : [];

  if (ipList.length === 0 || portList.length === 0) {
    return res.status(400).json({ error: 'ips and ports are required' });
  }

  const pairs = [];
  for (const ip of ipList) {
    for (const port of portList) {
      pairs.push({ ip, port });
    }
  }

  const limit = Math.max(1, Math.min(400, Number(concurrency) || 120));
  const t = Math.max(150, Math.min(5000, Number(timeoutMs) || 800));

  const openPairs = await runWithConcurrency(pairs, limit, async ({ ip, port }) => {
    const open = await checkTcpPort(ip, port, t);
    return open ? { ip, port } : null;
  });

  const openByIp = {};
  for (const item of openPairs) {
    if (!item) continue;
    if (!openByIp[item.ip]) openByIp[item.ip] = [];
    openByIp[item.ip].push(item.port);
  }

  for (const ip of Object.keys(openByIp)) {
    openByIp[ip].sort((a, b) => a - b);
  }

  res.json({
    ips: ipList.length,
    ports: portList.length,
    timeoutMs: t,
    concurrency: limit,
    openByIp,
  });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[edam] port-scan backend listening on http://localhost:${PORT}`);
});

