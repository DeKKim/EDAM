import { createServer } from 'http';
import { createReadStream, existsSync, statSync } from 'fs';
import { extname, join, normalize, resolve } from 'path';
import { fileURLToPath } from 'url';
import net from 'net';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const projectRoot = resolve(__dirname, '..');
const distRoot = resolve(projectRoot, 'dist');
const PORT = Number(process.env.PORT || 5173);
const HOST = process.env.HOST || '127.0.0.1';

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

function isValidIp(ip) {
  return typeof ip === 'string' && ip.length > 0 && ip.length < 80 && (ip.includes('.') || ip.includes(':'));
}

function isValidPort(p) {
  return Number.isInteger(p) && p > 0 && p <= 65535;
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolveBody, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolveBody(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function checkTcpPort(ip, port, timeoutMs) {
  return new Promise((resolveOpen) => {
    const socket = new net.Socket();
    let done = false;

    const finish = (open) => {
      if (done) return;
      done = true;
      socket.unref();
      socket.destroy();
      resolveOpen(open);
    };

    const connTimer = setTimeout(() => finish(false), timeoutMs);

    socket.once('connect', () => {
      clearTimeout(connTimer);
      finish(true);
    });
    socket.once('timeout', () => {
      clearTimeout(connTimer);
      finish(false);
    });
    socket.once('error', () => {
      clearTimeout(connTimer);
      finish(false);
    });

    try {
      socket.connect(port, ip);
    } catch {
      clearTimeout(connTimer);
      finish(false);
    }
  });
}

async function runWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let idx = 0;

  async function runner() {
    while (true) {
      const current = idx++;
      if (current >= items.length) return;
      results[current] = await worker(items[current]);
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, limit) }, runner));
  return results;
}

async function handlePortScan(req, res) {
  let body;
  try {
    body = await readJson(req);
  } catch (err) {
    sendJson(res, 400, { error: err.message });
    return;
  }

  const {
    ips = [],
    ports = [],
    timeoutMs = 2000,
    concurrency = 250,
  } = body || {};

  const ipList = Array.isArray(ips) ? ips.filter(isValidIp).slice(0, 200) : [];
  const portList = Array.isArray(ports) ? ports.map((p) => Number(p)).filter(isValidPort) : [];

  if (ipList.length === 0 || portList.length === 0) {
    sendJson(res, 400, { error: 'ips and ports are required' });
    return;
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

  sendJson(res, 200, {
    ips: ipList.length,
    ports: portList.length,
    timeoutMs: t,
    concurrency: limit,
    openByIp,
  });
}

function serveStatic(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const requestedPath = decodeURIComponent(url.pathname);
  const normalizedPath = normalize(requestedPath).replace(/^(\.\.[/\\])+/, '');
  let filePath = resolve(distRoot, `.${normalizedPath}`);

  if (!filePath.startsWith(distRoot)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
    filePath = join(distRoot, 'index.html');
  }

  if (!existsSync(filePath)) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Missing dist/index.html. Run npm install and npm run build on your own machine before the presentation.');
    return;
  }

  const ext = extname(filePath).toLowerCase();
  res.writeHead(200, {
    'content-type': mimeTypes[ext] || 'application/octet-stream',
  });
  createReadStream(filePath).pipe(res);
}

const server = createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/api/health') {
    sendJson(res, 200, { ok: true, mode: 'presentation' });
    return;
  }

  if (req.method === 'POST' && req.url === '/api/port-scan') {
    void handlePortScan(req, res);
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    serveStatic(req, res);
    return;
  }

  sendJson(res, 405, { error: 'Method not allowed' });
});

server.listen(PORT, HOST, () => {
  console.log(`[edam] presentation server running at http://${HOST}:${PORT}`);
});
