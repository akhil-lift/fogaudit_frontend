// fogaudit web front end: a tiny dependency-free server.
//   - serves web/index.html
//   - POST /api/run   (raw file bytes as the body, options in the query string) starts a REAL fogaudit run
//   - GET  /api/stream/:id   streams the program's output line by line (Server-Sent Events)
// Only one run at a time, because every run shares the build/ cache and the storage folders.
//
//   node web/server.js          then open http://127.0.0.1:3000
//   PORT=8080 HOST=0.0.0.0 node web/server.js    (listen on every interface; see README before exposing it)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'target', 'release', process.platform === 'win32' ? 'fogaudit.exe' : 'fogaudit');
const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_BLOCKS = 256;
const SECTORS = 4;
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;

const runs = new Map();
let current = null;

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
function intParam(q, key, def, lo, hi) {
  const v = q.get(key);
  if (v === null || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(`${key} must be an integer between ${lo} and ${hi}`);
  return n;
}
const safeName = (n) => (String(n || 'upload.bin').replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '') || 'upload.bin').slice(0, 60);

function emit(run, ev) {
  run.events.push(ev);
  for (const c of run.clients) c.write(`data: ${JSON.stringify(ev)}\n\n`);
}

function startRun(req, res, url) {
  if (!fs.existsSync(BIN)) {
    return json(res, 500, { error: 'The fogaudit binary is missing. Run "cargo build --release" in the project folder first.' });
  }
  if (!fs.existsSync(path.join(ROOT, 'zk', 'node_modules'))) {
    return json(res, 500, { error: 'Run "cd zk && npm install" first (snarkjs and circom are missing).' });
  }
  if (current && !current.done) return json(res, 409, { error: 'A run is already in progress. Wait for it to finish.' });

  let o;
  try {
    const q = url.searchParams;
    o = {
      name: safeName(q.get('name')),
      sectorBytes: intParam(q, 'sectorBytes', 31, 1, 31),
      batch: intParam(q, 'batch', 8, 1, 32),
      rounds: intParam(q, 'rounds', 3, 1, 10),
      pct: intParam(q, 'pct', 50, 1, 100),
      corrupt: q.get('corrupt') === null || q.get('corrupt') === '' ? null : intParam(q, 'corrupt', 0, 0, MAX_BLOCKS - 1),
      detail: intParam(q, 'detail', 3, 0, 20),
    };
  } catch (e) {
    return json(res, 400, { error: e.message });
  }
  const maxBytes = MAX_BLOCKS * SECTORS * o.sectorBytes;

  const chunks = [];
  let size = 0;
  let aborted = false;
  req.on('data', (c) => {
    size += c.length;
    if (size > maxBytes) {
      aborted = true;
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('close', () => {
    if (aborted && !res.writableEnded) json(res, 413, { error: `File too large: at most ${maxBytes} bytes with ${o.sectorBytes}-byte sectors.` });
  });
  req.on('end', () => {
    if (aborted) return;
    const data = Buffer.concat(chunks);
    if (data.length === 0) return json(res, 400, { error: 'The file is empty.' });
    fs.mkdirSync(path.join(ROOT, 'uploads'), { recursive: true });
    const file = path.join(ROOT, 'uploads', o.name);
    fs.writeFileSync(file, data);

    const args = [file, '--rounds', o.rounds, '--pct', o.pct, '--detail', o.detail, '--batch', o.batch, '--sector-bytes', o.sectorBytes];
    if (o.corrupt !== null) args.push('--corrupt', o.corrupt);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const run = { id, events: [], clients: new Set(), done: false, options: o, bytes: data.length };
    runs.set(id, run);
    current = run;
    if (runs.size > 20) runs.delete(runs.keys().next().value);

    const child = spawn(BIN, args.map(String), { cwd: ROOT });
    let buf = '';
    const feed = (chunk) => {
      buf += chunk.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        emit(run, { type: 'line', text: buf.slice(0, i).replace(ANSI, '').replace(/\r$/, '') });
        buf = buf.slice(i + 1);
      }
    };
    child.stdout.on('data', feed);
    child.stderr.on('data', feed);
    child.on('error', (e) => emit(run, { type: 'line', text: 'cannot start fogaudit: ' + e.message }));
    child.on('close', (code) => {
      if (buf) emit(run, { type: 'line', text: buf.replace(ANSI, '') });
      run.done = true;
      emit(run, { type: 'end', code });
      for (const c of run.clients) c.end();
    });
    json(res, 200, { id, bytes: data.length, options: o });
  });
}

function stream(req, res, id) {
  const run = runs.get(id);
  if (!run) return json(res, 404, { error: 'unknown run' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  for (const ev of run.events) res.write(`data: ${JSON.stringify(ev)}\n\n`);
  if (run.done) return res.end();
  run.clients.add(res);
  req.on('close', () => run.clients.delete(res));
}

http
  .createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    try {
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
      }
      if (req.method === 'POST' && url.pathname === '/api/run') return startRun(req, res, url);
      const m = url.pathname.match(/^\/api\/stream\/([\w-]+)$/);
      if (req.method === 'GET' && m) return stream(req, res, m[1]);
      if (req.method === 'GET' && url.pathname === '/api/status') return json(res, 200, { busy: !!(current && !current.done), binary: fs.existsSync(BIN) });
      json(res, 404, { error: 'not found' });
    } catch (e) {
      json(res, 500, { error: String(e.message || e) });
    }
  })
  .listen(PORT, HOST, () => {
    console.log(`fogaudit web front end: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    if (!fs.existsSync(BIN)) console.log('note: target/release/fogaudit not found yet. Run "cargo build --release" first.');
  });
