// Crypto app — small shares ledger server.
// One source of truth for every Crypto app install:
//   * first 1,000,000 wallets to register each get 1,000,000 shares
//   * hard cap: 1,000,000,000,000 shares total (1M wallets x 1M shares)
//   * wallets send shares to each other; every transfer is signed with the
//     sender's own key, so nobody can move anyone else's shares.
// The private key NEVER leaves the phone. The server only ever sees the
// public address and an ed25519 signature over the exact request.
// Storage: SQLite (ledger.db next to this file) — survives restarts.
// Zero external dependencies: node:http + node:sqlite + node:crypto only.

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8787);
const DB_PATH = process.env.LEDGER_DB || path.join(__dirname, 'ledger.db');

const SHARES_PER_WALLET = 1_000_000;
const MAX_WALLETS = 1_000_000;
const TOTAL_SUPPLY = 1_000_000_000_000;

// ---------- base58 (for addresses + signatures) ----------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  if (typeof s !== 'string' || !s) throw new Error('empty base58 value');
  const bytes = [0];
  for (const ch of s.trim()) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('bad base58 character');
    let carry = v;
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  let zeros = 0; while (zeros < s.length && s[zeros] === '1') zeros++;
  const out = Buffer.alloc(zeros + bytes.length);
  bytes.reverse().forEach((b, i) => { out[zeros + i] = b; });
  return out;
}
function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b !== 0) break; s = '1' + s; }
  return s || '1';
}

// ---------- ed25519 verify (built-in node crypto) ----------
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verifySig(addressB58, message, signatureB58) {
  const pub = b58decode(addressB58);
  const sig = b58decode(signatureB58);
  if (pub.length !== 32) throw new Error('address is not 32 bytes');
  if (sig.length !== 64) throw new Error('signature is not 64 bytes');
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(message, 'utf8'), key, sig);
}

// ---------- database ----------
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS wallets (
    address TEXT PRIMARY KEY,
    balance INTEGER NOT NULL,
    wallet_number INTEGER NOT NULL UNIQUE,
    next_nonce INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    amount INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_transfers_from ON transfers(from_addr);
  CREATE INDEX IF NOT EXISTS idx_transfers_to ON transfers(to_addr);
`);

const qCount = db.prepare('SELECT COUNT(*) AS n FROM wallets');
const qIssued = db.prepare('SELECT COALESCE(SUM(balance), 0) AS s FROM wallets');
const qWallet = db.prepare('SELECT * FROM wallets WHERE address = ?');
const qInsertWallet = db.prepare('INSERT INTO wallets (address, balance, wallet_number, next_nonce, created_at) VALUES (?, ?, ?, 1, ?)');
const qUpdateFrom = db.prepare('UPDATE wallets SET balance = balance - ?, next_nonce = next_nonce + 1 WHERE address = ?');
const qUpdateTo = db.prepare('UPDATE wallets SET balance = balance + ? WHERE address = ?');
const qInsertTransfer = db.prepare('INSERT INTO transfers (from_addr, to_addr, amount, nonce, ts) VALUES (?, ?, ?, ?, ?)');
const qHistory = db.prepare('SELECT id, from_addr AS "from", to_addr AS "to", amount, ts FROM transfers WHERE from_addr = ? OR to_addr = ? ORDER BY id DESC LIMIT ?');

// node:sqlite has no .transaction() helper (that's better-sqlite3), so wrap
// mutations in BEGIN IMMEDIATE / COMMIT / ROLLBACK ourselves.
function runTx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw e;
  }
}

function stats() {
  const totalWallets = qCount.get().n;
  const totalIssued = qIssued.get().s;
  return {
    sharesPerWallet: SHARES_PER_WALLET,
    maxWallets: MAX_WALLETS,
    totalSupply: TOTAL_SUPPLY,
    totalWallets,
    totalIssued,
    remaining: TOTAL_SUPPLY - totalIssued,
    walletsRemaining: MAX_WALLETS - totalWallets,
  };
}

// ---------- http helpers ----------
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 10240) reject(new Error('body too large')); });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { reject(new Error('bad JSON')); }
    });
    req.on('error', reject);
  });
}
function validAddress(a) {
  try { return typeof a === 'string' && b58decode(a).length === 32; } catch { return false; }
}
function validAmount(n) { return Number.isInteger(n) && n > 0 && n <= TOTAL_SUPPLY; }

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  console.log(new Date().toISOString(), req.method, p);
  if (req.method === 'OPTIONS') return send(res, 204, {});
  try {
    if (req.method === 'GET' && p === '/') {
      const s = stats();
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<!doctype html><title>Crypto ledger</title><body style="font-family:sans-serif;background:#0b0618;color:#e8e8f0;padding:24px"><h1>Crypto shares ledger — live</h1><p>Wallets registered: <b>${s.totalWallets.toLocaleString()}</b> / 1,000,000</p><p>Shares issued: <b>${s.totalIssued.toLocaleString()}</b> / 1,000,000,000,000</p><p>Shares remaining: <b>${s.remaining.toLocaleString()}</b></p><p>Each new wallet gets 1,000,000 shares. First come, first served.</p></body>`);
    }
    if (req.method === 'GET' && p === '/health') return send(res, 200, { ok: true, service: 'crypto-ledger', ...stats() });
    if (req.method === 'GET' && p === '/stats') return send(res, 200, stats());
    if (req.method === 'GET' && p === '/balance') {
      const address = url.searchParams.get('address') || '';
      if (!validAddress(address)) return send(res, 400, { error: 'bad address' });
      const w = qWallet.get(address);
      if (!w) return send(res, 200, { registered: false, balance: 0, walletNumber: null, nextNonce: 1 });
      return send(res, 200, { registered: true, balance: w.balance, walletNumber: w.wallet_number, nextNonce: w.next_nonce });
    }
    if (req.method === 'GET' && p === '/history') {
      const address = url.searchParams.get('address') || '';
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '20', 10) || 20, 1), 100);
      if (!validAddress(address)) return send(res, 400, { error: 'bad address' });
      const rows = qHistory.all(address, address, limit);
      return send(res, 200, { transfers: rows });
    }
    if (req.method === 'POST' && p === '/register') {
      const { address, signature } = await readBody(req);
      if (!validAddress(address)) return send(res, 400, { error: 'bad address' });
      if (typeof signature !== 'string' || !signature) return send(res, 400, { error: 'missing signature' });
      let ok = false;
      try { ok = verifySig(address, `crypto-register:${address}`, signature); } catch { ok = false; }
      if (!ok) return send(res, 401, { error: 'bad signature — the request must be signed by this wallet' });
      const out = runTx(() => {
        const existing = qWallet.get(address);
        if (existing) return { alreadyRegistered: true, balance: existing.balance, walletNumber: existing.wallet_number, ...stats() };
        const s = stats();
        if (s.totalWallets >= MAX_WALLETS) throw Object.assign(new Error('signup closed — all 1,000,000 wallets are claimed'), { code: 403 });
        if (s.totalIssued + SHARES_PER_WALLET > TOTAL_SUPPLY) throw Object.assign(new Error('supply cap reached'), { code: 403 });
        const num = s.totalWallets + 1;
        qInsertWallet.run(address, SHARES_PER_WALLET, num, Date.now());
        return { registered: true, balance: SHARES_PER_WALLET, walletNumber: num, ...stats() };
      });
      return send(res, 200, out);
    }
    if (req.method === 'POST' && p === '/transfer') {
      const { from, to, amount, nonce, signature } = await readBody(req);
      if (!validAddress(from) || !validAddress(to)) return send(res, 400, { error: 'bad address' });
      if (!validAmount(amount)) return send(res, 400, { error: 'amount must be a whole number of shares above 0' });
      if (!Number.isInteger(nonce) || nonce < 1) return send(res, 400, { error: 'bad nonce' });
      if (from === to) return send(res, 400, { error: 'cannot send shares to yourself' });
      if (typeof signature !== 'string' || !signature) return send(res, 400, { error: 'missing signature' });
      let ok = false;
      try { ok = verifySig(from, `crypto-transfer:${from}:${to}:${amount}:${nonce}`, signature); } catch { ok = false; }
      if (!ok) return send(res, 401, { error: 'bad signature — the transfer must be signed by the sending wallet' });
      const out = runTx(() => {
        const sender = qWallet.get(from);
        if (!sender) throw Object.assign(new Error('sender wallet is not registered yet'), { code: 404 });
        if (nonce !== sender.next_nonce) throw Object.assign(new Error(`stale nonce — expected ${sender.next_nonce}`), { code: 409 });
        const recip = qWallet.get(to);
        if (!recip) throw Object.assign(new Error('recipient wallet is not registered yet'), { code: 404 });
        if (amount > sender.balance) throw Object.assign(new Error('insufficient shares'), { code: 400 });
        qUpdateFrom.run(amount, from);
        qUpdateTo.run(amount, to);
        qInsertTransfer.run(from, to, amount, nonce, Date.now());
        const s2 = qWallet.get(from); const r2 = qWallet.get(to);
        return { ok: true, fromBalance: s2.balance, toBalance: r2.balance, nonce, ...stats() };
      });
      return send(res, 200, out);
    }
    return send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('ERR', e);
    return send(res, e.code || 500, { error: e.message || 'server error' });
  }
}

const server = http.createServer(handle);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`crypto-ledger listening on :${PORT} — db ${DB_PATH}`);
  console.log('cap:', TOTAL_SUPPLY.toLocaleString(), 'shares =', MAX_WALLETS.toLocaleString(), 'wallets x', SHARES_PER_WALLET.toLocaleString());
});
