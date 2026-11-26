# Crypto — shares app + ledger server

## What this is
- **Crypto app** (`crypto.apk`, package `com.myapps.crypto`, v1): installable
  Android app. Each wallet creates its own address, registers once, and gets
  **1,000,000 shares**. First **1,000,000 wallets** only. Hard cap
  **1,000,000,000,000 shares** (1M wallets x 1M shares). Wallets send shares
  to each other; every register/transfer is signed on the phone, so nobody
  can move anyone else's shares. The private key never leaves the phone.
- **Ledger server** (`server/server.js`): the one shared source of truth
  every app talks to. SQLite (`ledger.db`), zero dependencies (node:http +
  node:sqlite + node:crypto). Enforces the 1M-wallet cap, the 1T supply cap,
  one registration per wallet, and per-wallet nonces (no replayed transfers).

The shares live on this ledger server. They are NOT a coin — the separate
Solana meme coin launch is not part of this app and nothing about it is in
the app.

## Run the server locally (for testing)
```
cd server && node server.js        # listens on :8787, creates ledger.db
curl http://127.0.0.1:8787/health
```
Tests: `node test_server.js` (18 checks: register, double-register,
bad signatures, transfers, nonce replay, overspend, stats, history) and
`node test_app.js` (16 checks driving the real app code in www/index.html
against a throwaway server).

## Put the server on the internet (required for real phones)
The app on a phone can only reach the server at a public `https://` URL.
Deploy it — the code is one file, no build step:
1. **Render (simplest):** push this folder to GitHub, then in Render:
   New -> Blueprint -> pick the repo. It reads `render.yaml` + `Dockerfile`.
   Free tier works for testing. Copy the URL Render gives you
   (looks like `https://crypto-ledger.onrender.com`).
2. **Fly.io (better for the real launch):** `fly launch` with the Dockerfile,
   then add a persistent volume for `ledger.db` so the share records survive
   restarts. Render's free tier disk is ephemeral — it forgets the ledger on
   restart — so for the real 1M-wallet launch use a host with a persistent
   disk (Fly volume, or Render paid with a disk).
3. In the Crypto app, go to **Settings -> Ledger server**, paste the URL,
   tap **Save server URL**, then **Test connection**. No reinstall needed —
   the URL is just a setting, so the server can move hosts anytime.

## App build
- Source: `www/index.html` (+ `www/vendor/web3.min.js`, `nacl.min.js`).
- Build: `bash build.sh` -> `~/workspace/crypto.apk` (own keystore
  `crypto-app/signing.jks`; same keystore across versions = installs as an
  update, wallet data survives).
- Icon: `assets/icon-512.png` (neon green "C" coin).
