'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const url = require('url');

const CONFIG_DIR = path.join(os.homedir(), '.contextfort');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

module.exports = function startDashboard({ port = 9009 } = {}) {
  const localLogger = require('../local_logger')({ baseDir: CONFIG_DIR });
  const publicDir = path.join(__dirname, 'public');
  const { spawnSync } = require('child_process');
  const packageDir = path.join(__dirname, '..', '..');
  const secretsGuard = require('../secrets_guard')({ spawnSync, baseDir: packageDir, analytics: null });
  const exfilGuard = require('../exfil_guard')({ analytics: null, localLogger: null, readFileSync: fs.readFileSync });
  exfilGuard.init();
  let lastScanResult = null; // holds full scan results (including rawFull) in memory

  const server = http.createServer((req, res) => {
    const parsed = url.parse(req.url, true);
    const pathname = parsed.pathname;

    // CORS for local dev
    res.setHeader('Access-Control-Allow-Origin', '*');

    // API routes
    if (pathname === '/api/overview') return apiOverview(res, parsed.query);
    if (pathname === '/api/events') return apiEvents(res, parsed.query);
    if (pathname === '/api/scan' && req.method === 'GET') return apiScanResults(res);
    if (pathname === '/api/scan' && req.method === 'POST') return apiRunScan(req, res);
    if (pathname === '/api/solve' && req.method === 'POST') return apiSolve(req, res);
    if (pathname === '/api/skill/delete' && req.method === 'POST') return apiDeleteSkill(req, res);
    if (pathname === '/api/unblock' && req.method === 'POST') return apiUnblock(req, res);
    if (pathname === '/api/anthropic-key' && req.method === 'GET') return apiGetAnthropicKey(res);
    if (pathname === '/api/anthropic-key' && req.method === 'POST') return apiSetAnthropicKey(req, res);
    if (pathname === '/api/exfil-allowlist' && req.method === 'GET') return apiGetExfilAllowlist(res);
    if (pathname === '/api/exfil-allowlist' && req.method === 'POST') return apiUpdateExfilAllowlist(req, res);

    // Static file serving
    let filePath = pathname === '/' ? '/index.html' : pathname;
    filePath = path.join(publicDir, filePath);

    // Prevent directory traversal
    if (!filePath.startsWith(publicDir)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    try {
      const content = fs.readFileSync(filePath);
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(content);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  function json(res, data) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  function apiOverview(res, query) {
    const days = parseInt(query.days) || 7;
    const events = localLogger.getLocalEvents({ days, limit: 50000 });

    // Total commands = commands that passed all guards (command_check) + commands blocked by any guard (guard_check with decision=block)
    const allowed = events.filter(e => e.event === 'command_check').length;
    const blocked = events.filter(e => e.event === 'guard_check' && e.decision === 'block').length;
    const total = allowed + blocked;
    const redacted = events.filter(e => e.event === 'output_redacted').length;

    const byGuard = {};
    for (const e of events) {
      if (e.event === 'guard_check' && e.decision === 'block' && e.blocker) {
        byGuard[e.blocker] = (byGuard[e.blocker] || 0) + 1;
      }
    }

    // Find earliest hook_loaded for "active since"
    let activeSince = null;
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].event === 'hook_loaded') { activeSince = events[i].ts; break; }
    }

    const exfilDetections = events.filter(e => e.event === 'guard_check' && e.guard === 'exfil').length;
    const secretsLeaked = events.filter(e => e.event === 'guard_check' && e.guard === 'secrets_leak').length;

    const sandboxScrubs = events.filter(e => e.guard === 'sandbox' && e.decision === 'env_scrubbed').length;
    const sandboxFsBlocks = events.filter(e => e.guard === 'sandbox' && e.decision === 'fs_blocked').length;
    const sandboxNetLogs = events.filter(e => e.guard === 'sandbox' && e.decision === 'network_logged').length;

    const guardStatus = {
      skill_scanner: { blocks: byGuard.skill || 0, active: true },
      bash_guard: { blocks: byGuard.tirith || 0, active: true },
      prompt_injection: { blocks: byGuard.prompt_injection || 0, active: true },
      secrets_guard: { blocks: (byGuard.env_var || 0), redactions: redacted, leaks: secretsLeaked, active: true },
      exfil_monitor: { detections: exfilDetections, active: true },
      plugin_sandbox: { scrubs: sandboxScrubs, fs_blocks: sandboxFsBlocks, net_logs: sandboxNetLogs, active: true },
    };

    json(res, { total, blocked, allowed, redacted, byGuard, guardStatus, activeSince });
  }

  function apiEvents(res, query) {
    const type = query.type || 'local';
    const days = parseInt(query.days) || 7;
    const limit = Math.min(parseInt(query.limit) || 500, 5000);

    const events = type === 'server_send'
      ? localLogger.getServerSendEvents({ days, limit })
      : localLogger.getLocalEvents({ days, limit });

    json(res, { events });
  }

  function apiScanResults(res) {
    const installed = secretsGuard.isTrufflehogInstalled();
    let freshFindings = null;
    if (lastScanResult && lastScanResult.findings) {
      freshFindings = {
        targets: lastScanResult.targets,
        summary: lastScanResult.summary,
        findings: lastScanResult.findings.map((f, i) => ({
          index: i,
          detectorName: f.detectorName,
          verified: f.verified,
          raw: f.raw,
          file: f.file,
          line: f.line,
          scanTarget: f.scanTarget,
        })),
      };
    }
    json(res, { installed, scanning: scanInProgress, fresh: freshFindings });
  }

  let scanInProgress = true; // starts true — auto-scan kicks off on server start
  let currentWorker = null;

  function startScan() {
    // Kill any running scan
    if (currentWorker) {
      try { currentWorker.kill(); } catch {}
      currentWorker = null;
    }

    const { fork } = require('child_process');
    const worker = fork(path.join(__dirname, 'scan-worker.js'), [], {
      stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
    });

    currentWorker = worker;
    scanInProgress = true;

    worker.send({ onlyVerified: true, cwd: process.cwd() });

    worker.on('message', (msg) => {
      scanInProgress = false;
      currentWorker = null;
      if (msg.type === 'result') {
        lastScanResult = msg.data;
      }
    });

    worker.on('error', () => { scanInProgress = false; currentWorker = null; });
    worker.on('exit', () => { scanInProgress = false; currentWorker = null; });

    // Safety timeout — 5 minutes
    setTimeout(() => {
      if (scanInProgress && currentWorker === worker) {
        scanInProgress = false;
        currentWorker = null;
        try { worker.kill(); } catch {}
      }
    }, 300000);
  }

  function apiRunScan(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      startScan();
      json(res, { status: 'scanning' });
    });
  }

  function apiSolve(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { indices } = JSON.parse(body);
        if (!lastScanResult || !lastScanResult.findings) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No scan data. Wait for the auto-scan to complete or run a scan first.' }));
          return;
        }
        const selectedFindings = (indices || [])
          .filter(i => i >= 0 && i < lastScanResult.findings.length)
          .map(i => lastScanResult.findings[i]);
        if (selectedFindings.length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No valid findings selected.' }));
          return;
        }
        const results = secretsGuard.solve(selectedFindings);
        lastScanResult = null; // invalidate since files changed
        json(res, { results });
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  }

  function apiUnblock(req, res) {
    try {
      // Write unblock flag file — the hook checks for this
      const unblockFile = path.join(CONFIG_DIR, 'unblock');
      fs.writeFileSync(unblockFile, new Date().toISOString() + '\n');
      // Log the event
      localLogger.logLocal({ event: 'block_removed', reason: 'Block removed via dashboard' });
      json(res, { success: true });
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  }

  function apiDeleteSkill(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { skillPath } = JSON.parse(body);
        if (!skillPath || typeof skillPath !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing skillPath' }));
          return;
        }
        // Safety: only allow deleting from known skill directories
        const home = os.homedir();
        const allowed = [
          path.join(home, '.openclaw', 'skills'),
          path.join(home, '.claude', 'skills'),
          path.join(home, '.claude', 'plugins'),
        ];
        const resolved = path.resolve(skillPath);
        if (!allowed.some(d => resolved.startsWith(d))) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Path not in allowed skill directories' }));
          return;
        }
        // Recursively delete the skill directory
        fs.rmSync(resolved, { recursive: true, force: true });
        localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'deleted', reason: `Skill deleted via dashboard: ${path.basename(resolved)}`, detail: { skill_name: path.basename(resolved), skill_path: resolved } });
        json(res, { success: true, deleted: resolved });
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  }

  function apiGetAnthropicKey(res) {
    const keyFile = path.join(CONFIG_DIR, 'anthropic_key');
    let fromEnv = !!process.env.ANTHROPIC_API_KEY;
    let fromFile = false;
    try { const k = fs.readFileSync(keyFile, 'utf8').trim(); if (k) fromFile = true; } catch {}
    json(res, { hasKey: fromEnv || fromFile, source: fromEnv ? 'env' : fromFile ? 'file' : 'none' });
  }

  function apiSetAnthropicKey(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { key } = JSON.parse(body);
        if (!key || typeof key !== 'string' || !key.startsWith('sk-ant-')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid key format. Must start with sk-ant-' }));
          return;
        }
        const keyFile = path.join(CONFIG_DIR, 'anthropic_key');
        try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); } catch {}
        fs.writeFileSync(keyFile, key.trim(), { mode: 0o600 });
        json(res, { success: true, message: 'Key saved. Restart openclaw for it to take effect.' });
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  }

  function apiGetExfilAllowlist(res) {
    const al = exfilGuard.getAllowlist();
    json(res, al || { enabled: false, domains: [] });
  }

  function apiUpdateExfilAllowlist(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { action, domain } = JSON.parse(body);
        const al = exfilGuard.getAllowlist() || { enabled: false, domains: [] };

        if (action === 'add' && domain && typeof domain === 'string') {
          if (!al.domains.includes(domain)) al.domains.push(domain);
          al.enabled = true;
          exfilGuard.saveAllowlist(al);
          json(res, { success: true, allowlist: exfilGuard.getAllowlist() });
        } else if (action === 'remove' && domain) {
          al.domains = al.domains.filter(d => d !== domain);
          exfilGuard.saveAllowlist(al);
          json(res, { success: true, allowlist: exfilGuard.getAllowlist() });
        } else if (action === 'enable') {
          al.enabled = true;
          exfilGuard.saveAllowlist(al);
          json(res, { success: true, allowlist: exfilGuard.getAllowlist() });
        } else if (action === 'disable') {
          al.enabled = false;
          exfilGuard.saveAllowlist(al);
          json(res, { success: true, allowlist: exfilGuard.getAllowlist() });
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid action. Use: add, remove, enable, disable' }));
        }
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
  }

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n  Port ${port} is already in use. Try: openclaw-secure dashboard --port=9010\n`);
      process.exit(1);
    }
    throw err;
  });

  // Auto-scan on startup — same as clicking "Run Scan"
  function autoScan() {
    if (!secretsGuard.isTrufflehogInstalled()) return;
    startScan();
  }

  server.listen(port, '127.0.0.1', () => {
    console.log(`\n  ContextFort Security Dashboard`);
    console.log(`  http://localhost:${port}`);

    // Kick off auto-scan
    autoScan();

    // Try to start a cloudflared quick tunnel
    server._tunnel = null;
    try {
      const { spawn } = require('child_process');
      const cf = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${port}`], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      server._tunnel = cf;

      let urlFound = false;
      const extractUrl = (data) => {
        if (urlFound) return;
        const text = data.toString();
        const match = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
        if (match) {
          urlFound = true;
          console.log(`  ${match[0]}  (public tunnel)\n`);
          console.log(`  Press Ctrl+C to stop.\n`);
        }
      };
      cf.stdout.on('data', extractUrl);
      cf.stderr.on('data', extractUrl);

      // If tunnel fails or no URL found after 10s, show fallback
      setTimeout(() => {
        if (!urlFound) {
          console.log(`  (tunnel unavailable — local only)\n`);
          console.log(`  Press Ctrl+C to stop.\n`);
        }
      }, 10000);

      cf.on('error', () => {
        if (!urlFound) {
          console.log(`  (cloudflared not found — local only)\n`);
          console.log(`  Press Ctrl+C to stop.\n`);
        }
      });
    } catch {
      console.log(`\n  Press Ctrl+C to stop.\n`);
    }
  });

  return server;
};
