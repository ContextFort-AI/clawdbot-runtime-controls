'use strict';

// Worker process for running TruffleHog scans without blocking the dashboard event loop.
// Communicates with parent via IPC (process.send).

const { spawnSync } = require('child_process');
const path = require('path');

const packageDir = path.join(__dirname, '..', '..');
const secretsGuard = require('../secrets_guard')({ spawnSync, baseDir: packageDir, analytics: null });

process.on('message', (msg) => {
  try {
    const { onlyVerified, cwd } = msg;
    const result = secretsGuard.scan(cwd || process.cwd(), { onlyVerified: onlyVerified !== false });
    process.send({ type: 'result', data: result });
  } catch (e) {
    process.send({ type: 'error', error: e.message });
  }
  process.exit(0);
});
