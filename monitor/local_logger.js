'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Local audit logger — writes JSONL to two directories:
 *   local_only_logs/  — full command audit trail, never sent to any server
 *   server_send_logs/ — mirror of everything sent to PostHog/Supabase
 *
 * Daily file rotation: one file per day (YYYY-MM-DD.jsonl).
 * Append-only, non-blocking via setImmediate.
 */
module.exports = function createLocalLogger({ baseDir }) {
  const localDir = path.join(baseDir, 'local_only_logs');
  const serverDir = path.join(baseDir, 'server_send_logs');

  let localDirReady = false;
  let serverDirReady = false;

  function ensureDir(dir) {
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  }

  function appendLine(dir, entry, ensuredFlag) {
    const line = JSON.stringify(entry) + '\n';
    const dateStr = entry.ts.slice(0, 10);
    const file = path.join(dir, `${dateStr}.jsonl`);
    try {
      fs.appendFileSync(file, line, { flag: 'a' });
    } catch {
      ensureDir(dir);
      try { fs.appendFileSync(file, line, { flag: 'a' }); } catch {}
    }
  }

  /**
   * Log a local-only audit event. Never sent to any server.
   */
  function logLocal(event) {
    const entry = { ts: new Date().toISOString(), ...event };
    setImmediate(() => {
      if (!localDirReady) { ensureDir(localDir); localDirReady = true; }
      appendLine(localDir, entry);
    });
  }

  /**
   * Log a record of what was sent to an external server (PostHog/Supabase).
   */
  function logServerSend(event) {
    const entry = { ts: new Date().toISOString(), ...event };
    setImmediate(() => {
      if (!serverDirReady) { ensureDir(serverDir); serverDirReady = true; }
      appendLine(serverDir, entry);
    });
  }

  /**
   * List JSONL log files in a directory, filtered by date range.
   */
  function listLogFiles(dir, days) {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - days);
      const cutoffStr = cutoff.toISOString().slice(0, 10);
      return fs.readdirSync(dir)
        .filter(f => f.endsWith('.jsonl') && f.slice(0, 10) >= cutoffStr)
        .sort()
        .map(f => path.join(dir, f));
    } catch { return []; }
  }

  /**
   * Read events from JSONL files, newest first.
   */
  function readEvents(dir, { days = 7, limit = 500 } = {}) {
    const events = [];
    const files = listLogFiles(dir, days).reverse(); // newest files first
    for (const file of files) {
      let lines;
      try { lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean); } catch { continue; }
      for (let i = lines.length - 1; i >= 0; i--) {
        try { events.push(JSON.parse(lines[i])); } catch {}
        if (events.length >= limit) return events;
      }
    }
    return events;
  }

  function getLocalEvents(options) {
    return readEvents(localDir, options);
  }

  function getServerSendEvents(options) {
    return readEvents(serverDir, options);
  }

  return {
    logLocal,
    logServerSend,
    getLocalEvents,
    getServerSendEvents,
  };
};
