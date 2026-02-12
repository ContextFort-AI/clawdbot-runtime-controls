'use strict';

const path = require('path');
const os = require('os');

const HOME = os.homedir();
const PLUGIN_DIR = path.join(HOME, '.claude', 'plugins');

// Bare minimum for a Node.js process to function
const SANDBOX_KEEP_VARS = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME',
  'TMPDIR', 'TEMP', 'TMP',
  'LANG', 'LC_ALL', 'LC_CTYPE',
  'SHELL', 'TERM',
  'NODE_OPTIONS',           // so our hook loads in grandchild processes
  'NODE_PATH',              // module resolution
  '__CONTEXTFORT_SANDBOX',  // our marker
]);

const BLOCKED_DIRS = [
  path.join(HOME, '.ssh'),
  path.join(HOME, '.aws'),
  path.join(HOME, '.gnupg'),
  path.join(HOME, '.config'),
  path.join(HOME, '.contextfort'),
  path.join(HOME, '.npmrc'),
  path.join(HOME, '.netrc'),
  path.join(HOME, '.env'),
  path.join(HOME, '.bash_history'),
  path.join(HOME, '.zsh_history'),
  path.join(HOME, '.gitconfig'),
];

// Commands that can launch plugin code
const NODE_LIKE = new Set(['node', 'npx', 'tsx', 'bun']);

module.exports = function createPluginGuard({ localLogger, analytics }) {
  const track = analytics ? analytics.track.bind(analytics) : () => {};

  /**
   * Returns true if we're running inside a sandboxed plugin process.
   */
  function isSandboxed() {
    return !!process.env.__CONTEXTFORT_SANDBOX;
  }

  /**
   * Returns true if the spawn target is a plugin under ~/.claude/plugins/
   */
  function isPluginSpawn(command, args) {
    if (!command) return false;
    const cmd = path.basename(command);

    // Direct path under plugins dir
    try {
      const resolved = path.resolve(command);
      if (resolved.startsWith(PLUGIN_DIR + path.sep)) return true;
    } catch {}

    // node/npx/tsx/bun launching a file under plugins dir
    if (NODE_LIKE.has(cmd)) {
      if (Array.isArray(args)) {
        for (const arg of args) {
          if (typeof arg !== 'string') continue;
          if (arg.startsWith('-')) continue; // skip flags
          try {
            const resolved = path.resolve(arg);
            if (resolved.startsWith(PLUGIN_DIR + path.sep)) return true;
          } catch {}
        }
      }
    }

    return false;
  }

  /**
   * Returns a new env object with only SANDBOX_KEEP_VARS + the sandbox marker.
   * Logs the stripped variable names.
   */
  function scrubEnvForPlugin(originalEnv) {
    const scrubbed = {};
    const stripped = [];

    for (const key of Object.keys(originalEnv)) {
      if (SANDBOX_KEEP_VARS.has(key)) {
        scrubbed[key] = originalEnv[key];
      } else {
        stripped.push(key);
      }
    }

    scrubbed.__CONTEXTFORT_SANDBOX = '1';

    if (localLogger) {
      try {
        localLogger.logLocal({
          event: 'guard_check',
          guard: 'sandbox',
          decision: 'env_scrubbed',
          reason: `Scrubbed ${stripped.length} env vars from plugin process`,
          detail: {
            kept: Array.from(SANDBOX_KEEP_VARS),
            stripped_count: stripped.length,
            stripped_names: stripped,
          },
        });
      } catch {}
    }

    track('sandbox_env_scrubbed', { stripped_count: stripped.length });
    return scrubbed;
  }

  /**
   * Checks if a file path is blocked under the sandbox.
   * Returns null if allowed, { blocked: true, reason } if blocked.
   * Only active when isSandboxed() is true.
   */
  function checkFsAccess(filePath) {
    if (!isSandboxed()) return null;
    if (!filePath || typeof filePath !== 'string') return null;

    let resolved;
    try {
      resolved = path.resolve(String(filePath));
    } catch {
      return null;
    }

    for (const dir of BLOCKED_DIRS) {
      if (resolved === dir || resolved.startsWith(dir + path.sep)) {
        if (localLogger) {
          try {
            localLogger.logLocal({
              event: 'guard_check',
              guard: 'sandbox',
              decision: 'fs_blocked',
              reason: `Sandbox blocked read: ${resolved}`,
              detail: { path: resolved, blocked_dir: dir },
            });
          } catch {}
        }
        track('sandbox_fs_blocked', { path: resolved, blocked_dir: dir });
        return {
          blocked: true,
          reason: `SANDBOX: Access denied — ${resolved} is blocked for plugin processes`,
        };
      }
    }

    return null;
  }

  /**
   * Logs an outbound network request from a sandboxed plugin process.
   * Only active when isSandboxed() is true.
   */
  function logNetworkRequest(details) {
    if (!isSandboxed()) return;

    if (localLogger) {
      try {
        localLogger.logLocal({
          event: 'guard_check',
          guard: 'sandbox',
          decision: 'network_logged',
          reason: `Plugin network request: ${details.method || 'GET'} ${details.host || ''}${details.path || ''}`,
          detail: {
            host: details.host,
            port: details.port,
            method: details.method,
            path: details.path,
            protocol: details.protocol,
          },
        });
      } catch {}
    }

    track('sandbox_network', {
      host: details.host,
      port: details.port,
      method: details.method,
    });
  }

  return {
    isSandboxed,
    isPluginSpawn,
    scrubEnvForPlugin,
    checkFsAccess,
    logNetworkRequest,
  };
};
