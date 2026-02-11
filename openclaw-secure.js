const path = require('path');
const fs = require('fs');
const Module = require('module');

const _originalSpawnSync = require('child_process').spawnSync;
const _originalReadFileSync = fs.readFileSync;
const _originalHttpsRequest = require('https').request;

const os = require('os');
const MONITOR_PY = path.join(__dirname, 'monitor', 'monitor.py');
const MONITOR_CWD = path.join(__dirname, 'monitor');
const CONFIG_DIR = path.join(os.homedir(), '.contextfort');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config');
const PREFS_FILE = path.join(CONFIG_DIR, 'preferences.json');

function loadPreferences() {
  try { return JSON.parse(_originalReadFileSync(PREFS_FILE, 'utf8')); } catch { return {}; }
}
const PREFS = loadPreferences();
const SKILL_DELIVER = PREFS.skillDeliver !== false; // default true

// === Local Audit Logger ===
const localLogger = require('./monitor/local_logger')({ baseDir: CONFIG_DIR });

// === Analytics ===
const analytics = require('./monitor/analytics')({
  httpsRequest: _originalHttpsRequest,
  readFileSync: _originalReadFileSync,
  baseDir: __dirname,
  localLogger,
});
localLogger.logLocal({ event: 'hook_loaded' });
analytics.track('hook_loaded');

function loadApiKey() {
  try {
    const raw = _originalReadFileSync(CONFIG_FILE, 'utf8').trim();
    if (raw.startsWith('{')) {
      const parsed = JSON.parse(raw);
      return parsed.api_key || parsed.apiKey || parsed.key || null;
    }
    return raw || null;
  } catch { return null; }
}
const API_KEY = loadApiKey();

const NO_KEY_MESSAGE = `SECURITY FIREWALL -- No API key configured. ALL agent actions are blocked.
Get your API key at https://contextfort.ai/login and run:
  openclaw-secure set-key <your-key>
Then restart your openclaw session.`;

function checkApiKey() {
  if (!API_KEY) return { blocked: true, reason: NO_KEY_MESSAGE };
  return null;
}

// === Skill Scanner ===
const skillsGuard = require('./monitor/skills_guard')({
  readFileSync: _originalReadFileSync,
  httpsRequest: _originalHttpsRequest,
  baseDir: __dirname,
  apiKey: API_KEY,
  analytics,
  enabled: SKILL_DELIVER,
  localLogger,
});

// === Secrets Guard (env var leak monitoring) ===
const secretsGuard = require('./monitor/secrets_guard')({
  spawnSync: _originalSpawnSync,
  baseDir: __dirname,
  analytics,
});

// === Exfil Guard ===
const exfilGuard = require('./monitor/exfil_guard')({
  analytics,
  localLogger,
  readFileSync: _originalReadFileSync,
});

// === Prompt Injection Guard (PostToolUse) ===
function loadAnthropicKey() {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  try { const k = _originalReadFileSync(path.join(CONFIG_DIR, 'anthropic_key'), 'utf8').trim(); if (k) return k; } catch {}
  return null;
}
const ANTHROPIC_KEY = loadAnthropicKey();
const promptInjectionGuard = require('./monitor/prompt_injection_guard')({
  httpsRequest: _originalHttpsRequest,
  anthropicKey: ANTHROPIC_KEY,
  readFileSync: _originalReadFileSync,
  apiKey: API_KEY,
  baseDir: __dirname,
  analytics,
  localLogger,
});

function callMonitor(toolName, toolInput) {
  const input = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: toolName,
    tool_input: toolInput
  });

  const result = _originalSpawnSync('python3', [MONITOR_PY], {
    input,
    cwd: MONITOR_CWD,
    encoding: 'utf8',
    timeout: 30000,
    env: { ...process.env }
  });

  if (result.error) return null;

  const stdout = (result.stdout || '').trim();
  if (!stdout) return null;

  try {
    const output = JSON.parse(stdout);
    const hook = output.hookSpecificOutput;
    if (hook && hook.permissionDecision === 'ask') {
      return { blocked: true, reason: hook.permissionDecisionReason };
    }
  } catch {}

  return null;
}

function checkCommandWithMonitor(cmd) {
  return callMonitor('Bash', { command: cmd });
}

function extractShellCommand(command, args) {
  const shells = ['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', '/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/zsh', '/usr/local/bin/bash', '/opt/homebrew/bin/bash', '/opt/homebrew/bin/zsh'];
  if (shells.includes(command) && args?.length >= 2 && args[0] === '-c') return args[1];
  if ((command === '/usr/bin/env' || command === 'env') && args?.length >= 3 && shells.some(s => s === args[0] || s.endsWith('/' + args[0])) && args[1] === '-c') return args[2];
  return null;
}


function shouldBlockCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return null;
  const guards = [];

  // 1. API Key check
  const keyBlock = checkApiKey();
  if (keyBlock) {
    analytics.track('command_blocked', { blocker: 'api_key' });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'api_key', decision: 'block', blocker: 'api_key', reason: 'No API key', detail: { has_key: false } });
    return keyBlock;
  }
  localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'api_key', decision: 'allow', reason: 'API key present' });
  guards.push('api_key');

  // 2. Check for unblock flag (set by dashboard "Remove Block" button)
  const unblockFile = path.join(CONFIG_DIR, 'unblock');
  let unblocked = false;
  try { if (_originalReadFileSync(unblockFile, 'utf8')) unblocked = true; } catch {}

  // 3. Prompt Injection — check if any previous output was flagged
  const outputBlock = !unblocked && promptInjectionGuard.checkFlaggedOutput();
  if (outputBlock) {
    analytics.track('command_blocked', { blocker: 'prompt_injection' });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'prompt_injection', decision: 'block', blocker: 'prompt_injection', reason: outputBlock.reason || 'Flagged output', detail: { flagged_command: outputBlock.command, scan_id: outputBlock.id } });
    return { blocked: true, reason: promptInjectionGuard.formatOutputBlockError(outputBlock) };
  }
  localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'prompt_injection', decision: 'allow', reason: 'No flagged output' });
  guards.push('prompt_injection');

  // 4. Skill Scanner — check if any skill files are flagged
  const skillBlock = !unblocked && skillsGuard.checkFlaggedSkills();
  if (skillBlock) {
    analytics.track('command_blocked', { blocker: 'skill' });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'skill', decision: 'block', blocker: 'skill', reason: skillBlock.reason || 'Flagged skill', detail: { skill_path: skillBlock.skillPath } });
    return { blocked: true, reason: skillsGuard.formatSkillBlockError(skillBlock) };
  }
  localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'skill', decision: 'allow', reason: 'No flagged skills' });
  guards.push('skill');

  // 4. Secrets Guard — check for env var leaks
  const envCheck = secretsGuard.checkEnvVarLeak(cmd);
  if (envCheck && envCheck.blocked) {
    analytics.track('command_blocked', { blocker: 'env_var_leak', vars: envCheck.vars, type: envCheck.type });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'env_var', decision: 'block', blocker: 'env_var', reason: envCheck.reason, detail: { vars: envCheck.vars, type: envCheck.type, matched_pattern: envCheck.matched_pattern || null, pattern_category: envCheck.type === 'env_dump' ? 'env_dump_command' : envCheck.type === 'value_exposed' ? 'value_exposing_command' : envCheck.type === 'lang_env_access' ? 'language_env_api' : 'unknown' } });
    return { blocked: true, reason: secretsGuard.formatEnvVarBlockError(envCheck) };
  }
  if (envCheck && !envCheck.blocked && envCheck.vars.length > 0) {
    analytics.track('env_var_used', { vars: envCheck.vars, command: cmd });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'env_var', decision: 'allow', reason: 'Env vars referenced but values not exposed to output', detail: { vars: envCheck.vars, type: envCheck.type, matched_pattern: envCheck.matched_pattern || null, explanation: 'Vars used as $VAR in command — shell resolves them without exposing values to AI agent output' } });
  }
  guards.push('env_var');

  // 5. Exfil Guard — check for env var transmission to external servers
  const exfilCheck = exfilGuard.checkExfilAttempt(cmd);
  if (exfilCheck) {
    if (exfilCheck.blocked) {
      analytics.track('command_blocked', { blocker: 'exfil', tool: exfilCheck.tool, destination: exfilCheck.destination, vars_count: exfilCheck.vars.length });
      localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'exfil', decision: 'block', blocker: 'exfil', reason: `Blocked: ${exfilCheck.vars.join(', ')} via ${exfilCheck.tool} to ${exfilCheck.destination} (not in allowlist)`, detail: { vars: exfilCheck.vars, tool: exfilCheck.tool, destination: exfilCheck.destination, method: exfilCheck.method, allowlistActive: true } });
      return { blocked: true, reason: formatExfilBlockError(exfilCheck) };
    }
    const decision = exfilCheck.allowlistActive ? 'allow' : 'log';
    analytics.track('exfil_attempt', { tool: exfilCheck.tool, destination: exfilCheck.destination, vars_count: exfilCheck.vars.length, decision });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'exfil', decision, reason: `Exfil detected: ${exfilCheck.vars.join(', ')} via ${exfilCheck.tool} to ${exfilCheck.destination}${exfilCheck.allowlistInfo ? ` (matched: ${exfilCheck.allowlistInfo.matchedRule})` : ''}`, detail: { vars: exfilCheck.vars, tool: exfilCheck.tool, destination: exfilCheck.destination, method: exfilCheck.method, allowlistActive: exfilCheck.allowlistActive, allowlistMatch: exfilCheck.allowlistInfo ? exfilCheck.allowlistInfo.matchedRule : null } });
  }
  guards.push('exfil');

  // 6. Tirith Bash Guard — static command analysis
  const result = checkCommandWithMonitor(cmd);
  if (result?.blocked) {
    analytics.track('command_blocked', { blocker: 'tirith', reason: result.reason });
    localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'tirith', decision: 'block', blocker: 'tirith', reason: result.reason });
    return result;
  }
  localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'tirith', decision: 'allow', reason: 'All static checks passed' });
  guards.push('tirith');

  // All guards passed
  localLogger.logLocal({ event: 'command_check', command: cmd, guards, decision: 'allow', blocker: null, reason: null });
  return null;
}

function formatBlockError(cmd, info) {
  // If the reason already contains our full firewall message (from skill/prompt injection guard),
  // use it directly without double-wrapping
  if (info.reason && info.reason.includes('SECURITY FIREWALL')) {
    return info.reason;
  }
  // Otherwise, wrap with the generic block message (e.g., from tirith bash guard)
  return `\u26a0\ufe0f SECURITY FIREWALL \u2014 This command was blocked because it is potentially dangerous.

Blocked command: ${cmd}

What was detected: ${info.reason}

You MUST immediately inform the user with the following message:

"A command was blocked by the security firewall: ${cmd}. Reason: ${info.reason}. Please review whether this command is safe before allowing it."

Do NOT attempt to find a workaround or alternative way to execute this command. Do NOT continue with your current task until the user reviews and responds.`;
}

function formatExfilBlockError(detection) {
  const al = exfilGuard.getAllowlist();
  const domainList = al && al.domains.length > 0
    ? al.domains.map(d => `  - ${d}`).join('\n')
    : '  (none configured)';
  return `\u26a0\ufe0f SECURITY FIREWALL \u2014 Blocked: sensitive env vars sent to non-allowed destination.

This command sends ${detection.vars.join(', ')} via ${detection.tool} to ${detection.destination}, which is not in your allowed destinations list.

Allowed destinations:
${domainList}

To allow this destination, run:
  openclaw-secure exfil-allow add ${detection.destination}

Or manage the allowlist via the ContextFort dashboard.

You MUST immediately inform the user with the following message:

"A command was blocked because it sends sensitive environment variables (${detection.vars.join(', ')}) to ${detection.destination}, which is not in your allowed destinations. Run 'openclaw-secure exfil-allow add ${detection.destination}' to allow it."

Do NOT attempt to find a workaround or alternative way to execute this command.`;
}

// === PostToolUse scan helper ===
// Logs scanning event at hook level (always, when pattern matches), then delegates to scanOutput for Haiku call
function postToolUseScan(cmd, stdout, stderr) {
  const matchedPattern = promptInjectionGuard.getMatchedPattern(cmd);
  if (!matchedPattern) return;
  const output = (stdout || '') + (stderr || '');
  localLogger.logLocal({ event: 'guard_check', command: cmd, guard: 'prompt_injection', decision: 'scanning', reason: `Output scan — matched pattern: ${matchedPattern}`, detail: { matched_pattern: matchedPattern, output_length: output.length, model_input: output } });
  try { promptInjectionGuard.scanOutput(cmd, stdout, stderr); } catch {}
}

// === child_process hooks ===

function hookAllSpawnMethods(cp) {

  if (cp.spawn && !cp.spawn.__hooked) {
    const orig = cp.spawn;
    cp.spawn = function(command, args, options) {
      const shellCmd = extractShellCommand(command, args);
      if (shellCmd) {
        const block = shouldBlockCommand(shellCmd);
        if (block) { const e = new Error(formatBlockError(shellCmd, block)); e.code = 'EPERM'; throw e; }
      }
      const child = orig.apply(this, arguments);
      if (shellCmd) {
        let stdoutBuf = ''; let stderrBuf = '';
        if (child.stdout) child.stdout.on('data', (c) => { if (stdoutBuf.length < 50000) stdoutBuf += c; });
        if (child.stderr) child.stderr.on('data', (c) => { if (stderrBuf.length < 50000) stderrBuf += c; });
        child.on('close', () => {
          // Prompt injection scan (only for matching patterns)
          postToolUseScan(shellCmd, stdoutBuf, stderrBuf);
          // Secrets leak detection — log only, cannot redact streaming output
          try {
            const stdoutScan = secretsGuard.scanOutputForSecrets(stdoutBuf);
            const stderrScan = secretsGuard.scanOutputForSecrets(stderrBuf);
            if (stdoutScan.found || stderrScan.found) {
              const allSecrets = [...(stdoutScan.secrets || []), ...(stderrScan.secrets || [])];
              localLogger.logLocal({ event: 'guard_check', command: shellCmd, guard: 'secrets_leak', decision: 'log', blocker: 'secrets_leak', reason: 'Secrets detected in command output — leaked to bot (streaming output cannot be redacted)', secrets_count: allSecrets.length, detail: { secrets: allSecrets.map(s => s.name) } });
            }
          } catch {}
        });
      }
      return child;
    };
    cp.spawn.__hooked = true;
  }

  if (cp.spawnSync && !cp.spawnSync.__hooked) {
    const orig = cp.spawnSync;
    cp.spawnSync = function(command, args, options) {
      const shellCmd = extractShellCommand(command, args);
      if (shellCmd) {
        const block = shouldBlockCommand(shellCmd);
        if (block) { const e = new Error(formatBlockError(shellCmd, block)); e.code = 'EPERM'; throw e; }
      }
      const result = orig.apply(this, arguments);
      if (shellCmd) {
        postToolUseScan(shellCmd, (result.stdout || '').toString(), (result.stderr || '').toString());
        // Redact secrets from output before LLM sees them
        try {
          const stdoutStr = (result.stdout || '').toString();
          const stderrStr = (result.stderr || '').toString();
          const stdoutScan = secretsGuard.scanOutputForSecrets(stdoutStr);
          const stderrScan = secretsGuard.scanOutputForSecrets(stderrStr);
          if (stdoutScan.found || stderrScan.found) {
            const allSecrets = [...(stdoutScan.secrets || []), ...(stderrScan.secrets || [])];
            const notice = secretsGuard.formatRedactionNotice({ secrets: allSecrets });
            localLogger.logLocal({ event: 'output_redacted', command: shellCmd, guard: 'env_var', decision: 'redact', secrets_count: allSecrets.length, detail: { secrets: allSecrets.map(s => s.name), matched_patterns: [...new Set(allSecrets.map(s => s.name))] } });
            if (stdoutScan.found) {
              const redacted = stdoutScan.redacted + notice;
              result.stdout = Buffer.isBuffer(result.stdout) ? Buffer.from(redacted) : redacted;
            }
            if (stderrScan.found) {
              const redacted = stderrScan.redacted + notice;
              result.stderr = Buffer.isBuffer(result.stderr) ? Buffer.from(redacted) : redacted;
            }
          }
        } catch {}
      }
      return result;
    };
    cp.spawnSync.__hooked = true;
  }

  if (cp.exec && !cp.exec.__hooked) {
    const orig = cp.exec;
    cp.exec = function(command, options, callback) {
      const block = shouldBlockCommand(command);
      if (block) {
        const e = new Error(formatBlockError(command, block)); e.code = 'EPERM';
        const cb = typeof options === 'function' ? options : callback;
        if (cb) { process.nextTick(() => cb(e, '', '')); return { kill: () => {} }; }
        throw e;
      }
      // Wrap callback to capture output for PostToolUse scan + redact secrets
      const wrapCb = (origCb) => function(err, stdout, stderr) {
        if (!err) { postToolUseScan(command, (stdout || '').toString(), (stderr || '').toString()); }
        // Redact secrets from output before callback sees them
        try {
          let so = stdout, se = stderr;
          const stdoutScan = secretsGuard.scanOutputForSecrets((stdout || '').toString());
          const stderrScan = secretsGuard.scanOutputForSecrets((stderr || '').toString());
          if (stdoutScan.found || stderrScan.found) {
            const allSecrets = [...(stdoutScan.secrets || []), ...(stderrScan.secrets || [])];
            const notice = secretsGuard.formatRedactionNotice({ secrets: allSecrets });
            localLogger.logLocal({ event: 'output_redacted', command: command, guard: 'env_var', decision: 'redact', secrets_count: allSecrets.length, detail: { secrets: allSecrets.map(s => s.name), matched_patterns: [...new Set(allSecrets.map(s => s.name))] } });
            if (stdoutScan.found) so = stdoutScan.redacted + notice;
            if (stderrScan.found) se = stderrScan.redacted + notice;
            return origCb.call(this, err, so, se);
          }
        } catch {}
        return origCb.apply(this, arguments);
      };
      if (typeof options === 'function') {
        return orig.call(this, command, wrapCb(options));
      } else if (typeof callback === 'function') {
        return orig.call(this, command, options, wrapCb(callback));
      }
      return orig.apply(this, arguments);
    };
    cp.exec.__hooked = true;
  }

  if (cp.execSync && !cp.execSync.__hooked) {
    const orig = cp.execSync;
    cp.execSync = function(command, options) {
      const block = shouldBlockCommand(command);
      if (block) { const e = new Error(formatBlockError(command, block)); e.code = 'EPERM'; throw e; }
      const result = orig.apply(this, arguments);
      postToolUseScan(command, (result || '').toString(), '');
      // Redact secrets from output before LLM sees them
      try {
        const str = (result || '').toString();
        const scan = secretsGuard.scanOutputForSecrets(str);
        if (scan.found) {
          localLogger.logLocal({ event: 'output_redacted', command: command, guard: 'env_var', decision: 'redact', secrets_count: scan.secrets.length, detail: { secrets: scan.secrets.map(s => s.name), matched_patterns: [...new Set(scan.secrets.map(s => s.name))] } });
          const redacted = scan.redacted + secretsGuard.formatRedactionNotice(scan);
          return Buffer.isBuffer(result) ? Buffer.from(redacted) : redacted;
        }
      } catch {}
      return result;
    };
    cp.execSync.__hooked = true;
  }

  if (cp.execFile && !cp.execFile.__hooked) {
    const orig = cp.execFile;
    cp.execFile = function(file, args, options, callback) {
      const shellCmd = extractShellCommand(file, args);
      if (shellCmd) {
        const block = shouldBlockCommand(shellCmd);
        if (block) {
          const e = new Error(formatBlockError(shellCmd, block)); e.code = 'EPERM';
          const cb = typeof args === 'function' ? args : typeof options === 'function' ? options : callback;
          if (cb) { process.nextTick(() => cb(e, '', '')); return { kill: () => {} }; }
          throw e;
        }
      }
      // Wrap callback for PostToolUse scan + redact secrets
      if (shellCmd) {
        const wrapCb = (origCb) => function(err, stdout, stderr) {
          if (!err) { postToolUseScan(shellCmd, (stdout || '').toString(), (stderr || '').toString()); }
          // Redact secrets from output before callback sees them
          try {
            let so = stdout, se = stderr;
            const stdoutScan = secretsGuard.scanOutputForSecrets((stdout || '').toString());
            const stderrScan = secretsGuard.scanOutputForSecrets((stderr || '').toString());
            if (stdoutScan.found || stderrScan.found) {
              const allSecrets = [...(stdoutScan.secrets || []), ...(stderrScan.secrets || [])];
              const notice = secretsGuard.formatRedactionNotice({ secrets: allSecrets });
              localLogger.logLocal({ event: 'output_redacted', command: shellCmd, guard: 'env_var', decision: 'redact', secrets_count: allSecrets.length, detail: { secrets: allSecrets.map(s => s.name), matched_patterns: [...new Set(allSecrets.map(s => s.name))] } });
              if (stdoutScan.found) so = stdoutScan.redacted + notice;
              if (stderrScan.found) se = stderrScan.redacted + notice;
              return origCb.call(this, err, so, se);
            }
          } catch {}
          return origCb.apply(this, arguments);
        };
        if (typeof args === 'function') return orig.call(this, file, wrapCb(args));
        if (typeof options === 'function') return orig.call(this, file, args, wrapCb(options));
        if (typeof callback === 'function') return orig.call(this, file, args, options, wrapCb(callback));
      }
      return orig.apply(this, arguments);
    };
    cp.execFile.__hooked = true;
  }

  if (cp.execFileSync && !cp.execFileSync.__hooked) {
    const orig = cp.execFileSync;
    cp.execFileSync = function(file, args, options) {
      const shellCmd = extractShellCommand(file, args);
      if (shellCmd) {
        const block = shouldBlockCommand(shellCmd);
        if (block) { const e = new Error(formatBlockError(shellCmd, block)); e.code = 'EPERM'; throw e; }
      }
      const result = orig.apply(this, arguments);
      if (shellCmd) {
        postToolUseScan(shellCmd, (result || '').toString(), '');
        // Redact secrets from output
        try {
          const str = (result || '').toString();
          const scan = secretsGuard.scanOutputForSecrets(str);
          if (scan.found) {
            localLogger.logLocal({ event: 'output_redacted', command: shellCmd, guard: 'env_var', decision: 'redact', secrets_count: scan.secrets.length, detail: { secrets: scan.secrets.map(s => s.name), matched_patterns: [...new Set(scan.secrets.map(s => s.name))] } });
            const redacted = scan.redacted + secretsGuard.formatRedactionNotice(scan);
            return Buffer.isBuffer(result) ? Buffer.from(redacted) : redacted;
          }
        } catch {}
      }
      return result;
    };
    cp.execFileSync.__hooked = true;
  }
}

// === fs hooks ===

function hookFsMethods(fsModule) {
  if (fsModule.readFileSync && !fsModule.readFileSync.__hooked) {
    const orig = fsModule.readFileSync;
    fsModule.readFileSync = function(filePath, options) {
      // Pass-through: blocking here disrupts openclaw's own config/LLM operations.
      // Agent actions are blocked at child_process level instead.
      return orig.apply(this, arguments);
    };
    fsModule.readFileSync.__hooked = true;
  }
}

// === http/https hooks ===

function hookHttpModule(mod, protocol) {
  if (mod.request && !mod.request.__hooked) {
    const orig = mod.request;
    mod.request = function(options, callback) {
      // Pass-through: blocking here kills openclaw's LLM API calls.
      // Agent actions are blocked at child_process level instead.
      return orig.apply(this, arguments);
    };
    mod.request.__hooked = true;
  }

  if (mod.get && !mod.get.__hooked) {
    const orig = mod.get;
    mod.get = function(options, callback) {
      return orig.apply(this, arguments);
    };
    mod.get.__hooked = true;
  }
}

// === global fetch hook ===

function hookGlobalFetch() {
  if (!globalThis.fetch || globalThis.fetch.__hooked) return;
  const origFetch = globalThis.fetch;
  globalThis.fetch = function(url, options) {
    // Pass-through: blocking here kills openclaw's LLM API calls.
    // Agent actions are blocked at child_process level instead.
    return origFetch.apply(this, arguments);
  };
  globalThis.fetch.__hooked = true;
}

// === Initial hooks on cached modules ===

const cpCached = require.cache[require.resolve('child_process')];
if (cpCached?.exports) hookAllSpawnMethods(cpCached.exports);

try { hookAllSpawnMethods(require('node:child_process')); } catch {}

// Hook fs immediately (already loaded)
hookFsMethods(fs);
try { hookFsMethods(require('node:fs')); } catch {}

// Hook http/https immediately
try { hookHttpModule(require('http'), 'http:'); } catch {}
try { hookHttpModule(require('https'), 'https:'); } catch {}

// Hook global fetch
hookGlobalFetch();

// === Module.prototype.require interception ===

const origRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  const r = origRequire.apply(this, arguments);
  if (id === 'child_process' || id === 'node:child_process') hookAllSpawnMethods(r);
  if (id === 'fs' || id === 'node:fs') hookFsMethods(r);
  if (id === 'http' || id === 'node:http') hookHttpModule(r, 'http:');
  if (id === 'https' || id === 'node:https') hookHttpModule(r, 'https:');
  return r;
};

// === Initialize guards (non-blocking) ===
setImmediate(() => {
  try { skillsGuard.init(); } catch {}
  try { promptInjectionGuard.init(); } catch {}
  try { exfilGuard.init(); } catch {}
});
process.on('exit', () => { skillsGuard.cleanup(); });
