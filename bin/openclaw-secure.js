#!/usr/bin/env node
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const os = require('os');
const hook = path.join(__dirname, '..', 'openclaw-secure.js');
const args = process.argv.slice(2);
const CONFIG_DIR = path.join(os.homedir(), '.contextfort');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config');

const binLink = process.argv[1];
let installedScript;
try {
  const target = fs.readlinkSync(binLink);
  installedScript = path.resolve(path.dirname(binLink), target);
} catch {
  installedScript = binLink;
}
const installedBinDir = path.dirname(installedScript);
const packageDir = path.dirname(installedBinDir);
let nodeModules = path.dirname(packageDir);
if (path.basename(nodeModules).startsWith('@')) nodeModules = path.dirname(nodeModules);
const prefixDir = path.dirname(path.dirname(nodeModules));
const binDir = path.join(prefixDir, 'bin');
const realOpenclaw = path.join(nodeModules, 'openclaw', 'openclaw.mjs');
const openclawLink = path.join(binDir, 'openclaw');
const backupLink = path.join(binDir, '.openclaw-original');

if (args[0] === 'set-key') {
  const key = args[1];
  if (!key) {
    console.error('Usage: openclaw-secure set-key <your-api-key>');
    console.error('Get your key at https://contextfort.ai/login');
    process.exit(1);
  }
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, key + '\n', { mode: 0o600 });
  console.log('API key saved to ~/.contextfort/config');
  console.log('\nNext step: run `openclaw-secure enable` to activate the guard.');
  process.exit(0);
}

if (args[0] === 'enable') {
  // Check for API key first
  let hasKey = false;
  try { hasKey = fs.readFileSync(CONFIG_FILE, 'utf8').trim().length > 0; } catch {}
  if (!hasKey) {
    console.error('No API key found. Get your key at https://contextfort.ai/login and run:');
    console.error('  openclaw-secure set-key <your-key>');
    process.exit(1);
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('Warning: ANTHROPIC_API_KEY not set. PostToolUse prompt injection scanning will be disabled.');
    console.warn('Set it in your shell profile: export ANTHROPIC_API_KEY="sk-ant-..."');
  }
  if (!fs.existsSync(realOpenclaw)) {
    console.error('openclaw not found. Install it first: npm install -g openclaw');
    process.exit(1);
  }
  // Handle --no-skill-deliver flag
  const noSkillDeliver = args.includes('--no-skill-deliver');
  const prefsFile = path.join(CONFIG_DIR, 'preferences.json');
  let prefs = {};
  try { prefs = JSON.parse(fs.readFileSync(prefsFile, 'utf8')); } catch {}
  prefs.skillDeliver = !noSkillDeliver;
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(prefsFile, JSON.stringify(prefs, null, 2) + '\n', { mode: 0o600 });
  if (noSkillDeliver) {
    console.log('Skill file scanning disabled. Only local checks will run.');
  }
  try {
    const original = fs.readlinkSync(openclawLink);
    fs.writeFileSync(backupLink, original);
  } catch {}
  const wrapper = path.relative(binDir, path.join(installedBinDir, 'openclaw-secure.js'));
  fs.unlinkSync(openclawLink);
  fs.symlinkSync(wrapper, openclawLink);
  console.log('openclaw-secure enabled. `openclaw` is now guarded.');
  console.log('Restart your openclaw gateway for the guard to take effect.');
  process.exit(0);
}

if (args[0] === 'dashboard') {
  const portArg = args.find(a => a.startsWith('--port='));
  const port = portArg ? parseInt(portArg.split('=')[1]) : 9009;
  const startDashboard = require('../monitor/dashboard/server');
  const server = startDashboard({ port });

  // Auto-open browser
  const openUrl = `http://localhost:${port}`;
  try {
    const { execSync } = require('child_process');
    if (process.platform === 'darwin') execSync(`open "${openUrl}"`);
    else if (process.platform === 'linux') execSync(`xdg-open "${openUrl}" 2>/dev/null`);
    else if (process.platform === 'win32') execSync(`start "" "${openUrl}"`);
  } catch {}

  process.on('SIGINT', () => {
    if (server._tunnel) try { server._tunnel.kill(); } catch {}
    server.close();
    process.exit(0);
  });
  // Keep alive — don't fall through
  return;
}

if (args[0] === 'scan' || args[0] === 'solve') {
  const { spawnSync } = require('child_process');
  const readline = require('readline');
  const secretsGuard = require('../monitor/secrets_guard')({
    spawnSync,
    baseDir: packageDir,
    analytics: null,
  });

  if (!secretsGuard.isTrufflehogInstalled()) {
    console.error('\n  trufflehog is not installed.\n');
    console.error('  Install it with:  brew install trufflehog');
    console.error('  Or see: https://github.com/trufflesecurity/trufflehog#installation\n');
    process.exit(1);
  }

  const onlyVerified = !args.includes('--all');
  const cwd = args.find(a => !a.startsWith('-') && a !== 'scan' && a !== 'solve') || process.cwd();

  console.log('\n  Running TruffleHog secret scan...');
  if (args[0] === 'scan' && onlyVerified) {
    console.log('  Mode: verified secrets only (use --all to include unverified)\n');
  } else if (args[0] === 'scan') {
    console.log('  Mode: all findings (including unverified)\n');
  } else {
    console.log('  Mode: solve — scanning for live secrets to replace\n');
  }

  // For solve, always scan with onlyVerified=true (only replace live secrets)
  const scanVerified = args[0] === 'solve' ? true : onlyVerified;
  const result = secretsGuard.scan(cwd, { onlyVerified: scanVerified });
  console.log(secretsGuard.formatResults(result));

  if (args[0] === 'scan') {
    process.exit(result.findings.filter(f => f.verified).length > 0 ? 1 : 0);
  }

  // === SOLVE mode ===
  const verified = result.findings.filter(f => f.verified && f.rawFull && f.file);
  if (verified.length === 0) {
    console.log('  Nothing to solve — no live hardcoded secrets found.\n');
    process.exit(0);
  }

  // Group findings by file
  const fileMap = new Map(); // file → [findings]
  for (const f of verified) {
    if (!fileMap.has(f.file)) fileMap.set(f.file, []);
    fileMap.get(f.file).push(f);
  }
  const fileList = [...fileMap.entries()]; // [[file, [findings]], ...]

  console.log(`  OpenClaw can read these ${fileList.length} file(s) containing ${verified.length} live secret(s).`);
  console.log('  If not replaced, OpenClaw could read and leak them.\n');
  console.log('  Use \u2191\u2193 to move, SPACE to select, A to toggle all, ENTER to confirm, Q to quit.\n');

  // Build items for checkbox UI
  const items = fileList.map(([filePath, findings]) => {
    const types = [...new Set(findings.map(f => f.detectorName))].join(', ');
    const count = findings.length;
    return {
      label: `${filePath.replace(os.homedir(), '~')}  (${count} ${types})`,
      selected: false,
    };
  });

  let cursor = 0;

  function render() {
    // Move cursor up to overwrite previous render
    if (items._rendered) {
      process.stdout.write(`\x1b[${items.length + 1}A`);
    }
    for (let i = 0; i < items.length; i++) {
      const check = items[i].selected ? '\x1b[32m\u25c9\x1b[0m' : '\u25cb';
      const pointer = i === cursor ? '\x1b[36m\u276f\x1b[0m ' : '  ';
      const dim = i === cursor ? '' : '\x1b[2m';
      const reset = i === cursor ? '' : '\x1b[0m';
      process.stdout.write(`\x1b[2K  ${pointer}${check} ${dim}${items[i].label}${reset}\n`);
    }
    const selectedCount = items.filter(it => it.selected).length;
    process.stdout.write(`\x1b[2K  \x1b[2m${selectedCount}/${items.length} selected\x1b[0m\n`);
    items._rendered = true;
  }

  render();

  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding('utf8');

  stdin.on('data', (key) => {
    if (key === 'q' || key === '\x03') {
      // q or Ctrl+C
      stdin.setRawMode(false);
      console.log('\n\n  Aborted. No changes made.\n');
      process.exit(0);
    }
    if (key === '\r' || key === '\n') {
      // Enter — confirm
      stdin.setRawMode(false);
      stdin.pause();
      const selectedFindings = [];
      for (let i = 0; i < items.length; i++) {
        if (items[i].selected) {
          selectedFindings.push(...fileList[i][1]);
        }
      }
      if (selectedFindings.length === 0) {
        console.log('\n\n  No files selected. Aborted.\n');
        process.exit(0);
      }
      const selectedFiles = items.filter(it => it.selected).length;
      console.log(`\n\n  Replacing secrets in ${selectedFiles} file(s)...`);
      const results = secretsGuard.solve(selectedFindings);
      console.log(secretsGuard.formatSolveResults(results));
      process.exit(0);
      return;
    }
    if (key === ' ') {
      // Space — toggle current item
      items[cursor].selected = !items[cursor].selected;
      render();
      return;
    }
    if (key === 'a' || key === 'A') {
      // A — toggle all
      const allSelected = items.every(it => it.selected);
      for (const it of items) it.selected = !allSelected;
      render();
      return;
    }
    if (key === '\x1b[A' || key === 'k') {
      // Up arrow or k
      cursor = (cursor - 1 + items.length) % items.length;
      render();
      return;
    }
    if (key === '\x1b[B' || key === 'j') {
      // Down arrow or j
      cursor = (cursor + 1) % items.length;
      render();
      return;
    }
  });
  return; // don't fall through — raw mode is async
}

if (args[0] === 'exfil-allow') {
  const ALLOWLIST_FILE = path.join(CONFIG_DIR, 'exfil_allowlist.json');
  const sub = args[1];

  function readAllowlist() {
    try { return JSON.parse(fs.readFileSync(ALLOWLIST_FILE, 'utf8')); }
    catch { return { enabled: false, domains: [] }; }
  }

  function writeAllowlist(data) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(ALLOWLIST_FILE, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  }

  if (sub === 'list') {
    const al = readAllowlist();
    console.log(`\n  Exfil destination allowlist: ${al.enabled ? '\x1b[32menabled\x1b[0m (blocking non-allowed)' : '\x1b[33mdisabled\x1b[0m (log-only mode)'}`);
    if (al.domains.length === 0) {
      console.log('  No domains configured.\n');
    } else {
      console.log('  Allowed destinations:');
      for (const d of al.domains) console.log(`    - ${d}`);
      console.log();
    }
    process.exit(0);
  }

  if (sub === 'add') {
    const domain = args[2];
    if (!domain) { console.error('Usage: openclaw-secure exfil-allow add <domain>'); process.exit(1); }
    const al = readAllowlist();
    if (!al.domains.includes(domain)) al.domains.push(domain);
    al.enabled = true;
    writeAllowlist(al);
    console.log(`  Added ${domain} to exfil allowlist. Blocking mode enabled.`);
    console.log('  Restart your openclaw session for changes to take effect.');
    process.exit(0);
  }

  if (sub === 'remove') {
    const domain = args[2];
    if (!domain) { console.error('Usage: openclaw-secure exfil-allow remove <domain>'); process.exit(1); }
    const al = readAllowlist();
    al.domains = al.domains.filter(d => d !== domain);
    writeAllowlist(al);
    console.log(`  Removed ${domain} from exfil allowlist.`);
    if (al.domains.length === 0) console.log('  No domains left — consider disabling with: openclaw-secure exfil-allow disable');
    process.exit(0);
  }

  if (sub === 'enable') {
    const al = readAllowlist();
    al.enabled = true;
    writeAllowlist(al);
    console.log('  Exfil allowlist blocking enabled. Only allowlisted destinations will be permitted.');
    console.log('  Restart your openclaw session for changes to take effect.');
    process.exit(0);
  }

  if (sub === 'disable') {
    const al = readAllowlist();
    al.enabled = false;
    writeAllowlist(al);
    console.log('  Exfil allowlist blocking disabled. All exfil detections will be log-only.');
    process.exit(0);
  }

  console.error('Usage: openclaw-secure exfil-allow <list|add|remove|enable|disable> [domain]');
  process.exit(1);
}

if (args[0] === 'disable') {
  try {
    const original = fs.readFileSync(backupLink, 'utf8').trim();
    fs.unlinkSync(openclawLink);
    fs.symlinkSync(original, openclawLink);
    fs.unlinkSync(backupLink);
    console.log('openclaw-secure disabled. `openclaw` restored to original.');
  } catch {
    const rel = path.relative(binDir, realOpenclaw);
    try { fs.unlinkSync(openclawLink); } catch {}
    fs.symlinkSync(rel, openclawLink);
    console.log('openclaw-secure disabled. `openclaw` restored.');
  }
  process.exit(0);
}

if (!fs.existsSync(realOpenclaw)) {
  console.error('openclaw not found. Install it first: npm install -g openclaw');
  process.exit(1);
}

try {
  execFileSync('node', [realOpenclaw, ...args], {
    stdio: 'inherit',
    env: {
      ...process.env,
      NODE_OPTIONS: `--require ${hook} ${process.env.NODE_OPTIONS || ''}`
    }
  });
} catch (e) {
  process.exit(e.status || 1);
}
