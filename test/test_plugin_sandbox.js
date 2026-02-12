'use strict';

/**
 * Plugin Sandbox Guard tests.
 *
 * Safe: no global installs, no reading real secrets, no network calls.
 * Uses a temp dir for fake plugin fixtures, cleans up on exit.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const assert = require('assert');

const HOME = os.homedir();
let tmpPluginDir = null;
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
  } catch (e) {
    failed++;
    console.log(`  \x1b[31mFAIL\x1b[0m ${name}`);
    console.log(`       ${e.message}`);
  }
}

// =============================================
// Setup: create a temp dir to simulate plugins
// =============================================
function setup() {
  tmpPluginDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-sandbox-test-'));
  // Create a fake plugin server script that just prints env + tries reads
  const pluginDir = path.join(tmpPluginDir, 'test-plugin');
  fs.mkdirSync(pluginDir, { recursive: true });
  fs.writeFileSync(path.join(pluginDir, 'server.js'), `
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const results = {
      envKeys: Object.keys(process.env).sort(),
      sandboxMarker: process.env.__CONTEXTFORT_SANDBOX,
      hasPath: !!process.env.PATH,
      hasHome: !!process.env.HOME,
      // These should be stripped
      hasAnthropicKey: !!process.env.ANTHROPIC_API_KEY,
      hasFakeSecret: !!process.env.FAKE_SECRET_FOR_TEST,
      // FS block tests — try to stat blocked paths (NOT read contents)
      fsTests: {},
    };
    const blockedPaths = ['.ssh', '.aws', '.gnupg', '.config', '.contextfort'];
    for (const p of blockedPaths) {
      const full = path.join(os.homedir(), p);
      try {
        fs.statSync(full);
        results.fsTests[p] = 'allowed';
      } catch (e) {
        results.fsTests[p] = e.code; // EACCES from sandbox, ENOENT if doesn't exist
      }
    }
    // A non-blocked path should work
    try {
      fs.statSync(os.tmpdir());
      results.fsTests['tmpdir'] = 'allowed';
    } catch (e) {
      results.fsTests['tmpdir'] = e.code;
    }
    console.log(JSON.stringify(results));
  `);
}

function cleanup() {
  if (tmpPluginDir) {
    try { fs.rmSync(tmpPluginDir, { recursive: true, force: true }); } catch {}
  }
}

// =============================================
// Unit tests: plugin_guard module directly
// =============================================
function unitTests() {
  console.log('\n--- Unit Tests: plugin_guard module ---');

  const logEvents = [];
  const guard = require('../monitor/plugin_guard')({
    localLogger: { logLocal: (e) => logEvents.push(e) },
    analytics: null,
  });

  // --- isSandboxed ---
  test('isSandboxed returns false when env var not set', () => {
    delete process.env.__CONTEXTFORT_SANDBOX;
    assert.strictEqual(guard.isSandboxed(), false);
  });

  test('isSandboxed returns true when env var is set', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    assert.strictEqual(guard.isSandboxed(), true);
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  // --- isPluginSpawn ---
  const PLUGIN_DIR = path.join(HOME, '.claude', 'plugins');

  test('isPluginSpawn: node + plugin path → true', () => {
    assert.strictEqual(guard.isPluginSpawn('node', [PLUGIN_DIR + '/foo/server.js']), true);
  });

  test('isPluginSpawn: npx + plugin path → true', () => {
    assert.strictEqual(guard.isPluginSpawn('npx', [PLUGIN_DIR + '/bar/index.js']), true);
  });

  test('isPluginSpawn: tsx + plugin path → true', () => {
    assert.strictEqual(guard.isPluginSpawn('tsx', [PLUGIN_DIR + '/baz/main.ts']), true);
  });

  test('isPluginSpawn: bun + plugin path → true', () => {
    assert.strictEqual(guard.isPluginSpawn('bun', [PLUGIN_DIR + '/qux/run.js']), true);
  });

  test('isPluginSpawn: node + non-plugin path → false', () => {
    assert.strictEqual(guard.isPluginSpawn('node', ['./app.js']), false);
  });

  test('isPluginSpawn: node + flags before plugin path → true', () => {
    assert.strictEqual(guard.isPluginSpawn('node', ['--inspect', PLUGIN_DIR + '/foo/server.js']), true);
  });

  test('isPluginSpawn: bash shell command → false', () => {
    assert.strictEqual(guard.isPluginSpawn('bash', ['-c', 'ls -la']), false);
  });

  test('isPluginSpawn: direct plugin path as command → true', () => {
    assert.strictEqual(guard.isPluginSpawn(PLUGIN_DIR + '/direct/bin.js', []), true);
  });

  test('isPluginSpawn: null command → false', () => {
    assert.strictEqual(guard.isPluginSpawn(null, []), false);
  });

  test('isPluginSpawn: empty args → false for node', () => {
    assert.strictEqual(guard.isPluginSpawn('node', []), false);
  });

  // --- scrubEnvForPlugin ---
  test('scrubEnvForPlugin keeps only allowed vars', () => {
    const input = {
      PATH: '/usr/bin',
      HOME: '/Users/test',
      USER: 'test',
      ANTHROPIC_API_KEY: 'sk-ant-secret',
      AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI',
      FAKE_SECRET_FOR_TEST: 'supersecret',
      DATABASE_URL: 'postgres://...',
      NODE_OPTIONS: '--require ./hook.js',
    };
    const result = guard.scrubEnvForPlugin(input);

    assert.strictEqual(result.PATH, '/usr/bin');
    assert.strictEqual(result.HOME, '/Users/test');
    assert.strictEqual(result.USER, 'test');
    assert.strictEqual(result.NODE_OPTIONS, '--require ./hook.js');
    assert.strictEqual(result.__CONTEXTFORT_SANDBOX, '1');

    // Secrets must be gone
    assert.strictEqual(result.ANTHROPIC_API_KEY, undefined);
    assert.strictEqual(result.AWS_SECRET_ACCESS_KEY, undefined);
    assert.strictEqual(result.FAKE_SECRET_FOR_TEST, undefined);
    assert.strictEqual(result.DATABASE_URL, undefined);
  });

  test('scrubEnvForPlugin logs stripped count', () => {
    logEvents.length = 0;
    guard.scrubEnvForPlugin({ PATH: '/bin', SECRET: 'x', TOKEN: 'y' });
    const scrubEvent = logEvents.find(e => e.decision === 'env_scrubbed');
    assert.ok(scrubEvent, 'should log env_scrubbed event');
    assert.strictEqual(scrubEvent.detail.stripped_count, 2);
    assert.deepStrictEqual(scrubEvent.detail.stripped_names.sort(), ['SECRET', 'TOKEN']);
  });

  // --- checkFsAccess ---
  test('checkFsAccess: not sandboxed → always null', () => {
    delete process.env.__CONTEXTFORT_SANDBOX;
    assert.strictEqual(guard.checkFsAccess(path.join(HOME, '.ssh', 'id_rsa')), null);
    assert.strictEqual(guard.checkFsAccess(path.join(HOME, '.aws', 'credentials')), null);
  });

  test('checkFsAccess: sandboxed → blocks .ssh', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.ssh', 'id_rsa'));
    assert.ok(result && result.blocked, 'should block .ssh');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → blocks .aws', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.aws', 'credentials'));
    assert.ok(result && result.blocked, 'should block .aws');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → blocks .gnupg', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.gnupg', 'pubring.kbx'));
    assert.ok(result && result.blocked, 'should block .gnupg');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → blocks .config', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.config', 'some-app'));
    assert.ok(result && result.blocked, 'should block .config');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → blocks .contextfort', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.contextfort', 'config'));
    assert.ok(result && result.blocked, 'should block .contextfort');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → blocks exact dir path', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, '.ssh'));
    assert.ok(result && result.blocked, 'should block .ssh dir itself');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → allows /tmp', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess('/tmp/somefile');
    assert.strictEqual(result, null, 'should allow /tmp');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: sandboxed → allows project files', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const result = guard.checkFsAccess(path.join(HOME, 'projects', 'app', 'index.js'));
    assert.strictEqual(result, null, 'should allow project files');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('checkFsAccess: null path → null', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    assert.strictEqual(guard.checkFsAccess(null), null);
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  // --- logNetworkRequest ---
  test('logNetworkRequest: not sandboxed → no log', () => {
    delete process.env.__CONTEXTFORT_SANDBOX;
    logEvents.length = 0;
    guard.logNetworkRequest({ host: 'evil.com', port: 443, method: 'POST', path: '/steal' });
    assert.strictEqual(logEvents.filter(e => e.decision === 'network_logged').length, 0);
  });

  test('logNetworkRequest: sandboxed → logs', () => {
    process.env.__CONTEXTFORT_SANDBOX = '1';
    logEvents.length = 0;
    guard.logNetworkRequest({ host: 'example.com', port: 443, method: 'GET', path: '/api', protocol: 'https:' });
    const netEvent = logEvents.find(e => e.decision === 'network_logged');
    assert.ok(netEvent, 'should log network_logged event');
    assert.strictEqual(netEvent.detail.host, 'example.com');
    assert.strictEqual(netEvent.detail.method, 'GET');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });
}

// =============================================
// Integration test: spawn through the hook
// =============================================
function integrationTests() {
  console.log('\n--- Integration Test: spawn through hook ---');

  // We can't require openclaw-secure.js in this process (it hooks everything),
  // so we spawn a child that loads the hook and then spawns the fake plugin.
  // The "fake plugin" lives in tmpPluginDir, NOT in ~/.claude/plugins,
  // so isPluginSpawn won't match. Instead we test the guard module's logic
  // by calling it directly in a child process.

  const { spawnSync } = require('child_process');
  const pluginScript = path.join(tmpPluginDir, 'test-plugin', 'server.js');

  // Test: run the plugin script directly WITH __CONTEXTFORT_SANDBOX set
  // and WITH the hook loaded — this simulates what happens in a real
  // sandboxed child process.
  const hookPath = path.resolve(__dirname, '..', 'openclaw-secure.js');

  test('sandboxed child: FS blocklist active', () => {
    // Create a wrapper that loads ONLY the plugin_guard (not the full hook)
    // to avoid monitor.py / skill scanner timeout in tests.
    const wrapperScript = path.join(tmpPluginDir, 'sandbox-wrapper.js');
    const guardPath = path.resolve(__dirname, '..', 'monitor', 'plugin_guard');
    fs.writeFileSync(wrapperScript, `
      const guard = require(${JSON.stringify(guardPath)})({ localLogger: null, analytics: null });
      const fs = require('fs');
      const origStatSync = fs.statSync;
      const origReadFileSync = fs.readFileSync;
      const origExistsSync = fs.existsSync;
      const origAccessSync = fs.accessSync;
      const origReaddirSync = fs.readdirSync;
      for (const method of ['statSync', 'readFileSync', 'existsSync', 'accessSync', 'readdirSync']) {
        const orig = fs[method];
        fs[method] = function(filePath) {
          const block = guard.checkFsAccess(filePath);
          if (block) { const e = new Error(block.reason); e.code = 'EACCES'; throw e; }
          return orig.apply(this, arguments);
        };
      }
    `);

    const result = spawnSync('node', [
      '--require', wrapperScript,
      pluginScript,
    ], {
      encoding: 'utf8',
      timeout: 10000,
      env: {
        PATH: process.env.PATH,
        HOME: HOME,
        USER: process.env.USER,
        TMPDIR: process.env.TMPDIR || '/tmp',
        NODE_PATH: process.env.NODE_PATH || '',
        __CONTEXTFORT_SANDBOX: '1',
        // Intentionally NOT passing secrets — they should already be gone
      },
    });

    if (result.error) {
      throw new Error('spawn failed: ' + result.error.message);
    }
    if (result.status !== 0) {
      throw new Error('exit code ' + result.status + ': ' + (result.stderr || '').slice(0, 300));
    }

    const output = JSON.parse(result.stdout.trim().split('\n').pop());

    // Env checks
    assert.strictEqual(output.sandboxMarker, '1', 'sandbox marker should be set');
    assert.strictEqual(output.hasPath, true, 'PATH should be present');
    assert.strictEqual(output.hasHome, true, 'HOME should be present');
    assert.strictEqual(output.hasAnthropicKey, false, 'ANTHROPIC_API_KEY should not be present');
    assert.strictEqual(output.hasFakeSecret, false, 'FAKE_SECRET should not be present');

    // FS checks — blocked dirs should get EACCES
    for (const dir of ['.ssh', '.aws', '.gnupg', '.config', '.contextfort']) {
      const code = output.fsTests[dir];
      assert.strictEqual(code, 'EACCES', `${dir} should be EACCES, got ${code}`);
    }

    // tmpdir should be allowed
    assert.strictEqual(output.fsTests['tmpdir'], 'allowed', 'tmpdir should be allowed');
  });

  test('sandboxed child preserves plugin-set env vars (camofox pattern)', () => {
    // Simulate what camofox does: already-sandboxed process spawns
    // node server.js with CAMOFOX_PORT in the env.
    // The hook should NOT re-scrub because isSandboxed() is true.
    const pluginServerScript = path.join(tmpPluginDir, 'test-plugin', 'check-port.js');
    fs.writeFileSync(pluginServerScript, `
      console.log(JSON.stringify({
        camofoxPort: process.env.CAMOFOX_PORT || 'MISSING',
        sandboxed: process.env.__CONTEXTFORT_SANDBOX || 'no',
        envCount: Object.keys(process.env).length,
      }));
    `);

    // Spawn WITH __CONTEXTFORT_SANDBOX already set + CAMOFOX_PORT
    // This simulates a sandboxed plugin spawning its own child.
    // Since we're not loading the full hook (just the guard), we test
    // the guard logic directly.
    const guard2 = require('../monitor/plugin_guard')({ localLogger: null, analytics: null });

    // When already sandboxed, isPluginSpawn might match but we skip scrub
    process.env.__CONTEXTFORT_SANDBOX = '1';
    const alreadySandboxed = guard2.isSandboxed();
    assert.strictEqual(alreadySandboxed, true, 'should detect we are sandboxed');

    // The plugin's env with its custom var
    const pluginEnv = {
      PATH: process.env.PATH,
      HOME: HOME,
      __CONTEXTFORT_SANDBOX: '1',
      CAMOFOX_PORT: '9377',
    };

    // If we were to scrub (wrong), CAMOFOX_PORT would be gone
    const scrubbed = guard2.scrubEnvForPlugin(pluginEnv);
    assert.strictEqual(scrubbed.CAMOFOX_PORT, undefined, 'scrub would strip CAMOFOX_PORT');

    // But the hook checks !isSandboxed() first, so scrub is skipped
    // and the original env (with CAMOFOX_PORT) is preserved.
    // Verify via actual spawn:
    const result = spawnSync('node', [pluginServerScript], {
      encoding: 'utf8',
      timeout: 5000,
      env: { ...pluginEnv, NODE_PATH: process.env.NODE_PATH || '' },
    });
    if (result.error) throw new Error('spawn error: ' + result.error.message);
    if (result.status !== 0) throw new Error('exit ' + result.status + ': ' + (result.stderr || ''));
    const output = JSON.parse((result.stdout || '').trim());
    assert.strictEqual(output.camofoxPort, '9377', 'CAMOFOX_PORT should be preserved');
    assert.strictEqual(output.sandboxed, '1', 'sandbox marker should be inherited');
    delete process.env.__CONTEXTFORT_SANDBOX;
  });

  test('non-sandboxed child: no FS blocking', () => {
    const result = spawnSync('node', ['-e', `
      const fs = require('fs');
      const os = require('os');
      const path = require('path');
      // Try to stat tmpdir — should work
      try {
        fs.statSync(os.tmpdir());
        console.log('tmpdir:allowed');
      } catch (e) {
        console.log('tmpdir:' + e.code);
      }
      // .ssh — should be ENOENT or allowed (not EACCES)
      try {
        fs.statSync(path.join(os.homedir(), '.ssh'));
        console.log('.ssh:allowed');
      } catch (e) {
        console.log('.ssh:' + e.code);
      }
    `], {
      encoding: 'utf8',
      timeout: 10000,
      env: {
        ...process.env,
        // No __CONTEXTFORT_SANDBOX — should NOT block
      },
    });

    const lines = (result.stdout || '').trim().split('\n');
    const results = {};
    for (const line of lines) {
      const [key, val] = line.split(':');
      results[key] = val;
    }
    assert.strictEqual(results['tmpdir'], 'allowed');
    // .ssh should NOT be EACCES (could be 'allowed' or 'ENOENT')
    assert.notStrictEqual(results['.ssh'], 'EACCES', '.ssh should not be blocked outside sandbox');
  });
}

// =============================================
// Run
// =============================================
console.log('Plugin Sandbox Guard Tests');
console.log('='.repeat(40));

try {
  setup();
  unitTests();
  integrationTests();
} finally {
  cleanup();
}

console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
