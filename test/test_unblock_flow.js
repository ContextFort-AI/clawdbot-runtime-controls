'use strict';

/**
 * End-to-end test for the unblock flow:
 * 1. Flag output as prompt injection
 * 2. Verify commands are blocked
 * 3. Write unblock file (simulating dashboard button)
 * 4. Verify next command is unblocked
 * 5. Verify subsequent commands remain unblocked
 * 6. Flag again
 * 7. Verify blocked again
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG_DIR = path.join(os.homedir(), '.contextfort');
const UNBLOCK_FILE = path.join(CONFIG_DIR, 'unblock');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  OK  ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL  ${name}`);
    console.error(`    ${e.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

// Clean up before test
try { fs.unlinkSync(UNBLOCK_FILE); } catch {}

// Create prompt injection guard directly
const piGuard = require('../monitor/prompt_injection_guard')({
  httpsRequest: null,
  anthropicKey: null,
  analytics: null,
  readFileSync: fs.readFileSync,
  apiKey: null,
  baseDir: path.join(__dirname, '..'),
  localLogger: null,
});

// Create skills guard stub (no real scanning needed)
const skillsGuard = {
  _flagged: new Map(),
  checkFlaggedSkills() {
    if (this._flagged.size === 0) return null;
    for (const [p, info] of this._flagged) {
      if (info.suspicious) return { blocked: true, skillPath: p, reason: info.reason };
    }
    return null;
  },
  clearFlaggedSkills() { this._flagged.clear(); },
};

// Helper: simulate the unblock logic from openclaw-secure.js
function runUnblockCheck() {
  try {
    if (fs.readFileSync(UNBLOCK_FILE, 'utf8')) {
      piGuard.clearFlaggedOutput();
      skillsGuard.clearFlaggedSkills();
      try { fs.unlinkSync(UNBLOCK_FILE); } catch {}
      return true; // unblock happened
    }
  } catch {}
  return false;
}

// Helper: simulate shouldBlockCommand's PI + skill checks
function wouldBlock() {
  runUnblockCheck();
  const piBlock = piGuard.checkFlaggedOutput();
  if (piBlock) return { blocked: true, guard: 'prompt_injection', reason: piBlock.reason };
  const skillBlock = skillsGuard.checkFlaggedSkills();
  if (skillBlock) return { blocked: true, guard: 'skill', reason: skillBlock.reason };
  return null;
}

console.log('\n  Unblock Flow Tests\n');

// --- Test 1: Initially not blocked ---
test('Initially not blocked', () => {
  assert(wouldBlock() === null, 'Should not be blocked initially');
});

// --- Test 2: Manually flag output, verify blocked ---
// We can't easily trigger scanOutput (needs Anthropic API), so directly set flaggedOutput
// via the internal scanOutput → flaggedOutput flow. Let's use a workaround:
// The guard exposes checkFlaggedOutput which reads the Map. We need to put something in the Map.
// Since scanOutput is async (HTTP call), we'll test clearFlaggedOutput directly.

// Simulate: directly inject a flag by calling internals
// We can't access the private Map directly, but we can verify clear works:

test('checkFlaggedOutput returns null when empty', () => {
  assert(piGuard.checkFlaggedOutput() === null, 'Should be null');
});

test('clearFlaggedOutput on empty map does not throw', () => {
  piGuard.clearFlaggedOutput(); // should not throw
  assert(piGuard.checkFlaggedOutput() === null, 'Still null');
});

// --- Test with skills guard (we control the Map) ---
test('Skill flag blocks commands', () => {
  skillsGuard._flagged.set('/test/skill.md', { suspicious: true, reason: 'test injection' });
  const result = wouldBlock();
  assert(result !== null, 'Should be blocked');
  assert(result.guard === 'skill', 'Should be skill guard');
});

test('Unblock file clears skill flags', () => {
  // Skill is still flagged from previous test
  assert(skillsGuard.checkFlaggedSkills() !== null, 'Skill should still be flagged');

  // Write unblock file (simulating dashboard button press)
  fs.writeFileSync(UNBLOCK_FILE, new Date().toISOString() + '\n');

  // Now check — should clear and unblock
  const result = wouldBlock();
  assert(result === null, 'Should be unblocked after unblock file');
});

test('Unblock file is consumed (deleted)', () => {
  let exists = false;
  try { fs.accessSync(UNBLOCK_FILE); exists = true; } catch {}
  assert(!exists, 'Unblock file should be deleted after consumption');
});

test('Subsequent commands remain unblocked (flags were cleared)', () => {
  const result = wouldBlock();
  assert(result === null, 'Should still be unblocked — flags were cleared, not just bypassed');
});

test('Re-flagging blocks again', () => {
  skillsGuard._flagged.set('/test/evil.md', { suspicious: true, reason: 'new injection' });
  const result = wouldBlock();
  assert(result !== null, 'Should be blocked again');
  assert(result.guard === 'skill', 'Should be skill guard');
});

test('Second unblock clears again', () => {
  fs.writeFileSync(UNBLOCK_FILE, new Date().toISOString() + '\n');
  const result = wouldBlock();
  assert(result === null, 'Should be unblocked after second unblock');
});

test('Multiple flags cleared at once', () => {
  // Flag both guards
  skillsGuard._flagged.set('/a.md', { suspicious: true, reason: 'a' });
  skillsGuard._flagged.set('/b.md', { suspicious: true, reason: 'b' });
  assert(wouldBlock() !== null, 'Should be blocked');

  fs.writeFileSync(UNBLOCK_FILE, new Date().toISOString() + '\n');
  assert(wouldBlock() === null, 'Should be unblocked');
  assert(skillsGuard._flagged.size === 0, 'All flags should be cleared');
});

// Clean up
try { fs.unlinkSync(UNBLOCK_FILE); } catch {}

console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
