'use strict';

/**
 * Tests for scanOutputForSecrets — verifies that known secret patterns
 * are detected and redacted, and that normal output is not affected.
 */

const { spawnSync } = require('child_process');
const guard = require('./index')({
  spawnSync,
  baseDir: require('path').join(__dirname, '..', '..'),
  analytics: null,
});

// Build test secret values at runtime to avoid triggering GitHub push protection.
// GitHub scans source for literal patterns like sk_live_*, xoxb-*, SK*, rk_live_*
// so we construct them dynamically from parts.
function fakeSecret(prefix, len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = prefix;
  while (s.length < prefix.length + len) s += chars[s.length % chars.length];
  return s;
}
const STRIPE_LIVE = fakeSecret('sk_' + 'live_', 30);
const STRIPE_TEST = fakeSecret('sk_' + 'test_', 30);
const STRIPE_RK = fakeSecret('rk_' + 'live_', 30);
const SLACK_BOT = 'xoxb' + '-0000000000000-0000000000000-' + fakeSecret('', 24);
const SLACK_HOOK = 'https://hooks.slack.com/services/T' + '00000000/B00000000/' + fakeSecret('', 24);
// Twilio pattern is SK + 32 hex chars. Build from parts.
const TWILIO_KEY = ['SK', '0a1b2c3d', '4e5f6a7b', '8c9d0e1f', '2a3b4c5d'].join('');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    console.error(`  FAIL: ${name}`);
    console.error(`    ${e.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

// === TRUE POSITIVES: Must be detected and redacted ===

test('Anthropic API key', () => {
  const output = 'Your key: sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Anthropic key');
  assert(result.secrets.some(s => s.name === 'Anthropic'), 'Should identify as Anthropic');
  assert(!result.redacted.includes('sk-ant-api03-'), 'Should redact the key');
  assert(result.redacted.includes('[REDACTED Anthropic secret]'), 'Should have replacement text');
});

test('OpenAI sk-proj key', () => {
  const output = 'key=sk-proj-abcdefghij1234567890abcdefghij1234567890abcdefghij';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect OpenAI key');
  assert(result.secrets.some(s => s.name === 'OpenAI'), 'Should identify as OpenAI');
  assert(!result.redacted.includes('sk-proj-'), 'Should redact');
});

test('OpenAI legacy sk- key (48 chars)', () => {
  const output = 'OPENAI_KEY=sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB3cD4eF';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect long sk- key');
});

test('AWS Access Key ID', () => {
  const output = 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect AWS key');
  assert(result.secrets.some(s => s.name.includes('AWS')), 'Should identify as AWS');
});

test('AWS Secret Access Key', () => {
  const output = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect AWS secret');
});

test('GitHub PAT ghp_', () => {
  const output = 'token: ghp_ABCDEFghijklmnopqrstuvwxyz1234567890';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect GitHub PAT');
  assert(result.secrets.some(s => s.name === 'GitHub'), 'Should identify as GitHub');
});

test('GitHub PAT github_pat_', () => {
  const output = 'GITHUB_TOKEN=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQ';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect github_pat_ token');
});

test('Stripe live key', () => {
  const output = 'stripe_key: ' + STRIPE_LIVE;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Stripe live key');
  assert(result.secrets.some(s => s.name === 'Stripe'), 'Should identify as Stripe');
});

test('Stripe test key', () => {
  const output = 'STRIPE_TEST=' + STRIPE_TEST;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Stripe test key');
});

test('Slack bot token xoxb-', () => {
  const output = 'SLACK_TOKEN=' + SLACK_BOT;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Slack bot token');
  assert(result.secrets.some(s => s.name === 'Slack'), 'Should identify as Slack');
});

test('Slack webhook URL', () => {
  const output = 'webhook: ' + SLACK_HOOK;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Slack webhook');
});

test('Twilio API key', () => {
  const output = 'TWILIO_KEY=' + TWILIO_KEY;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Twilio key');
  assert(result.secrets.some(s => s.name === 'Twilio'), 'Should identify as Twilio');
});

test('SendGrid API key', () => {
  const output = 'SENDGRID_KEY=SG.abcdefghijklmnopqrstuv.wxyz1234567890ABCDEFGHIJKLMNOPQRS';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect SendGrid key');
  assert(result.secrets.some(s => s.name === 'SendGrid'), 'Should identify as SendGrid');
});

test('Mailgun API key', () => {
  const output = 'MAILGUN_KEY=key-1234567890abcdef1234567890abcdef';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Mailgun key');
});

test('Google API key', () => {
  const output = 'GOOGLE_API_KEY=AIzaSyC-abcdefghijklmnopqrstuvwxyz12345';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Google API key');
  assert(result.secrets.some(s => s.name === 'Google API'), 'Should identify as Google API');
});

test('Supabase JWT (service_role)', () => {
  const output = 'service_role key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjk5MDAwMDAwLCJleHAiOjIwMTQ1NzYwMDB9.abcdefghijklmnop_1234567890ABCDEFG';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Supabase JWT');
  assert(result.secrets.some(s => s.name === 'Supabase JWT'), 'Should identify as Supabase JWT');
});

test('Private key header', () => {
  const output = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5...';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect private key');
  assert(result.secrets.some(s => s.name === 'Private Key'), 'Should identify as Private Key');
});

test('EC private key', () => {
  const output = '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect EC private key');
});

test('npm token', () => {
  const output = 'NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect npm token');
});

test('PyPI token', () => {
  const output = 'PYPI_TOKEN=pypi-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrSt';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect PyPI token');
});

test('Vault token', () => {
  const output = 'VAULT_TOKEN=hvs.abcdefghijklmnopqrstuvwx';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Vault token');
});

test('Labeled secret (api_key=...)', () => {
  const output = 'api_key: AbCdEf1234567890GhIjKlMnOpQrSt';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect labeled secret');
});

test('Labeled secret (secret_key=...)', () => {
  const output = "secret_key='AbCdEfGhIjKlMnOpQrStUvWx1234567890'";
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect labeled secret_key');
});

test('Datadog API key', () => {
  const output = 'dd-api-key: 1234567890abcdef1234567890abcdef';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Datadog key');
});

test('Multiple secrets in same output', () => {
  const output = `ANTHROPIC_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
OPENAI_KEY=sk-proj-abcdefghij1234567890abcdefghij1234567890
STRIPE_KEY=${STRIPE_LIVE}`;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect all secrets');
  assert(result.secrets.length >= 3, `Should find at least 3, found ${result.secrets.length}`);
  assert(!result.redacted.includes('sk-ant-api03-'), 'Should redact Anthropic');
  assert(!result.redacted.includes('sk-proj-'), 'Should redact OpenAI');
  assert(!result.redacted.includes('sk_live_'), 'Should redact Stripe');
});

test('supabase projects api-keys output format', () => {
  // Simulates actual `supabase projects api-keys` output
  const output = `   LINKED PROJECTS

   ORG ID        PROJECT ID            PROJECT NAME
   org-abc       lschqndjjwtyrlcojvly  myproject

   API KEYS
   NAME           API KEY
   anon           eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxzY2hxbmRqand0eXJsY29qdmx5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE2OTkwMDAwMDAsImV4cCI6MjAxNDU3NjAwMH0.fakeAnon1234567890
   service_role   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxzY2hxbmRqand0eXJsY29qdmx5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY5OTAwMDAwMCwiZXhwIjoyMDE0NTc2MDAwfQ.fakeService1234567890`;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Supabase JWTs in api-keys output');
  assert(result.secrets.length >= 2, `Should find at least 2 JWTs, found ${result.secrets.length}`);
  assert(!result.redacted.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSI'), 'Should redact the JWTs');
});

test('Heroku-like UUID near keyword', () => {
  const output = 'heroku api_key: 12345678-1234-1234-1234-123456789abc';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect UUID near heroku keyword');
});

test('Stripe restricted key rk_live_', () => {
  const output = 'STRIPE_RK=' + STRIPE_RK;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect Stripe restricted key');
});

// === TRUE NEGATIVES: Must NOT be detected ===

test('Normal git log output', () => {
  const output = `commit abc1234567890def
Author: John Doe <john@example.com>
Date:   Mon Jan 1 12:00:00 2024 +0000

    Fix authentication bug`;
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag normal git output');
});

test('Normal ls output', () => {
  const output = `total 32
drwxr-xr-x  5 user staff  160 Jan  1 12:00 .
drwxr-xr-x 10 user staff  320 Jan  1 12:00 ..
-rw-r--r--  1 user staff 1234 Jan  1 12:00 package.json
-rw-r--r--  1 user staff 5678 Jan  1 12:00 index.js`;
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag ls output');
});

test('Normal npm install output', () => {
  const output = `added 150 packages, and audited 200 packages in 10s
30 packages are looking for funding
  run \`npm fund\` for details
found 0 vulnerabilities`;
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag npm install output');
});

test('Short strings are ignored', () => {
  const result = guard.scanOutputForSecrets('ok');
  assert(!result.found, 'Should not flag very short output');
});

test('Empty output', () => {
  const result = guard.scanOutputForSecrets('');
  assert(!result.found, 'Should handle empty string');
});

test('Null output', () => {
  const result = guard.scanOutputForSecrets(null);
  assert(!result.found, 'Should handle null');
});

test('Normal UUID without secret keyword', () => {
  const output = 'Request ID: 12345678-1234-1234-1234-123456789abc processed successfully';
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag UUID without secret keyword nearby');
});

test('Code with sk- prefix but not a key', () => {
  const output = 'function sk_live() { return true; }';
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag short sk_ strings that are not keys');
});

test('Normal JSON output', () => {
  const output = '{"status":"ok","count":42,"items":[{"id":1,"name":"test"}]}';
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag normal JSON');
});

test('Git diff output', () => {
  const output = `diff --git a/file.js b/file.js
index 1234567..abcdefg 100644
--- a/file.js
+++ b/file.js
@@ -1,3 +1,3 @@
-const x = 1;
+const x = 2;`;
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag normal diff output');
});

test('Python traceback', () => {
  const output = `Traceback (most recent call last):
  File "main.py", line 10, in <module>
    raise ValueError("something went wrong")
ValueError: something went wrong`;
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag Python traceback');
});

test('Base64 encoded data (not labeled as secret)', () => {
  const output = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwADhQGAWjR9awAAAABJRU5ErkJggg==';
  const result = guard.scanOutputForSecrets(output);
  assert(!result.found, 'Should not flag base64 image data');
});

// === EDGE CASES ===

test('Secret embedded in JSON', () => {
  const output = '{"apiKey":"sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz","status":"ok"}';
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect secret in JSON');
});

test('Secret in multiline output', () => {
  const output = `Configuration:
  region: us-east-1
  access_key: AKIAIOSFODNN7EXAMPLE
  output: json`;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect AWS key in config-like output');
});

test('Same secret appearing twice', () => {
  const output = 'key1=' + STRIPE_LIVE + ' and again ' + STRIPE_LIVE;
  const result = guard.scanOutputForSecrets(output);
  assert(result.found, 'Should detect');
  assert(result.secrets.length === 1, `Should deduplicate, got ${result.secrets.length}`);
});

test('Redaction preserves surrounding text', () => {
  const output = 'Before the key sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz after the key';
  const result = guard.scanOutputForSecrets(output);
  assert(result.redacted.includes('Before the key'), 'Should preserve text before');
  assert(result.redacted.includes('after the key'), 'Should preserve text after');
  assert(result.redacted.includes('[REDACTED Anthropic secret]'), 'Should have replacement');
});

test('formatRedactionNotice includes type', () => {
  const output = 'key=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz';
  const result = guard.scanOutputForSecrets(output);
  const notice = guard.formatRedactionNotice(result);
  assert(notice.includes('Anthropic'), 'Notice should mention the type');
  assert(notice.includes('[SECURITY]'), 'Notice should have SECURITY prefix');
  assert(notice.includes('1 secret'), 'Notice should count secrets');
});

// === Summary ===
console.log(`\n  Output scanner tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
