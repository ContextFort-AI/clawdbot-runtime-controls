'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

const HOME = os.homedir();

/**
 * Secrets Guard — scans all directories OpenClaw can read for hardcoded secrets
 * using TruffleHog. Runs on init and on-demand via `openclaw-secure scan`.
 *
 * If hardcoded secrets exist, the LLM could read them directly from files.
 * This guard ensures secrets only exist as $ENV_VAR references, which the
 * bash guard monitors at runtime.
 */
module.exports = function createSecretsGuard({ spawnSync, baseDir, analytics }) {
  const track = analytics ? analytics.track.bind(analytics) : () => {};
  let trufflehogAvailable = null; // null = unknown, true/false after check

  /**
   * Check if trufflehog binary is available on the system
   */
  function isTrufflehogInstalled() {
    if (trufflehogAvailable !== null) return trufflehogAvailable;
    try {
      const result = spawnSync('trufflehog', ['--version'], {
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      trufflehogAvailable = result.status === 0;
    } catch {
      trufflehogAvailable = false;
    }
    return trufflehogAvailable;
  }

  /**
   * Get all directories that OpenClaw has read access to.
   * These are the attack surface for hardcoded secrets.
   */
  function getScanTargets(cwd) {
    const targets = [];

    // 1. Current working directory (project dir)
    if (cwd) {
      targets.push({ path: cwd, label: 'Project directory' });
    }

    // 2. OpenClaw config dirs
    const openclawDir = path.join(HOME, '.openclaw');
    if (dirExists(openclawDir)) {
      targets.push({ path: openclawDir, label: 'OpenClaw config (~/.openclaw/)' });
    }

    // 3. Claude config dirs
    const claudeDir = path.join(HOME, '.claude');
    if (dirExists(claudeDir)) {
      targets.push({ path: claudeDir, label: 'Claude config (~/.claude/)' });
    }

    // 4. Legacy config dirs
    const legacyDirs = [
      path.join(HOME, '.config', 'openclaw'),
      path.join(HOME, '.config', 'claude'),
    ];
    for (const d of legacyDirs) {
      if (dirExists(d)) {
        targets.push({ path: d, label: `Legacy config (${d.replace(HOME, '~')})` });
      }
    }

    return targets;
  }

  function dirExists(d) {
    try { return fs.statSync(d).isDirectory(); } catch { return false; }
  }

  /**
   * Run trufflehog on a single directory. Returns array of findings.
   * Uses --only-verified to reduce noise — only live secrets matter.
   */
  function scanDirectory(dirPath, onlyVerified = true) {
    const args = ['filesystem', dirPath, '--json'];
    if (onlyVerified) args.push('--only-verified');

    // Exclude common noisy dirs
    args.push('--exclude-paths');
    const excludeFile = path.join(baseDir, 'monitor', 'secrets_guard', '.trufflehog-exclude');
    ensureExcludeFile(excludeFile);
    args.push(excludeFile);

    try {
      const result = spawnSync('trufflehog', args, {
        encoding: 'utf8',
        timeout: 120000, // 2 minutes per directory
        maxBuffer: 10 * 1024 * 1024, // 10MB
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      if (result.error) return [];

      const stdout = (result.stdout || '').trim();
      if (!stdout) return [];

      // TruffleHog outputs one JSON object per line (NDJSON)
      const findings = [];
      for (const line of stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const finding = JSON.parse(trimmed);
          findings.push(normalizeFinding(finding));
        } catch {}
      }

      return findings;
    } catch {
      return [];
    }
  }

  /**
   * Normalize a TruffleHog finding into a clean, consistent format
   */
  function normalizeFinding(raw) {
    return {
      detectorName: raw.DetectorName || raw.detectorName || 'Unknown',
      verified: raw.Verified === true || raw.verified === true,
      raw: redactSecret(raw.Raw || raw.raw || ''),
      rawFull: raw.Raw || raw.raw || '',
      file: extractFilePath(raw),
      line: raw.SourceMetadata?.Data?.Filesystem?.line || null,
      detectorType: raw.DetectorType || raw.detectorType || null,
    };
  }

  /**
   * Redact a secret for display — show first 4 and last 4 chars only
   */
  function redactSecret(secret) {
    if (!secret || secret.length < 12) return '****';
    return secret.slice(0, 4) + '...' + secret.slice(-4);
  }

  /**
   * Extract the file path from a TruffleHog finding
   */
  function extractFilePath(raw) {
    // TruffleHog v3 nests file path under SourceMetadata.Data.Filesystem.file
    const meta = raw.SourceMetadata || raw.sourceMetadata || {};
    const data = meta.Data || meta.data || {};
    const fsData = data.Filesystem || data.filesystem || {};
    return fsData.file || null;
  }

  /**
   * Create the exclude patterns file for trufflehog
   */
  function ensureExcludeFile(filePath) {
    // TruffleHog --exclude-paths expects regex patterns, one per line
    const patterns = [
      'node_modules/',
      '\\.git/',
      '__pycache__/',
      '\\.pyc$',
      '\\.next/',
      'dist/',
      'build/',
      '\\.venv/',
      'venv/',
    ].join('\n') + '\n';

    try {
      // Only write if doesn't exist or different
      let existing = '';
      try { existing = fs.readFileSync(filePath, 'utf8'); } catch {}
      if (existing !== patterns) {
        fs.writeFileSync(filePath, patterns);
      }
    } catch {}
  }

  /**
   * Run a full scan of all OpenClaw-accessible directories.
   * Returns { targets, findings, summary }.
   */
  function scan(cwd, { onlyVerified = true, verbose = false } = {}) {
    if (!isTrufflehogInstalled()) {
      return {
        error: 'trufflehog is not installed. Install it with: brew install trufflehog',
        targets: [],
        findings: [],
        summary: null,
      };
    }

    const targets = getScanTargets(cwd);
    const allFindings = [];

    for (const target of targets) {
      const findings = scanDirectory(target.path, onlyVerified);
      for (const f of findings) {
        f.scanTarget = target.label;
        f.scanTargetPath = target.path;
      }
      allFindings.push(...findings);
    }

    // Deduplicate by file + detectorName + redacted secret
    const seen = new Set();
    const deduped = [];
    for (const f of allFindings) {
      const key = `${f.file}:${f.detectorName}:${f.raw}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(f);
      }
    }

    const verified = deduped.filter(f => f.verified);
    const unverified = deduped.filter(f => !f.verified);

    const result = {
      error: null,
      targets,
      findings: deduped,
      summary: {
        totalFindings: deduped.length,
        verifiedLive: verified.length,
        unverified: unverified.length,
        targetsScanned: targets.length,
        scannedAt: new Date().toISOString(),
      },
    };

    track('secrets_scan_complete', {
      targets_scanned: targets.length,
      total_findings: deduped.length,
      verified_live: verified.length,
    });

    return result;
  }

  /**
   * Format scan results for terminal display
   */
  function formatResults(result) {
    if (result.error) {
      return `\n  ERROR: ${result.error}\n`;
    }

    const lines = [];
    lines.push('');
    lines.push('  Scanning areas OpenClaw can access...');
    for (const t of result.targets) {
      lines.push(`    \u2713 ${t.label}`);
    }
    lines.push('');

    const verified = result.findings.filter(f => f.verified);
    const unverified = result.findings.filter(f => !f.verified);

    if (verified.length > 0) {
      lines.push(`  \u26a0  Found ${verified.length} LIVE hardcoded secret${verified.length > 1 ? 's' : ''}:\n`);
      verified.forEach((f, i) => {
        lines.push(`    ${i + 1}. ${f.detectorName} (VERIFIED LIVE)`);
        if (f.file) lines.push(`       File: ${f.file.replace(HOME, '~')}`);
        lines.push(`       Secret: ${f.raw}`);
        lines.push(`       Action: Rotate this secret and move to an environment variable`);
        lines.push('');
      });
    }

    if (unverified.length > 0 && verified.length === 0) {
      lines.push(`  Found ${unverified.length} potential secret${unverified.length > 1 ? 's' : ''} (unverified):\n`);
      unverified.forEach((f, i) => {
        lines.push(`    ${i + 1}. ${f.detectorName}`);
        if (f.file) lines.push(`       File: ${f.file.replace(HOME, '~')}`);
        lines.push(`       Secret: ${f.raw}`);
        lines.push('');
      });
    }

    if (result.findings.length === 0) {
      lines.push('  \u2713 No hardcoded secrets found in OpenClaw-accessible areas.');
      lines.push('  All secrets should be referenced via $ENV_VAR only.');
    }

    lines.push('');
    return lines.join('\n');
  }

  // =============================================
  // SOLVE — replace live secrets with dummy values
  // =============================================

  /**
   * Generate a dummy version of a secret by randomly mutating some characters.
   * Keeps same length and format so the file still looks normal.
   */
  function generateDummy(secret) {
    if (!secret || secret.length < 4) return 'REDACTED_BY_CONTEXTFORT';
    const chars = secret.split('');
    // Mutate ~30% of characters, but skip first 4 (prefix often identifies the key type)
    const startIdx = Math.min(4, chars.length - 1);
    const numToChange = Math.max(3, Math.floor((chars.length - startIdx) * 0.3));
    const indices = [];
    while (indices.length < numToChange) {
      const idx = startIdx + Math.floor(Math.random() * (chars.length - startIdx));
      if (!indices.includes(idx)) indices.push(idx);
    }
    for (const idx of indices) {
      const c = chars[idx];
      if (c >= '0' && c <= '9') {
        chars[idx] = String(Math.floor(Math.random() * 10));
      } else if (c >= 'a' && c <= 'z') {
        chars[idx] = String.fromCharCode(97 + Math.floor(Math.random() * 26));
      } else if (c >= 'A' && c <= 'Z') {
        chars[idx] = String.fromCharCode(65 + Math.floor(Math.random() * 26));
      } else {
        chars[idx] = String.fromCharCode(48 + Math.floor(Math.random() * 10));
      }
    }
    return chars.join('');
  }

  /**
   * Replace a live secret in a file with a dummy value.
   * Returns { success, file, original (redacted), dummy (redacted) } or { success: false, error }.
   */
  function replaceSecretInFile(filePath, realSecret) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      if (!content.includes(realSecret)) {
        return { success: false, file: filePath, error: 'Secret no longer found in file' };
      }
      const dummy = generateDummy(realSecret);
      const updated = content.split(realSecret).join(dummy);
      fs.writeFileSync(filePath, updated);
      return {
        success: true,
        file: filePath,
        original: redactSecret(realSecret),
        dummy: redactSecret(dummy),
      };
    } catch (e) {
      return { success: false, file: filePath, error: e.message };
    }
  }

  /**
   * Solve: replace all verified live secrets in files with dummy values.
   * Takes scan result findings and replaces each one.
   * Returns array of replacement results.
   */
  function solve(findings) {
    const verified = findings.filter(f => f.verified && f.rawFull && f.file);
    const results = [];

    // Group by unique secret value to avoid replacing same secret multiple times per file
    const byFile = new Map(); // file → [{ rawFull, detectorName }]
    for (const f of verified) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      const existing = byFile.get(f.file);
      if (!existing.some(e => e.rawFull === f.rawFull)) {
        existing.push(f);
      }
    }

    for (const [filePath, secrets] of byFile) {
      for (const s of secrets) {
        const r = replaceSecretInFile(filePath, s.rawFull);
        r.detectorName = s.detectorName;
        results.push(r);
      }
    }

    track('secrets_solve', {
      total_replaced: results.filter(r => r.success).length,
      total_failed: results.filter(r => !r.success).length,
    });

    return results;
  }

  /**
   * Format solve results for terminal display
   */
  function formatSolveResults(results) {
    const lines = [];
    const succeeded = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);

    if (succeeded.length > 0) {
      lines.push(`\n  Replaced ${succeeded.length} secret${succeeded.length > 1 ? 's' : ''} with dummy values:\n`);
      for (const r of succeeded) {
        lines.push(`    \u2713 ${r.file.replace(HOME, '~')}`);
        lines.push(`      ${r.detectorName}: ${r.original} -> ${r.dummy}`);
      }
    }

    if (failed.length > 0) {
      lines.push(`\n  Failed to replace ${failed.length}:\n`);
      for (const r of failed) {
        lines.push(`    \u2717 ${r.file.replace(HOME, '~')}: ${r.error}`);
      }
    }

    if (succeeded.length > 0) {
      lines.push('\n  These secrets are now invalidated in the files OpenClaw can read.');
      lines.push('  Remember to rotate the REAL secrets in their original services.');
    }

    lines.push('');
    return lines.join('\n');
  }

  // =============================================
  // ENV VAR MONITORING — block/log $VAR access
  // =============================================

  // Patterns that match env var references in shell commands
  // Covers $VAR, ${VAR}, ${VAR:-default}, ${VAR:+alt}, ${VAR:=val}
  // Does NOT match ${!PREFIX_*} (lists names, not values) or ${#VAR} (length)
  const ENV_VAR_PATTERN = /\$([A-Z_][A-Z0-9_]{2,})\b|\$\{([A-Z_][A-Z0-9_]{2,})(?:[:#%\/]|:-|:\+|:=)[^}]*\}|\$\{([A-Z_][A-Z0-9_]{2,})\}/g;

  // Env vars that are NOT secrets — safe to echo/print
  const SAFE_ENV_VARS = new Set([
    'HOME', 'USER', 'USERNAME', 'LOGNAME', 'SHELL', 'TERM', 'TERM_PROGRAM',
    'PATH', 'PWD', 'OLDPWD', 'HOSTNAME', 'LANG', 'LC_ALL', 'LC_CTYPE',
    'EDITOR', 'VISUAL', 'PAGER', 'BROWSER', 'DISPLAY', 'XDG_RUNTIME_DIR',
    'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME',
    'TMPDIR', 'TEMP', 'TMP', 'COLORTERM', 'COLUMNS', 'LINES',
    'SHLVL', 'HISTSIZE', 'HISTFILESIZE', 'HISTFILE', 'HISTCONTROL',
    'NODE_ENV', 'RAILS_ENV', 'RACK_ENV', 'FLASK_ENV', 'DJANGO_SETTINGS_MODULE',
    'GOPATH', 'GOROOT', 'CARGO_HOME', 'RUSTUP_HOME', 'JAVA_HOME',
    'NVM_DIR', 'PYENV_ROOT', 'RBENV_ROOT', 'VIRTUAL_ENV', 'CONDA_DEFAULT_ENV',
    'CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS',
    'ARCH', 'MACHTYPE', 'OSTYPE', 'VENDOR',
    'SSH_TTY', 'SSH_CONNECTION', 'SSH_CLIENT',
    'GPG_TTY', 'GNUPGHOME',
  ]);

  // Commands that would expose env var VALUES to stdout (LLM sees the output)
  // Category A: shell resolves $VAR, command prints the resolved value
  // Category B: language-specific env access that reads vars by name
  const VALUE_EXPOSING_COMMANDS = [
    // Category A — shell prints resolved $VAR
    /\becho\b/,
    /\bprintf\b/,
    /<<<\s*"?\$\{?[A-Z_]/,       // here-string: cat <<< $VAR, <<< "$VAR", <<< "${VAR}"
    // Category B — language env access
    /\bprintenv\s+\w/,          // printenv VAR_NAME
    /\bos\.environ/,            // python os.environ['KEY'] or os.environ.get
    /\bos\.getenv/,             // python os.getenv('KEY')
    /\bprocess\.env\b/,         // node process.env.KEY
    /\bENVIRON\s*\[/,           // awk ENVIRON["KEY"]
    /\$ENV\s*\{/,               // perl $ENV{KEY}
    /\bENV\s*\[/,               // ruby ENV["KEY"]
    /\bgetenv\s*\(/,            // php getenv("KEY")
    /\bSystem\.getenv/,         // java System.getenv
    /\bos\.Getenv/,             // go os.Getenv
  ];

  // Commands that dump ALL env vars (even without $VAR reference)
  const ENV_DUMP_COMMANDS = [
    /^\s*env\s*$/,               // bare `env` dumps everything
    /^\s*printenv\s*$/,          // bare `printenv` dumps everything
    /^\s*export\s+-p\s*$/,      // export -p dumps all
    /^\s*export\s*$/,            // bare export
    /\benv\s*\|/,               // env | grep ...
    /\bprintenv\s*\|/,          // printenv | grep ...
    /\bset\s*\|/,               // set | grep ...
    /\bcat\s+\/proc\/self\/environ/,
    /\bstrings\s+\/proc\/self\/environ/,
    /\bxxd\s+\/proc\/self\/environ/,
    /\bos\.environ\b/,          // python os.environ (full dict)
    /\bnode\b.*\bprocess\.env\b/,  // node ... process.env (only in node commands)
    /\bENVIRON\b/,              // awk ENVIRON (full array)
    /\$ENV\b/,                  // perl %ENV (full hash)
    /\bENV\.(to_a|each|keys|values|inspect|map|select|reject|sort)\b/, // ruby ENV iteration
    /\bdeclare\s+-[px]/,         // bash declare -p (dumps vars), declare -x (exported)
    /\btypeset\s+-p/,            // ksh/zsh typeset -p (dumps vars)
    /\bcompgen\s+-[ve]/,         // bash compgen -v (var names), -e (exported)
  ];

  /**
   * Extract all env var names referenced in a command.
   * Returns array of var names like ['STRIPE_KEY', 'AWS_SECRET_ACCESS_KEY'].
   */
  function extractEnvVarRefs(cmd) {
    if (!cmd || typeof cmd !== 'string') return [];
    const vars = new Set();
    let match;
    const regex = new RegExp(ENV_VAR_PATTERN.source, 'g');
    while ((match = regex.exec(cmd)) !== null) {
      vars.add(match[1] || match[2] || match[3]);
    }
    return [...vars];
  }

  /**
   * Filter out safe (non-secret) env vars from a list.
   * Returns only potentially sensitive vars.
   */
  function filterSensitiveVars(vars) {
    return vars.filter(v => !SAFE_ENV_VARS.has(v));
  }

  /**
   * Check if a command would expose env var values to stdout.
   * Returns { blocked, reason, vars } or null if safe.
   */
  function checkEnvVarLeak(cmd) {
    if (!cmd || typeof cmd !== 'string') return null;

    // Check for commands that dump ALL env vars
    for (const pattern of ENV_DUMP_COMMANDS) {
      if (pattern.test(cmd)) {
        return {
          blocked: true,
          reason: `Command dumps environment variables to output. OpenClaw would see all secret values. Use specific $VAR references in commands instead.`,
          vars: ['ALL'],
          type: 'env_dump',
          matched_pattern: pattern.source,
        };
      }
    }

    // Check for `printenv VAR_NAME` — exposes value without $ prefix
    const printenvMatch = cmd.match(/\bprintenv\s+([A-Z_][A-Z0-9_]{2,})\b/);
    if (printenvMatch) {
      return {
        blocked: true,
        reason: `Command would expose env var value to output: ${printenvMatch[1]}. OpenClaw would see the actual secret.`,
        vars: [printenvMatch[1]],
        type: 'value_exposed',
        matched_pattern: '\\bprintenv\\s+VAR_NAME',
      };
    }

    // Check for language-specific env access (no $ prefix needed)
    // These read env vars by name string, not shell expansion
    // IMPORTANT: Only match outside of quoted strings to avoid false positives
    // like echo "use process.env.KEY in your code"
    const LANG_ENV_ACCESS = [
      /\bos\.getenv\s*\(/,        // python os.getenv('KEY')
      /\bos\.environ\s*[\[.]/,    // python os.environ['KEY'] or os.environ.get
      /(?:^|[;|&])\s*node\b.*\bprocess\.env\b/,  // node -e "...process.env..." (only in node commands)
      /\bENVIRON\s*\[/,           // awk ENVIRON["KEY"]
      /\$ENV\s*\{/,               // perl $ENV{KEY}
      /\bENV\s*\[/,               // ruby ENV["KEY"]
      /\bENV\s*\./,               // ruby ENV.to_a, ENV.each, ENV.keys
      /\bgetenv\s*\(/,            // php getenv("KEY")
      /\bSystem\.getenv\s*\(/,    // java System.getenv("KEY")
      /\bos\.Getenv\s*\(/,        // go os.Getenv("KEY")
      /\bsubprocess\b.*\bprintenv\b/,  // python subprocess calling printenv
    ];
    for (const pattern of LANG_ENV_ACCESS) {
      if (pattern.test(cmd)) {
        return {
          blocked: true,
          reason: `Command reads environment variables via language API. OpenClaw would see the actual secret value in output.`,
          vars: ['LANG_ENV_ACCESS'],
          type: 'lang_env_access',
          matched_pattern: pattern.source,
        };
      }
    }

    // Check for $VAR references
    const allVars = extractEnvVarRefs(cmd);
    if (allVars.length === 0) return null;

    // Filter to only sensitive vars (ignore $HOME, $PATH, $USER, etc.)
    const sensitiveVars = filterSensitiveVars(allVars);

    // Check if this command would PRINT the var values to stdout
    const exposingPattern = VALUE_EXPOSING_COMMANDS.find(p => p.test(cmd));
    if (exposingPattern && sensitiveVars.length > 0) {
      return {
        blocked: true,
        reason: `Command would expose env var value(s) to output: ${sensitiveVars.join(', ')}. OpenClaw would see the actual secret. Use env vars directly in commands (e.g. curl -H "Bearer $TOKEN" ...) without echoing them.`,
        vars: sensitiveVars,
        type: 'value_exposed',
        matched_pattern: exposingPattern.source,
      };
    }

    // If only safe vars are being echoed, allow it
    if (exposingPattern && sensitiveVars.length === 0) {
      return null;
    }

    // Not exposing values — just log sensitive var usage
    if (sensitiveVars.length > 0) {
      return {
        blocked: false,
        reason: null,
        vars: sensitiveVars,
        type: 'env_ref_logged',
      };
    }

    return null;
  }

  /**
   * Format the block error for env var leak detection
   */
  function formatEnvVarBlockError(info) {
    return `\u26a0\ufe0f SECURITY FIREWALL \u2014 ENV VAR LEAK BLOCKED

This command was blocked because it would expose environment variable values to the AI agent's output.

What was detected: ${info.reason}

Environment variables referenced: ${info.vars.join(', ')}

If OpenClaw sees the actual secret value, it could be exfiltrated. Secrets should only be used as $VAR references inside commands (e.g. curl -H "Authorization: Bearer $API_KEY" https://api.example.com) — the shell resolves them without the AI ever seeing the value.

You MUST immediately inform the user:

"A command was blocked because it would have exposed secret values from environment variables (${info.vars.join(', ')}) to the AI agent. This protects against secret exfiltration. Use env var references ($VAR) directly in commands without echoing them."

Do NOT attempt workarounds. Do NOT use alternative commands to read these values.`;
  }

  // =============================================
  // OUTPUT SECRET SCANNER — redact secrets from
  // command output BEFORE the LLM sees them
  // =============================================

  // High-confidence regex patterns for known secret formats.
  // Ported from TruffleHog detector patterns + additions.
  // Each has: name, pattern, and an optional validator function.
  // These must be FAST (run on every command output) and LOW false-positive.
  const SECRET_OUTPUT_PATTERNS = [
    // === AI / LLM Providers ===
    { name: 'Anthropic', pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}/g },
    { name: 'OpenAI', pattern: /sk-proj-[A-Za-z0-9_-]{20,}/g },
    { name: 'OpenAI', pattern: /sk-[A-Za-z0-9]{40,}/g },
    { name: 'Cohere', pattern: /[a-zA-Z0-9]{40}/g, validate: (m, ctx) => { const n = ctx.slice(Math.max(0, ctx.indexOf(m) - 60), ctx.indexOf(m) + m.length + 60).toLowerCase(); return /cohere/.test(n); } },
    { name: 'Replicate', pattern: /r8_[A-Za-z0-9]{37}/g },
    { name: 'HuggingFace', pattern: /hf_[A-Za-z0-9]{34}/g },

    // === Cloud Providers ===
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret', pattern: /(?:aws_secret_access_key|secret_?key|SecretAccessKey)['":\s=]+([A-Za-z0-9/+=]{40})/gi, extract: 1 },
    { name: 'Google API', pattern: /AIza[A-Za-z0-9_-]{35}/g },
    { name: 'GCP Service Account', pattern: /"type"\s*:\s*"service_account"/g },
    { name: 'Azure Storage', pattern: /(?:AccountKey|SharedAccessKey)['":\s=]+([A-Za-z0-9/+=]{86,88})/gi, extract: 1 },
    { name: 'Azure AD', pattern: /(?:client_secret|clientSecret)['":\s=]+([A-Za-z0-9~._-]{34,})/gi, extract: 1 },
    { name: 'DigitalOcean PAT', pattern: /dop_v1_[a-f0-9]{64}/g },
    { name: 'DigitalOcean OAuth', pattern: /doo_v1_[a-f0-9]{64}/g },
    { name: 'DigitalOcean Spaces', pattern: /(?:spaces_access_key|SPACES_ACCESS)['":\s=]+([A-Z0-9]{20})/gi, extract: 1 },
    { name: 'Linode', pattern: /(?:linode_token|LINODE_TOKEN)['":\s=]+([a-f0-9]{64})/gi, extract: 1 },
    { name: 'Vultr', pattern: /(?:VULTR_API_KEY|vultr_api_key)['":\s=]+([A-Z0-9]{36})/gi, extract: 1 },

    // === Hosting / PaaS ===
    { name: 'Heroku', pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
      validate: (match, context) => {
        const nearby = context.slice(Math.max(0, context.indexOf(match) - 80), context.indexOf(match) + match.length + 80).toLowerCase();
        return /(?:heroku|api[_-]?key|token|secret|password|credential|authorization)/.test(nearby);
      }
    },
    { name: 'Vercel', pattern: /(?:vercel_token|VERCEL_TOKEN)['":\s=]+([A-Za-z0-9]{24})/gi, extract: 1 },
    { name: 'Netlify', pattern: /(?:netlify_token|NETLIFY_AUTH_TOKEN)['":\s=]+([A-Za-z0-9_-]{40,})/gi, extract: 1 },
    { name: 'Fly.io', pattern: /fo1_[A-Za-z0-9_-]{39}/g },
    { name: 'Render', pattern: /rnd_[A-Za-z0-9]{32,}/g },
    { name: 'Railway', pattern: /(?:RAILWAY_TOKEN)['":\s=]+([a-f0-9-]{36})/gi, extract: 1 },

    // === Git / CI/CD ===
    { name: 'GitHub', pattern: /ghp_[A-Za-z0-9]{36}/g },
    { name: 'GitHub', pattern: /gho_[A-Za-z0-9]{36}/g },
    { name: 'GitHub', pattern: /ghs_[A-Za-z0-9]{36}/g },
    { name: 'GitHub', pattern: /ghr_[A-Za-z0-9]{36}/g },
    { name: 'GitHub', pattern: /github_pat_[A-Za-z0-9_]{22,}/g },
    { name: 'GitLab PAT', pattern: /glpat-[A-Za-z0-9_-]{20}/g },
    { name: 'GitLab Deploy', pattern: /gldt-[A-Za-z0-9_-]{20,}/g },
    { name: 'GitLab Runner', pattern: /glrt-[A-Za-z0-9_-]{20,}/g },
    { name: 'GitLab Pipeline', pattern: /glptt-[A-Za-z0-9]{20,}/g },
    { name: 'Bitbucket', pattern: /(?:bitbucket_app_password|BITBUCKET_TOKEN)['":\s=]+([A-Za-z0-9]{18,})/gi, extract: 1 },
    { name: 'CircleCI', pattern: /(?:circle-token|CIRCLE_TOKEN)['":\s=]+([A-Za-z0-9]{40})/gi, extract: 1 },
    { name: 'Travis CI', pattern: /(?:TRAVIS_TOKEN|travis_token)['":\s=]+([A-Za-z0-9_-]{22,})/gi, extract: 1 },

    // === Payments ===
    { name: 'Stripe', pattern: /sk_live_[A-Za-z0-9]{24,}/g },
    { name: 'Stripe', pattern: /sk_test_[A-Za-z0-9]{24,}/g },
    { name: 'Stripe', pattern: /rk_live_[A-Za-z0-9]{24,}/g },
    { name: 'Stripe', pattern: /rk_test_[A-Za-z0-9]{24,}/g },
    { name: 'Stripe Webhook', pattern: /whsec_[A-Za-z0-9]{32,}/g },
    { name: 'PayPal', pattern: /(?:PAYPAL_SECRET|paypal_client_secret)['":\s=]+([A-Za-z0-9_-]{40,})/gi, extract: 1 },
    { name: 'Square', pattern: /sq0[a-z]{3}-[A-Za-z0-9_-]{22,}/g },
    { name: 'Braintree', pattern: /(?:braintree_private_key|BRAINTREE_PRIVATE)['":\s=]+([a-f0-9]{32})/gi, extract: 1 },
    { name: 'Adyen', pattern: /(?:adyen_api_key|ADYEN_KEY)['":\s=]+([A-Za-z0-9]{30,})/gi, extract: 1 },
    { name: 'Coinbase', pattern: /(?:coinbase_api_secret|COINBASE_SECRET)['":\s=]+([A-Za-z0-9/+=]{40,})/gi, extract: 1 },
    { name: 'Plaid', pattern: /(?:plaid_secret|PLAID_SECRET)['":\s=]+([a-f0-9]{30})/gi, extract: 1 },

    // === Communication ===
    { name: 'Slack', pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/g },
    { name: 'Slack', pattern: /xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/g },
    { name: 'Slack', pattern: /xoxs-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/g },
    { name: 'Slack', pattern: /xoxa-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/g },
    { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,}/g },
    { name: 'Telegram Bot', pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },
    { name: 'Discord Bot', pattern: /(?:mfa\.[a-z0-9_-]{20,})|(?:[a-z0-9_-]{24}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27,})/gi },
    { name: 'Discord Webhook', pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
    { name: 'Twilio', pattern: /SK[0-9a-f]{32}/g },
    { name: 'Twilio Auth', pattern: /(?:TWILIO_AUTH_TOKEN|twilio_auth_token)['":\s=]+([a-f0-9]{32})/gi, extract: 1 },
    { name: 'SendGrid', pattern: /SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}/g },
    { name: 'Mailgun', pattern: /key-[0-9a-f]{32}/g },
    { name: 'Mailchimp', pattern: /[a-f0-9]{32}-us\d{1,2}/g },
    { name: 'Postmark', pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
      validate: (m, ctx) => { const n = ctx.slice(Math.max(0, ctx.indexOf(m) - 60), ctx.indexOf(m) + m.length + 60).toLowerCase(); return /postmark/.test(n); }
    },
    { name: 'Intercom', pattern: /(?:INTERCOM_TOKEN|intercom_access_token)['":\s=]+([a-zA-Z0-9=_-]{40,})/gi, extract: 1 },

    // === Databases ===
    { name: 'Supabase JWT', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZSI[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
    { name: 'MongoDB', pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/\s'"]+/g },
    { name: 'PostgreSQL', pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/\s'"]+/g },
    { name: 'MySQL', pattern: /mysql:\/\/[^:]+:[^@]+@[^/\s'"]+/g },
    { name: 'Redis', pattern: /redis(?:s)?:\/\/[^:]*:[^@]+@[^/\s'"]+/g },
    { name: 'PlanetScale', pattern: /pscale_tkn_[A-Za-z0-9_-]{43}/g },
    { name: 'PlanetScale Password', pattern: /pscale_pw_[A-Za-z0-9_-]{43}/g },
    { name: 'CockroachDB', pattern: /(?:COCKROACH_URL|cockroach_url)['":\s=]+([^\s'"]+)/gi, extract: 1, validate: (m) => m.includes('@') },
    { name: 'Elasticsearch', pattern: /(?:ELASTIC_APM_SECRET|elastic_api_key)['":\s=]+([A-Za-z0-9_-]{20,})/gi, extract: 1 },
    { name: 'Firebase', pattern: /(?:FIREBASE_TOKEN|firebase_api_key)['":\s=]+([A-Za-z0-9_-]{30,})/gi, extract: 1 },

    // === Infrastructure / Networking ===
    { name: 'Cloudflare API', pattern: /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN)['":\s=]+([A-Za-z0-9_-]{40})/gi, extract: 1 },
    { name: 'Cloudflare Global', pattern: /(?:CF_API_KEY|CLOUDFLARE_API_KEY)['":\s=]+([a-f0-9]{37})/gi, extract: 1 },
    { name: 'Fastly', pattern: /(?:FASTLY_API_TOKEN|fastly_key)['":\s=]+([A-Za-z0-9_-]{32})/gi, extract: 1 },
    { name: 'Terraform', pattern: /(?:TFE_TOKEN|TERRAFORM_TOKEN)['":\s=]+([A-Za-z0-9._-]{14,})/gi, extract: 1 },
    { name: 'Pulumi', pattern: /pul-[a-f0-9]{40}/g },
    { name: 'Consul', pattern: /(?:CONSUL_HTTP_TOKEN|consul_token)['":\s=]+([a-f0-9-]{36})/gi, extract: 1 },
    { name: 'Doppler', pattern: /dp\.(?:st|ct|sa)\.[A-Za-z0-9]{40,}/g },

    // === Monitoring / Observability ===
    { name: 'Datadog', pattern: /(?:dd-api-key|dd-app-key|datadog_api_key|datadog_app_key|DD_API_KEY|DD_APP_KEY)['":\s=]+([a-f0-9]{32,40})/gi, extract: 1 },
    { name: 'New Relic', pattern: /(?:NEW_RELIC_LICENSE_KEY|NRLS-)[A-Za-z0-9]{30,}/gi },
    { name: 'New Relic User', pattern: /NRAK-[A-Z0-9]{27}/g },
    { name: 'Sentry', pattern: /sntrys_[A-Za-z0-9]{40,}/g },
    { name: 'Sentry DSN', pattern: /https:\/\/[a-f0-9]{32}@[^/]+\.ingest\.sentry\.io\/\d+/g },
    { name: 'Grafana', pattern: /glc_[A-Za-z0-9_+/=-]{32,}/g },
    { name: 'Grafana SA', pattern: /glsa_[A-Za-z0-9_+/=-]{32,}/g },
    { name: 'PagerDuty', pattern: /(?:PAGERDUTY_TOKEN|pagerduty_api_key)['":\s=]+([A-Za-z0-9_+/-]{20})/gi, extract: 1 },
    { name: 'Logz.io', pattern: /(?:LOGZIO_TOKEN|logzio_token)['":\s=]+([A-Za-z0-9]{32})/gi, extract: 1 },

    // === SaaS / APIs ===
    { name: 'Notion', pattern: /secret_[A-Za-z0-9]{43}/g },
    { name: 'Notion', pattern: /ntn_[A-Za-z0-9]{50,}/g },
    { name: 'Airtable', pattern: /pat[A-Za-z0-9]{14}\.[a-f0-9]{64}/g },
    { name: 'Linear', pattern: /lin_api_[A-Za-z0-9]{40}/g },
    { name: 'Asana', pattern: /(?:ASANA_TOKEN|asana_personal_access)['":\s=]+(\d+\/\d+:[A-Za-z0-9]{32})/gi, extract: 1 },
    { name: 'Jira', pattern: /(?:JIRA_API_TOKEN|jira_token)['":\s=]+([A-Za-z0-9+/=]{24,})/gi, extract: 1 },
    { name: 'Confluence', pattern: /(?:CONFLUENCE_TOKEN|confluence_api_token)['":\s=]+([A-Za-z0-9+/=]{24,})/gi, extract: 1 },
    { name: 'HubSpot', pattern: /(?:HUBSPOT_API_KEY|hubspot_api_key)['":\s=]+([a-f0-9-]{36})/gi, extract: 1 },
    { name: 'Shopify', pattern: /shpat_[a-fA-F0-9]{32}/g },
    { name: 'Shopify', pattern: /shpss_[a-fA-F0-9]{32}/g },
    { name: 'Shopify', pattern: /shppa_[a-fA-F0-9]{32}/g },
    { name: 'Contentful', pattern: /CFPAT-[A-Za-z0-9_-]{43}/g },
    { name: 'Algolia Admin', pattern: /(?:ALGOLIA_ADMIN_KEY|algolia_api_key)['":\s=]+([a-f0-9]{32})/gi, extract: 1 },
    { name: 'Mapbox', pattern: /sk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
    { name: 'Mapbox', pattern: /pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
    { name: 'Twitch', pattern: /(?:TWITCH_CLIENT_SECRET|twitch_secret)['":\s=]+([A-Za-z0-9]{30})/gi, extract: 1 },
    { name: 'Twitter/X', pattern: /(?:TWITTER_BEARER|twitter_api_secret)['":\s=]+([A-Za-z0-9_-]{40,})/gi, extract: 1 },
    { name: 'Zendesk', pattern: /(?:ZENDESK_TOKEN|zendesk_api_token)['":\s=]+([A-Za-z0-9]{40})/gi, extract: 1 },
    { name: 'Freshdesk', pattern: /(?:FRESHDESK_API_KEY|freshdesk_key)['":\s=]+([A-Za-z0-9]{20})/gi, extract: 1 },

    // === Auth Providers ===
    { name: 'Okta', pattern: /(?:OKTA_TOKEN|okta_api_token)['":\s=]+([A-Za-z0-9_-]{42})/gi, extract: 1 },
    { name: 'Auth0', pattern: /(?:AUTH0_CLIENT_SECRET|auth0_secret)['":\s=]+([A-Za-z0-9_-]{40,})/gi, extract: 1 },
    { name: 'Clerk', pattern: /sk_live_[A-Za-z0-9]{40,}/g },
    { name: 'Clerk', pattern: /sk_test_[A-Za-z0-9]{40,}/g },

    // === Package Registries ===
    { name: 'npm', pattern: /npm_[A-Za-z0-9]{36}/g },
    { name: 'PyPI', pattern: /pypi-[A-Za-z0-9_-]{50,}/g },
    { name: 'RubyGems', pattern: /rubygems_[a-f0-9]{48}/g },
    { name: 'NuGet', pattern: /oy2[a-z0-9]{43}/g },

    // === Secrets Management ===
    { name: 'Vault', pattern: /hvs\.[A-Za-z0-9_-]{24,}/g },
    { name: '1Password', pattern: /ops_[A-Za-z0-9_-]{50,}/g },
    { name: 'Doppler', pattern: /dp\.(?:st|ct|sa)\.[A-Za-z0-9]{40,}/g },
    { name: 'Age Key', pattern: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g },

    // === Crypto / Keys ===
    { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
    { name: 'PGP Private', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },

    // === Misc Services ===
    { name: 'Postman', pattern: /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/g },
    { name: 'Databricks', pattern: /dapi[a-f0-9]{32}/g },
    { name: 'Livekit', pattern: /(?:LIVEKIT_API_SECRET|livekit_secret)['":\s=]+([A-Za-z0-9]{32,})/gi, extract: 1 },

    // === Generic labeled secrets (catch-all) ===
    { name: 'Labeled Secret', pattern: /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|service[_-]?key|private[_-]?key|password|credential|bearer)['":\s=]+([A-Za-z0-9_/+=-]{20,})/gi, extract: 1 },

    // === Connection strings with embedded passwords ===
    { name: 'Connection String', pattern: /(?:amqps?|nats|kafka):\/\/[^:]+:[^@]+@[^/\s'"]+/g },
  ];

  /**
   * Scan command output for secrets. Returns { found, secrets, redacted }.
   * This runs SYNCHRONOUSLY before output is returned to OpenClaw.
   */
  function scanOutputForSecrets(output) {
    if (!output || typeof output !== 'string' || output.length < 10) {
      return { found: false, secrets: [], redacted: output };
    }

    const foundSecrets = []; // { name, match, start, end }

    for (const detector of SECRET_OUTPUT_PATTERNS) {
      // Reset regex lastIndex — ensure 'g' flag to prevent infinite exec() loop
      const flags = detector.pattern.flags.includes('g') ? detector.pattern.flags : detector.pattern.flags + 'g';
      const regex = new RegExp(detector.pattern.source, flags);
      let m;
      while ((m = regex.exec(output)) !== null) {
        const secret = detector.extract ? m[detector.extract] : m[0];
        if (!secret || secret.length < 8) continue;

        // Run optional validator
        if (detector.validate && !detector.validate(secret, output)) continue;

        foundSecrets.push({
          name: detector.name,
          match: secret,
          start: m.index,
          end: m.index + m[0].length,
        });
      }
    }

    if (foundSecrets.length === 0) {
      return { found: false, secrets: [], redacted: output };
    }

    // Deduplicate by match value
    const seen = new Set();
    const unique = [];
    for (const s of foundSecrets) {
      if (!seen.has(s.match)) {
        seen.add(s.match);
        unique.push(s);
      }
    }

    // Redact all found secrets in output
    let redacted = output;
    for (const s of unique) {
      const replacement = `[REDACTED ${s.name} secret]`;
      redacted = redacted.split(s.match).join(replacement);
    }

    track('output_secrets_redacted', {
      count: unique.length,
      types: [...new Set(unique.map(s => s.name))],
    });

    return {
      found: true,
      secrets: unique.map(s => ({
        name: s.name,
        redacted: redactSecret(s.match),
      })),
      redacted,
    };
  }

  /**
   * Format the redaction notice appended to output
   */
  function formatRedactionNotice(scanResult) {
    const types = [...new Set(scanResult.secrets.map(s => s.name))].join(', ');
    return `\n\n[SECURITY] ${scanResult.secrets.length} secret(s) redacted from output (${types}). The AI agent cannot see the actual values.`;
  }

  return {
    scan,
    scanDirectory,
    getScanTargets,
    formatResults,
    isTrufflehogInstalled,
    solve,
    formatSolveResults,
    generateDummy,
    checkEnvVarLeak,
    extractEnvVarRefs,
    formatEnvVarBlockError,
    scanOutputForSecrets,
    formatRedactionNotice,
  };
};
