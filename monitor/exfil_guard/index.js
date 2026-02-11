'use strict';

/**
 * Exfil Guard — detects when sensitive environment variables are being
 * transmitted to external servers via curl/wget/nc/httpie.
 *
 * When no allowlist is configured, this is a LOGGING-ONLY guard.
 * When a destination allowlist is active, commands sending secrets
 * to non-allowlisted domains are BLOCKED.
 */
module.exports = function createExfilGuard({ analytics, localLogger, readFileSync }) {
  const track = analytics ? analytics.track.bind(analytics) : () => {};
  const _readFileSync = readFileSync || require('fs').readFileSync;
  const _writeFileSync = require('fs').writeFileSync;
  const _mkdirSync = require('fs').mkdirSync;
  const _os = require('os');
  const _path = require('path');
  const CONFIG_DIR = _path.join(_os.homedir(), '.contextfort');
  const ALLOWLIST_FILE = _path.join(CONFIG_DIR, 'exfil_allowlist.json');

  // --- Destination allowlist ---
  let allowlist = null; // { enabled: bool, domains: string[] } or null (log-only)

  function loadAllowlist() {
    try {
      const raw = _readFileSync(ALLOWLIST_FILE, 'utf8').trim();
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.enabled === 'boolean' && Array.isArray(parsed.domains)) {
        allowlist = { enabled: parsed.enabled, domains: parsed.domains.filter(d => typeof d === 'string') };
      } else {
        allowlist = null;
      }
    } catch {
      allowlist = null;
    }
    return allowlist;
  }

  function saveAllowlist(data) {
    try { _mkdirSync(CONFIG_DIR, { recursive: true }); } catch {}
    _writeFileSync(ALLOWLIST_FILE, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
    allowlist = { enabled: data.enabled, domains: (data.domains || []).filter(d => typeof d === 'string') };
    return allowlist;
  }

  function getAllowlist() {
    return allowlist;
  }

  function isDestinationAllowed(destination) {
    if (!allowlist || !allowlist.enabled) return { allowed: true, matchedRule: null };
    if (!destination || destination === 'unknown') return { allowed: false, matchedRule: null };

    const dest = destination.toLowerCase();
    for (const rule of allowlist.domains) {
      const r = rule.toLowerCase();
      if (r.startsWith('*.')) {
        // Wildcard: *.supabase.co matches xyz.supabase.co, a.b.supabase.co
        const suffix = r.slice(1); // .supabase.co
        if (dest.endsWith(suffix) || dest === r.slice(2)) {
          return { allowed: true, matchedRule: rule };
        }
      } else {
        // Exact match
        if (dest === r) return { allowed: true, matchedRule: rule };
      }
    }
    return { allowed: false, matchedRule: null };
  }

  // --- Env var extraction (duplicated from secrets_guard to avoid coupling) ---

  const ENV_VAR_PATTERN = /\$([A-Z_][A-Z0-9_]{2,})\b|\$\{([A-Z_][A-Z0-9_]{2,})(?:[:#%\/]|:-|:\+|:=)[^}]*\}|\$\{([A-Z_][A-Z0-9_]{2,})\}/g;

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

  function filterSensitiveVars(vars) {
    return vars.filter(v => !SAFE_ENV_VARS.has(v));
  }

  // --- Exfil tool detection ---

  const EXFIL_TOOLS = [
    { name: 'curl', pattern: /\bcurl\b/ },
    { name: 'wget', pattern: /\bwget\b/ },
    { name: 'nc', pattern: /\b(?:nc|ncat|netcat)\b/ },
    { name: 'httpie', pattern: /\b(?:http|https)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD)\b/ },
    { name: 'openssl', pattern: /\bopenssl\s+s_client\b/ },
    { name: 'socat', pattern: /\bsocat\b/ },
    { name: 'telnet', pattern: /\btelnet\b/ },
  ];

  // Commands where the tool word appears but is NOT being invoked as a network tool.
  // These are string-context false positives.
  const NON_EXEC_PREFIXES = [
    /^\s*(?:git\s+(?:commit|log|show|diff|grep|blame))\b/,  // git commit -m "...curl..."
    /^\s*(?:grep|rg|ag|ack)\b/,         // grep for curl patterns
    /^\s*(?:sed|awk|perl\s+-[pi]e)\b/,  // sed/awk text processing
    /^\s*(?:man|info|whatis|apropos)\b/, // man curl
    /^\s*(?:which|where|type|command\s+-v|hash)\b/, // which curl
    /^\s*(?:brew|apt-get|apt|yum|dnf|pacman|apk|port)\s+(?:install|remove|uninstall|info|search)\b/, // package managers
    /^\s*(?:[A-Z_][A-Z0-9_]*=(?:"(?:[^"\\]|\\.)*"|'[^']*'|\$\([^)]*\)|[^\s'"]+)\s*)+$/,  // pure VAR=value assignment (no command follows)
  ];

  // Commands where tool word appears in string-only context (no pipe involved).
  // echo/printf are OK as prefixes ONLY when there's no pipe to a network tool.
  const STRING_ONLY_PREFIXES = [
    /^\s*(?:echo|printf)\b/,            // echo "use curl ..." (but NOT echo $VAR | curl)
  ];

  // Flags that take a local file/path argument (env var after these is NOT transmitted)
  const LOCAL_PATH_FLAGS = {
    curl: [
      /\s-o\s+/, /\s--output\s+/, /\s--output=/, // output file
      /\s-K\s+/, /\s--config\s+/,                 // config file
      /\s--cacert\s+/, /\s--capath\s+/,           // CA cert paths
      /\s-E\s+/, /\s--cert\s+/,                   // client cert
      /\s--key\s+/,                                // client key file
      /\s--ciphers\s+/,                            // cipher list
      /\s-D\s+/, /\s--dump-header\s+/,             // dump header to file
      /\s--trace\s+/, /\s--trace-ascii\s+/,        // trace output file
      /\s-T\s+/, /\s--upload-file\s+/,             // upload from file
    ],
    wget: [
      /\s-O\s+/, /\s--output-document\s+/, /\s--output-document=/,
      /\s-o\s+/, /\s--output-file\s+/,
      /\s-P\s+/, /\s--directory-prefix\s+/,
      /\s--ca-certificate\s+/,
    ],
  };

  // Filter out sensitive vars that only appear as the direct argument to a local-path flag
  // (e.g. curl -o $VAR). Returns the subset of vars that are in transmit positions.
  function filterVarsNotInLocalPaths(cmd, tool, sensitiveVars) {
    const flags = LOCAL_PATH_FLAGS[tool];
    if (!flags) return sensitiveVars;

    // Build a set of character ranges that are "local path" argument positions.
    // For each local-path flag match, the argument immediately after it is local.
    const localRanges = [];
    for (const fp of flags) {
      const regex = new RegExp(fp.source, 'g');
      let m;
      while ((m = regex.exec(cmd)) !== null) {
        // The argument starts right after the flag match
        const argStart = m.index + m[0].length;
        // The argument ends at the next whitespace (or end of string)
        const rest = cmd.slice(argStart);
        const argEnd = rest.search(/\s/) === -1 ? cmd.length : argStart + rest.search(/\s/);
        localRanges.push([argStart, argEnd]);
      }
    }

    return sensitiveVars.filter(varName => {
      const varPatterns = [
        new RegExp('\\$' + varName + '\\b', 'g'),
        new RegExp('\\$\\{' + varName + '[^}]*\\}', 'g'),
      ];

      for (const vp of varPatterns) {
        let match;
        while ((match = vp.exec(cmd)) !== null) {
          const pos = match.index;
          // Check if this var position falls inside any local-path argument range
          const inLocalRange = localRanges.some(([s, e]) => pos >= s && pos < e);
          if (!inLocalRange) return true; // at least one occurrence is NOT a local path arg
        }
      }
      return false; // all occurrences are in local-path argument positions
    });
  }

  // Extract destination hostname from a command
  function extractDestination(cmd) {
    // Match URLs: https://host.com/... or http://host.com/...
    const urlMatch = cmd.match(/https?:\/\/([^\/\s'"\\]+)/);
    if (urlMatch) return urlMatch[1];

    // For nc/ncat/telnet/openssl: tool hostname port
    const socketMatch = cmd.match(/\b(?:nc|ncat|netcat|telnet)\s+(?:-[a-z]+\s+)*([a-zA-Z0-9.-]+)\s+\d+/);
    if (socketMatch) return socketMatch[1];

    // openssl s_client -connect host:port
    const sslMatch = cmd.match(/s_client\s+.*-connect\s+([a-zA-Z0-9.-]+):\d+/);
    if (sslMatch) return sslMatch[1];

    // socat - TCP:host:port
    const socatMatch = cmd.match(/TCP[46]?:([a-zA-Z0-9.-]+):\d+/i);
    if (socatMatch) return socatMatch[1];

    return null;
  }

  // Determine the transmission method
  function detectMethod(cmd, tool) {
    if (tool === 'curl') {
      if (/\s-[Hh]\s/.test(cmd) || /--header\b/.test(cmd)) return 'header';
      if (/\s-[dD]\s/.test(cmd) || /--data\b/.test(cmd) || /--data-raw\b/.test(cmd)) return 'body';
      if (/\s-u\s/.test(cmd) || /--user\b/.test(cmd)) return 'auth';
      if (/\s-F\s/.test(cmd) || /--form\b/.test(cmd)) return 'form';
      return 'url';
    }
    if (tool === 'wget') {
      if (/--header\b/.test(cmd)) return 'header';
      if (/--post-data\b/.test(cmd) || /--post-file\b/.test(cmd)) return 'body';
      if (/--user\b/.test(cmd) || /--password\b/.test(cmd)) return 'auth';
      return 'url';
    }
    if (tool === 'nc' || tool === 'telnet' || tool === 'socat' || tool === 'openssl') return 'socket';
    if (tool === 'httpie') return 'httpie';
    return 'unknown';
  }

  /**
   * Check if a command transmits sensitive env vars to an external server.
   * Returns detection object or null.
   */
  function checkExfilAttempt(cmd) {
    if (!cmd || typeof cmd !== 'string') return null;

    // Skip commands where the tool word appears in a non-execution context
    for (const prefix of NON_EXEC_PREFIXES) {
      if (prefix.test(cmd)) return null;
    }

    // echo/printf are string-only IF there's no pipe to a network tool after them
    const hasPipeToNetwork = /\|\s*(?:curl|wget|nc|ncat|netcat|openssl|socat|telnet)\b/.test(cmd);
    if (!hasPipeToNetwork) {
      for (const prefix of STRING_ONLY_PREFIXES) {
        if (prefix.test(cmd)) return null;
      }
    }

    // Detect which exfil tool is present
    let detectedTool = null;
    for (const tool of EXFIL_TOOLS) {
      if (tool.pattern.test(cmd)) {
        detectedTool = tool.name;
        break;
      }
    }

    // Also detect pipe-to-exfil patterns: ... | curl, ... | nc, ... | openssl, ... | socat, ... | telnet
    if (!detectedTool) {
      const pipeMatch = cmd.match(/\|\s*(?:curl|wget|nc|ncat|netcat|openssl|socat|telnet)\b/);
      if (pipeMatch) {
        detectedTool = pipeMatch[0].replace(/^\|\s*/, '').trim();
        if (detectedTool === 'ncat' || detectedTool === 'netcat') detectedTool = 'nc';
      }
    }

    if (!detectedTool) return null;

    // Extract env var references and filter to sensitive ones
    const allVars = extractEnvVarRefs(cmd);
    if (allVars.length === 0) return null;

    const sensitiveVars = filterSensitiveVars(allVars);
    if (sensitiveVars.length === 0) return null;

    // Filter out vars that only appear in local-path positions (e.g. curl -o $VAR)
    const transmitVars = filterVarsNotInLocalPaths(cmd, detectedTool, sensitiveVars);
    if (transmitVars.length === 0) return null;

    // We have a network tool + sensitive env vars in transmit positions → detection
    const destination = extractDestination(cmd);
    const method = detectMethod(cmd, detectedTool);
    const dest = destination || 'unknown';

    // Check against allowlist
    const allowlistActive = !!(allowlist && allowlist.enabled);
    const allowlistInfo = allowlistActive ? isDestinationAllowed(dest) : null;
    const blocked = allowlistActive && (!allowlistInfo || !allowlistInfo.allowed);

    return {
      vars: transmitVars,
      destination: dest,
      tool: detectedTool,
      method,
      blocked,
      allowlistActive,
      allowlistInfo,
    };
  }

  function init() {
    loadAllowlist();
  }
  function cleanup() {}

  return {
    checkExfilAttempt,
    loadAllowlist,
    saveAllowlist,
    getAllowlist,
    isDestinationAllowed,
    init,
    cleanup,
  };
};
