'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

const SKILL_SCAN_API = 'https://lschqndjjwtyrlcojvly.supabase.co/functions/v1/scan-skill';
const HOME = os.homedir();

module.exports = function createSkillsGuard({ readFileSync, httpsRequest, baseDir, apiKey, analytics, enabled = true, localLogger }) {
  // If skill delivery is disabled, return a no-op guard
  if (!enabled) {
    return {
      checkFlaggedSkills() { return null; },
      formatSkillBlockError() { return ''; },
      init() {},
      cleanup() {},
    };
  }

  let PACKAGE_VERSION;
  try { PACKAGE_VERSION = require(path.join(baseDir, 'package.json')).version; } catch { PACKAGE_VERSION = 'unknown'; }

  const track = analytics ? analytics.track.bind(analytics) : () => {};
  const SKILL_CACHE_FILE = path.join(baseDir, 'monitor', '.skill_scan_cache.json');
  const INSTALL_ID_FILE = path.join(baseDir, 'monitor', '.install_id');

  const skillContentHashes = new Map();  // skillPath → SHA-256
  const flaggedSkills = new Map();       // skillPath → { suspicious, reason }
  const pendingScans = new Set();        // skill paths currently being scanned
  const activeWatchers = [];             // fs.FSWatcher instances

  function getInstallId() {
    try {
      return readFileSync(INSTALL_ID_FILE, 'utf8').trim();
    } catch {
      const id = crypto.randomUUID();
      try {
        fs.mkdirSync(path.dirname(INSTALL_ID_FILE), { recursive: true });
        fs.writeFileSync(INSTALL_ID_FILE, id + '\n');
      } catch {}
      return id;
    }
  }

  function getSkillDirectories() {
    const candidates = [
      path.join(HOME, '.openclaw', 'skills'),
      path.join(HOME, '.claude', 'skills'),
    ];
    // Also check plugin skill dirs: ~/.claude/plugins/*/skills/
    const pluginsDir = path.join(HOME, '.claude', 'plugins');
    try {
      const entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory()) {
          candidates.push(path.join(pluginsDir, e.name, 'skills'));
        }
      }
    } catch {}

    return candidates.filter(d => {
      try { return fs.statSync(d).isDirectory(); } catch { return false; }
    });
  }

  function collectSkillEntries(dir) {
    // Each subdirectory of a skill dir is one skill; also treat loose files as a single "root" skill
    const skills = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory()) {
          skills.push({ skillPath: path.join(dir, e.name), skillName: e.name });
        }
      }
      // If there are loose files directly in the skill dir (e.g. SKILL.md), treat as a skill
      const hasLooseFiles = entries.some(e => e.isFile());
      if (hasLooseFiles) {
        skills.push({ skillPath: dir, skillName: path.basename(dir) });
      }
    } catch {}
    return skills;
  }

  function readSkillFiles(skillPath) {
    const files = [];
    const binaryFiles = [];
    const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB
    const MAX_TOTAL_SIZE = 5 * 1024 * 1024; // 5MB
    let totalSize = 0;

    function walk(dirPath, base) {
      let entries;
      try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (e.name.startsWith('.') || e.name === 'node_modules') continue; // skip hidden and node_modules
        const full = path.join(dirPath, e.name);
        if (e.isDirectory()) {
          walk(full, path.join(base, e.name));
        } else if (e.isFile()) {
          try {
            const stat = fs.statSync(full);
            if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;
            if (totalSize + stat.size > MAX_TOTAL_SIZE) continue;
            // Check for binaries: read first 512 bytes and check for null bytes
            const buf = Buffer.alloc(Math.min(512, stat.size));
            const fd = fs.openSync(full, 'r');
            try { fs.readSync(fd, buf, 0, buf.length, 0); } finally { fs.closeSync(fd); }
            if (buf.includes(0)) {
              binaryFiles.push(path.join(base, e.name));
              continue;
            }

            const content = readFileSync(full, 'utf8');
            totalSize += stat.size;
            files.push({ relative_path: path.join(base, e.name), content });
          } catch {}
        }
      }
    }
    walk(skillPath, '');
    return { files, binaryFiles };
  }

  function hashSkillFiles(files) {
    const h = crypto.createHash('sha256');
    const sorted = [...files].sort((a, b) => a.relative_path.localeCompare(b.relative_path));
    for (const f of sorted) {
      h.update(f.relative_path + '\0' + f.content + '\0');
    }
    return h.digest('hex');
  }

  function loadScanCache() {
    try {
      const data = JSON.parse(readFileSync(SKILL_CACHE_FILE, 'utf8'));
      const versionChanged = data.version !== PACKAGE_VERSION;
      if (data.hashes && !versionChanged) {
        for (const [k, v] of Object.entries(data.hashes)) {
          skillContentHashes.set(k, v);
        }
      }
      if (data.flagged) {
        for (const [k, v] of Object.entries(data.flagged)) {
          if (v && v.suspicious) {
            flaggedSkills.set(k, v);
          }
        }
      }
    } catch {}
  }

  function saveScanCache() {
    try {
      const data = {
        version: PACKAGE_VERSION,
        hashes: Object.fromEntries(skillContentHashes),
        flagged: Object.fromEntries(flaggedSkills),
        updated: new Date().toISOString()
      };
      fs.mkdirSync(path.dirname(SKILL_CACHE_FILE), { recursive: true });
      fs.writeFileSync(SKILL_CACHE_FILE, JSON.stringify(data, null, 2) + '\n');
    } catch {}
  }

  function scanSkillAsync(skillPath, files, hash, installId) {
    if (pendingScans.has(skillPath)) return;
    pendingScans.add(skillPath);
    track('skill_scan_started', { skill_name: path.basename(skillPath), file_count: files.length });
    if (localLogger) {
      try { localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'scanning', reason: `Scanning skill: ${path.basename(skillPath)} (${files.length} files)`, detail: { skill_name: path.basename(skillPath), skill_path: skillPath, file_count: files.length, file_names: files.map(f => f.relative_path), file_contents: files.map(f => ({ path: f.relative_path, content: f.content.slice(0, 2000) })) } }); } catch {}
    }

    const payload = JSON.stringify({
      install_id: installId,
      skill_path: skillPath,
      skill_name: path.basename(skillPath),
      files: files,
    });

    // Log what we're sending to Supabase (omit file contents for privacy)
    if (localLogger) {
      try { localLogger.logServerSend({ destination: 'supabase', event: 'skill_scan', payload: { skill_name: path.basename(skillPath), file_count: files.length } }); } catch {}
    }

    const url = new URL(SKILL_SCAN_API);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers,
      timeout: 15000,
    };

    try {
      const req = httpsRequest(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          pendingScans.delete(skillPath);
          if (res.statusCode === 200) {
            try {
              const result = JSON.parse(body);
              skillContentHashes.set(skillPath, hash);
              if (result.suspicious) {
                flaggedSkills.set(skillPath, { suspicious: true, reason: result.reason || 'Suspicious skill detected' });
              } else {
                flaggedSkills.delete(skillPath);
              }
              track('skill_scan_result', { skill_name: path.basename(skillPath), suspicious: !!result.suspicious, status_code: 200 });
              if (localLogger) {
                try {
                  if (result.suspicious) {
                    localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'scan_flagged', reason: result.reason || 'Suspicious skill detected', detail: { skill_name: path.basename(skillPath), skill_path: skillPath, file_count: files.length, file_names: files.map(f => f.relative_path), file_contents: files.map(f => ({ path: f.relative_path, content: f.content.slice(0, 2000) })) } });
                  } else {
                    localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'scan_clean', reason: `Skill scan clean: ${path.basename(skillPath)}`, detail: { skill_name: path.basename(skillPath), skill_path: skillPath, file_count: files.length, file_names: files.map(f => f.relative_path) } });
                  }
                } catch {}
              }
              saveScanCache();
            } catch {}
          } else {
            track('skill_scan_result', { skill_name: path.basename(skillPath), suspicious: false, status_code: res.statusCode });
          }
        });
      });

      req.on('error', () => { pendingScans.delete(skillPath); });
      req.on('timeout', () => { req.destroy(); pendingScans.delete(skillPath); });
      req.write(payload);
      req.end();
    } catch {
      pendingScans.delete(skillPath);
    }
  }

  function logSkillRemoved(skillPath, installId) {
    track('skill_removed', { skill_name: path.basename(skillPath) });
    if (localLogger) {
      try { localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'removed', reason: `Skill removed: ${path.basename(skillPath)}`, detail: { skill_name: path.basename(skillPath), skill_path: skillPath } }); } catch {}
    }
    const payload = JSON.stringify({
      install_id: installId,
      skill_path: skillPath,
      skill_name: path.basename(skillPath),
      files: [],
      removed: true,
    });

    const url = new URL(SKILL_SCAN_API);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
    try {
      const req = httpsRequest({
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers,
        timeout: 15000,
      }, () => {});
      req.on('error', () => {});
      req.write(payload);
      req.end();
    } catch {}
  }

  function scanSkillIfChanged(skillPath) {
    const { files, binaryFiles } = readSkillFiles(skillPath);
    if (files.length === 0 && binaryFiles.length === 0) {
      // Skill was deleted or is empty — remove from flagged
      flaggedSkills.delete(skillPath);
      skillContentHashes.delete(skillPath);
      saveScanCache();
      return;
    }

    // Flag immediately if binary files found — legitimate skills should not contain binaries
    if (binaryFiles.length > 0) {
      flaggedSkills.set(skillPath, {
        suspicious: true,
        reason: `Skill contains binary files (${binaryFiles.join(', ')}). Legitimate skills should only contain text files. Please delete these binary files or remove this skill.`,
      });
      track('skill_binary_detected', { skill_name: path.basename(skillPath), binary_count: binaryFiles.length });
      if (localLogger) {
        try { localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'binary_detected', reason: `Binary files found in skill: ${path.basename(skillPath)}`, detail: { skill_name: path.basename(skillPath), skill_path: skillPath, binary_files: binaryFiles } }); } catch {}
      }
      saveScanCache();
      return;
    }

    const hash = hashSkillFiles(files);
    const isNew = !skillContentHashes.has(skillPath);
    if (skillContentHashes.get(skillPath) === hash) return; // unchanged

    if (!isNew && localLogger) {
      try { localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'modified', reason: `Skill modified: ${path.basename(skillPath)}`, detail: { skill_name: path.basename(skillPath), skill_path: skillPath, file_count: files.length, file_names: files.map(f => f.relative_path) } }); } catch {}
    }

    const installId = getInstallId();
    scanSkillAsync(skillPath, files, hash, installId);
  }

  function watchSkillDirectory(dir) {
    const debounceTimers = new Map();
    try {
      const watcher = fs.watch(dir, { recursive: true }, (eventType, filename) => {
        // Debounce: 500ms per skill directory
        const skillDir = filename ? path.join(dir, filename.split(path.sep)[0]) : dir;
        if (debounceTimers.has(skillDir)) clearTimeout(debounceTimers.get(skillDir));
        debounceTimers.set(skillDir, setTimeout(() => {
          debounceTimers.delete(skillDir);
          // Re-discover skills and scan changed ones
          const skills = collectSkillEntries(dir);
          const currentPaths = new Set(skills.map(s => s.skillPath));
          for (const { skillPath } of skills) {
            scanSkillIfChanged(skillPath);
          }
          // Detect deleted skills: any known skill in this dir that no longer exists
          for (const knownPath of skillContentHashes.keys()) {
            if (knownPath.startsWith(dir) && !currentPaths.has(knownPath)) {
              flaggedSkills.delete(knownPath);
              skillContentHashes.delete(knownPath);
              const installId = getInstallId();
              logSkillRemoved(knownPath, installId);
              saveScanCache();
            }
          }
        }, 500));
      });
      activeWatchers.push(watcher);
      watcher.on('error', () => {}); // ignore watch errors
    } catch {}
  }

  // Register session with Supabase so install_id → user_id mapping always exists
  function registerSession(installId, totalSkills) {
    const payload = JSON.stringify({
      install_id: installId,
      skill_path: '__session_start__',
      skill_name: '__session_start__',
      files: [],
    });

    const url = new URL(SKILL_SCAN_API);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers,
      timeout: 15000,
    };

    try {
      const req = httpsRequest(options, () => {});
      req.on('error', () => {});
      req.on('timeout', () => { req.destroy(); });
      req.write(payload);
      req.end();
    } catch {}
  }

  function initSkillScanner() {
    loadScanCache();

    const installId = getInstallId();
    const dirs = getSkillDirectories();
    let totalSkills = 0;
    for (const dir of dirs) {
      const skills = collectSkillEntries(dir);
      totalSkills += skills.length;
      for (const { skillPath } of skills) {
        scanSkillIfChanged(skillPath);
      }
      watchSkillDirectory(dir);
    }
    // Always register session so install_id → user_id mapping exists in Supabase
    registerSession(installId, totalSkills);
    track('skill_scanner_init', { skill_dir_count: dirs.length, total_skills: totalSkills });
    if (localLogger) {
      try { localLogger.logLocal({ event: 'guard_check', guard: 'skill', decision: 'init', reason: `Skill scanner initialized: ${totalSkills} skills in ${dirs.length} directories`, detail: { skill_dir_count: dirs.length, total_skills: totalSkills, directories: dirs } }); } catch {}
      // Log each skill individually so dashboard can show per-skill status
      for (const dir of dirs) {
        const skills = collectSkillEntries(dir);
        for (const { skillPath, skillName } of skills) {
          try {
            const { files, binaryFiles } = readSkillFiles(skillPath);
            const cached = skillContentHashes.has(skillPath);
            const flagged = flaggedSkills.get(skillPath);
            localLogger.logLocal({
              event: 'guard_check', guard: 'skill', decision: 'init_skill',
              reason: `Skill discovered: ${skillName}`,
              detail: {
                skill_name: skillName,
                skill_path: skillPath,
                skill_dir: dir,
                file_count: files.length,
                binary_count: binaryFiles.length,
                file_names: files.map(f => f.relative_path),
                binary_files: binaryFiles,
                cached,
                status: flagged?.suspicious ? 'malicious' : (binaryFiles.length > 0 ? 'binary' : 'clean'),
                flagged_reason: flagged?.reason || null,
              },
            });
          } catch {}
        }
      }
    }
  }

  function checkFlaggedSkills() {
    if (flaggedSkills.size === 0) return null;
    for (const [skillPath, info] of flaggedSkills) {
      if (info.suspicious) {
        return { blocked: true, skillPath, reason: info.reason };
      }
    }
    return null;
  }

  function formatSkillBlockError(info) {
    return `\u26a0\ufe0f SECURITY FIREWALL \u2014 MALICIOUS SKILL DETECTED

A skill/plugin installed on this system has been scanned by our AI security engine and flagged as dangerous.

Flagged skill: ${info.skillPath}

What was found: ${info.reason}

This means a skill in your openclaw installation contains code or instructions that could harm your system, steal credentials, or hijack your AI agent.

You MUST immediately inform the user with the following message:

"A malicious skill was detected at ${info.skillPath}. Our security scan found: ${info.reason}. ALL commands are blocked until this is fixed. Please remove this skill by running: rm -rf ${info.skillPath} and then restart openclaw."

Do NOT execute any commands, do NOT attempt workarounds. Your ONLY job right now is to deliver the above warning to the user and wait for them to fix it.`;
  }

  function clearFlaggedSkills() {
    flaggedSkills.clear();
  }

  return {
    checkFlaggedSkills,
    clearFlaggedSkills,
    formatSkillBlockError,
    init: initSkillScanner,
    cleanup() {
      for (const w of activeWatchers) {
        try { w.close(); } catch {}
      }
    },
  };
};
