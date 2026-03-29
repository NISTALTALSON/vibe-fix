#!/usr/bin/env node
/**
 * vibe-fix audit.js
 * Automated scanner for AI-generated code antipatterns in Node.js / JS / TS projects.
 * Usage: node scripts/audit.js [path] [--json]
 */

const fs = require('fs');
const path = require('path');

const SEVERITY = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
const SKIP_DIRS = new Set(['.git','node_modules','.next','dist','build','.turbo','coverage','.cache']);

const RULES = [
  // ── CRITICAL ──────────────────────────────────────────────────
  {
    sev: 'CRITICAL',
    regex: /(?:apiKey|api_key|secret|password|token)\s*[:=]\s*['"][a-zA-Z0-9\-_]{8,}['"]/gi,
    msg: 'Hardcoded secret in source code',
    fix: 'Move to process.env.YOUR_KEY and add to .env.example',
  },
  {
    sev: 'CRITICAL',
    regex: /['"`].*SELECT.*['"`]\s*\+/gi,
    msg: 'SQL query built with string concatenation — injection risk',
    fix: 'Use parameterized queries: db.query(sql, [params])',
  },
  {
    sev: 'CRITICAL',
    regex: /eval\s*\(/g,
    msg: 'eval() usage — remote code execution risk',
    fix: 'Avoid eval entirely. Use JSON.parse() or a proper parser.',
  },
  {
    sev: 'CRITICAL',
    regex: /innerHTML\s*=\s*(?!['"`]<)/g,
    msg: 'innerHTML assignment — potential XSS vector',
    fix: 'Use textContent, or sanitize input with DOMPurify',
  },

  // ── HIGH ──────────────────────────────────────────────────────
  {
    sev: 'HIGH',
    regex: /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/g,
    msg: 'Empty .catch() — errors silently swallowed',
    fix: 'Log the error: .catch(err => console.error(err))',
  },
  {
    sev: 'HIGH',
    regex: /} catch \(e\) \{\s*\}/gm,
    msg: 'Empty catch block — error ignored',
    fix: 'At minimum: catch(err) { console.error("[module]", err) }',
  },
  {
    sev: 'HIGH',
    regex: /process\.env\.[A-Z_]+(?!\s*\|\|)(?!\s*\?\?)/g,
    msg: 'env var accessed without fallback or validation',
    fix: 'Add: const val = process.env.KEY; if (!val) throw new Error("KEY not set")',
  },

  // ── MEDIUM ────────────────────────────────────────────────────
  {
    sev: 'MEDIUM',
    regex: /console\.log\s*\(\s*['"`]debug/gi,
    msg: 'Debug console.log left in code',
    fix: 'Remove or replace with a proper logger (winston, pino)',
  },
  {
    sev: 'MEDIUM',
    regex: /\/\/\s*(TODO|FIXME|HACK|XXX):/gi,
    msg: 'Unresolved TODO/FIXME',
    fix: 'Resolve or create a tracked GitHub issue',
  },
  {
    sev: 'MEDIUM',
    regex: /setTimeout\s*\(\s*(?:async\s*)?\(\s*\)\s*=>/g,
    msg: 'setTimeout with async callback — unhandled rejection risk',
    fix: 'Wrap inner async function in try/catch',
  },

  // ── LOW ───────────────────────────────────────────────────────
  {
    sev: 'LOW',
    regex: /var\s+\w+\s*=/g,
    msg: 'var declaration — prefer const/let',
    fix: 'Replace var with const (or let if reassigned)',
  },
  {
    sev: 'LOW',
    regex: /==(?!=)/g,
    msg: 'Loose equality == — prefer ===',
    fix: 'Use === for strict equality',
  },
];

const EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);

function walkDir(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walkDir(path.join(dir, entry.name));
    } else if (EXTENSIONS.has(path.extname(entry.name))) {
      files.push(path.join(dir, entry.name));
    }
  }
  return files;
}

function scanFile(filepath) {
  const issues = [];
  let content;
  try { content = fs.readFileSync(filepath, 'utf8'); } catch { return issues; }
  const lines = content.split('\n');

  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let match;
    while ((match = rule.regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      issues.push({
        severity: rule.sev,
        file: filepath,
        line: lineNum,
        message: rule.msg,
        fix: rule.fix,
        snippet: lines[lineNum - 1]?.trim().substring(0, 80),
      });
    }
  }
  return issues;
}

function printReport(issues, rootDir, totalFiles) {
  const bySev = sev => issues.filter(i => i.severity === sev);
  const riskLevel = issues.some(i => i.severity === 'CRITICAL') ? 'CRITICAL'
    : issues.some(i => i.severity === 'HIGH') ? 'HIGH'
    : issues.some(i => i.severity === 'MEDIUM') ? 'MEDIUM'
    : issues.length ? 'LOW' : 'CLEAN';

  const line = '═'.repeat(60);
  console.log('\n' + line);
  console.log('  🔧 VIBE-FIX AUDIT REPORT');
  console.log(line);
  console.log(`  Project  : ${path.basename(rootDir)}`);
  console.log(`  Files    : ${totalFiles} JS/TS scanned`);
  console.log(`  Risk     : ${EMOJI[riskLevel] || '✅'} ${riskLevel}`);
  console.log(`  Issues   : ${issues.length} total\n`);

  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    const items = bySev(sev);
    if (!items.length) continue;
    console.log(`${EMOJI[sev]}  ${sev} (${items.length})`);
    console.log('─'.repeat(60));
    for (const issue of items) {
      console.log(`  [${issue.file}:${issue.line}]`);
      if (issue.snippet) console.log(`  > ${issue.snippet}`);
      console.log(`  ↳ ${issue.message}`);
      console.log(`  ✔ Fix: ${issue.fix}\n`);
    }
  }

  if (!issues.length) console.log('  ✅ No issues found.\n');
  console.log(line + '\n');
}

// ── Main ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const rootDir = path.resolve(args.find(a => !a.startsWith('--')) || '.');
const asJson = args.includes('--json');

let allFiles;
try { allFiles = walkDir(rootDir); }
catch (e) { console.error('Cannot read directory:', rootDir); process.exit(1); }

const allIssues = allFiles.flatMap(scanFile);

// Deduplicate
const seen = new Set();
const unique = allIssues.filter(i => {
  const key = `${i.file}:${i.line}:${i.message}`;
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
});

if (asJson) {
  console.log(JSON.stringify({ project: path.basename(rootDir), issues: unique }, null, 2));
} else {
  printReport(unique, rootDir, allFiles.length);
}

process.exit(unique.some(i => i.severity === 'CRITICAL') ? 1 : 0);
