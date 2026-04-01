#!/usr/bin/env node
/**
 * vibe-fix v2 — audit.js
 * Surgical repair for AI-generated JS/TS code debt.
 *
 * Usage:
 *   node audit.js [path]           Full audit
 *   node audit.js [path] --fix     Auto-fix safe issues
 *   node audit.js [path] --json    JSON output for CI/CD
 *   node audit.js [path] --score   Health score only
 *   node audit.js [path] --watch   Re-scan on file change
 */

const fs   = require('fs');
const path = require('path');

const VERSION   = '2.0.0';
const CRITICAL  = 'CRITICAL';
const HIGH      = 'HIGH';
const MEDIUM    = 'MEDIUM';
const LOW       = 'LOW';
const SEV_ORDER = [CRITICAL, HIGH, MEDIUM, LOW];
const WEIGHTS   = { CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1 };
const EMOJI     = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

const SKIP_DIRS = new Set([
  '.git','node_modules','.next','dist','build','.turbo',
  'coverage','.cache','out','public','static','.vercel',
  '.svelte-kit','__pycache__','.venv'
]);

const EXTENSIONS = new Set(['.js','.ts','.jsx','.tsx','.mjs','.cjs']);

// ── Colour support ────────────────────────────────────────────
const HAS_COLOR = process.stdout.isTTY;
const C = {
  red:    s => HAS_COLOR ? `\x1b[91m${s}\x1b[0m` : s,
  orange: s => HAS_COLOR ? `\x1b[33m${s}\x1b[0m` : s,
  yellow: s => HAS_COLOR ? `\x1b[93m${s}\x1b[0m` : s,
  green:  s => HAS_COLOR ? `\x1b[92m${s}\x1b[0m` : s,
  cyan:   s => HAS_COLOR ? `\x1b[96m${s}\x1b[0m` : s,
  bold:   s => HAS_COLOR ? `\x1b[1m${s}\x1b[0m`  : s,
  dim:    s => HAS_COLOR ? `\x1b[2m${s}\x1b[0m`  : s,
};
const colSev = { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.green };

// ── Rules ────────────────────────────────────────────────────
// [regex, severity, code, message, fix, autoFixable]
const RULES = [
  // ── CRITICAL ──────────────────────────────────────────────
  [/(?:apiKey|api_key|apiSecret|password|passwd|secret|token|authToken|privateKey|accessKey)\s*[:=]\s*['"`][a-zA-Z0-9\-_\.@#$%^&*]{6,}['"`]/gi,
   CRITICAL, 'SEC001', 'Hardcoded secret or credential in source',
   'Move to process.env.YOUR_KEY and add to .env.example', false],

  [/sk-[a-zA-Z0-9]{20,}/g,
   CRITICAL, 'SEC002', 'OpenAI API key hardcoded',
   "Use process.env.OPENAI_API_KEY", false],

  [/AKIA[0-9A-Z]{16}/g,
   CRITICAL, 'SEC003', 'AWS Access Key ID hardcoded',
   'Use AWS credential chain — never hardcode keys', false],

  [/ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{80,}/g,
   CRITICAL, 'SEC004', 'GitHub personal access token hardcoded',
   "Use process.env.GITHUB_TOKEN", false],

  [/['"`].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['"`]\s*\+/gi,
   CRITICAL, 'INJ001', 'SQL query built with string concatenation — injection risk',
   'Use parameterized queries: db.query(sql, [params])', false],

  [/`.*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{/gi,
   CRITICAL, 'INJ002', 'SQL query built with template literal — injection risk',
   'Use parameterized queries: db.query(sql, [params])', false],

  [/\beval\s*\(/g,
   CRITICAL, 'INJ003', 'eval() usage — remote code execution risk',
   'Never use eval(). Use JSON.parse() or a safe parser.', false],

  [/innerHTML\s*=(?!=)\s*(?!['"`]\s*['"`])/g,
   CRITICAL, 'INJ004', 'innerHTML assignment — XSS risk',
   'Use textContent, or sanitize with DOMPurify before assigning innerHTML', false],

  [/(?:exec|execSync)\s*\([^)]*\$\{/g,
   CRITICAL, 'INJ005', 'Shell command built with template literal — injection risk',
   'Use execFile() with argument array instead of string interpolation', false],

  // ── HIGH ──────────────────────────────────────────────────
  [/\.catch\s*\(\s*(?:\(\s*\)|_)\s*=>\s*\{\s*\}\s*\)/g,
   HIGH, 'ERR001', 'Empty .catch() — errors silently swallowed',
   "Handle the error: .catch(err => console.error('[module]', err))", true],

  [/}\s*catch\s*\([^)]*\)\s*\{\s*\}/g,
   HIGH, 'ERR002', 'Empty catch block — silent failure',
   "Log the error at minimum: catch(err) { console.error(err) }", true],

  [/process\.env\.[A-Z_]{3,}(?!\s*(?:\|\||&&|\?\?|,|\)))/g,
   HIGH, 'ENV001', 'env var used without fallback or validation',
   "Validate: const val = process.env.KEY; if (!val) throw new Error('KEY not set')", false],

  [/(?:fetch|axios\.get|axios\.post)\s*\([^)]+\)(?!\s*\.(?:then|catch|finally))/g,
   HIGH, 'NET001', 'Async HTTP call without error handling',
   'Add .catch() or use try/catch around await', false],

  [/setTimeout\s*\(\s*async/g,
   HIGH, 'ASYNC001', 'setTimeout with async callback — unhandled rejection risk',
   'Wrap the async body in try/catch', true],

  [/new Promise\s*\(\s*(?:async\s*)?\(?resolve/g,
   HIGH, 'ASYNC002', 'async function inside new Promise — anti-pattern',
   'Use async/await directly instead of wrapping in new Promise', false],

  // ── MEDIUM ────────────────────────────────────────────────
  [/console\.log\s*\(\s*['"`](?:debug|DEBUG|test|temp|TODO)/gi,
   MEDIUM, 'DBG001', 'Debug console.log left in production code',
   'Remove or replace with a structured logger (winston, pino)', true],

  [/\/\/\s*(?:TODO|FIXME|HACK|XXX|TEMP):/gi,
   MEDIUM, 'DEBT001', 'Unresolved TODO/FIXME comment',
   'Resolve or open a GitHub issue', false],

  [/localStorage\.(getItem|setItem)\s*\(['"]/g,
   MEDIUM, 'PERF001', 'Direct localStorage access — not SSR-safe, no error handling',
   'Wrap in try/catch and check for window existence first', false],

  [/\bvar\s+/g,
   MEDIUM, 'STYLE001', 'var declaration — prefer const/let',
   'Replace var with const (or let if reassigned)', true],

  [/==(?!=)/g,
   MEDIUM, 'STYLE002', 'Loose equality == — prefer ===',
   'Use === for strict equality', true],

  [/any(?:\s*[;,\)]|\s*=)/g,
   MEDIUM, 'TYPE001', 'TypeScript any type — defeats type safety',
   'Use a specific type or unknown', false],

  // ── LOW ───────────────────────────────────────────────────
  [/console\.log\s*\(/g,
   LOW, 'DBG002', 'console.log found — remove before production',
   'Replace with a logger or remove', false],

  [/(?<!\w)([0-9]{3,})(?!\w)/g,
   LOW, 'MAGIC001', 'Magic number — unexplained literal',
   'Extract to a named constant: const MAX_RETRIES = 3', false],
];

// ── Scanner ──────────────────────────────────────────────────
function scanFile(filepath) {
  const issues = [];
  let content;
  try { content = fs.readFileSync(filepath, 'utf8'); }
  catch { return issues; }

  const lines   = content.split('\n');
  const seen    = new Set();

  for (const [regex, sev, code, msg, fix, autoFix] of RULES) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      const key     = `${filepath}:${lineNum}:${code}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const snippet = (lines[lineNum - 1] || '').trim().substring(0, 80);
      issues.push({ severity: sev, file: filepath, line: lineNum, code, message: msg, fix, autoFix, snippet });
    }
  }

  // Function length check
  checkFunctionLength(filepath, content, lines, issues, seen);

  return issues;
}

function checkFunctionLength(filepath, content, lines, issues, seen) {
  const funcRegex = /(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>|(\w+)\s*\([^)]*\)\s*\{)/g;
  let match;
  while ((match = funcRegex.exec(content)) !== null) {
    const name      = match[1] || match[2] || match[3] || 'anonymous';
    const startLine = content.substring(0, match.index).split('\n').length;
    // Find matching brace
    let depth = 0, endLine = startLine;
    let i = match.index;
    while (i < content.length) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') {
        depth--;
        if (depth === 0) {
          endLine = content.substring(0, i).split('\n').length;
          break;
        }
      }
      i++;
    }
    const length = endLine - startLine;
    if (length > 50) {
      const key = `${filepath}:${startLine}:CMPLX001`;
      if (!seen.has(key)) {
        seen.add(key);
        issues.push({
          severity: HIGH, file: filepath, line: startLine, code: 'CMPLX001',
          message: `Function '${name}' is ${length} lines — too complex, split it up`,
          fix: 'Break into smaller single-responsibility functions',
          autoFix: false,
          snippet: (lines[startLine - 1] || '').trim().substring(0, 80),
        });
      }
    }
  }
}

// ── Project-level checks ─────────────────────────────────────
function checkGitignore(root) {
  const issues = [];
  const gi = path.join(root, '.gitignore');
  if (!fs.existsSync(gi)) {
    issues.push({ severity: HIGH, file: gi, line: 0, code: 'SEC006',
      message: '.gitignore missing — secrets may be committed to git',
      fix: 'Create .gitignore with at minimum: .env, node_modules/', autoFix: true, snippet: '' });
    return issues;
  }
  const content = fs.readFileSync(gi, 'utf8');
  for (const entry of ['.env', 'node_modules']) {
    if (!content.includes(entry)) {
      issues.push({ severity: MEDIUM, file: gi, line: 0, code: 'SEC007',
        message: `.gitignore is missing '${entry}'`,
        fix: `Add '${entry}' to .gitignore`, autoFix: true, snippet: '' });
    }
  }
  return issues;
}

function checkEnvExample(root, allContent) {
  const envExample = path.join(root, '.env.example');
  if (fs.existsSync(envExample)) return [];
  if (!allContent.includes('process.env.')) return [];
  return [{ severity: LOW, file: envExample, line: 0, code: 'ENV002',
    message: 'No .env.example — teammates don\'t know what env vars are required',
    fix: 'Create .env.example listing all required variable names (no real values)',
    autoFix: true, snippet: '' }];
}

function checkReadme(root) {
  for (const name of ['README.md', 'readme.md', 'README.txt']) {
    if (fs.existsSync(path.join(root, name))) return [];
  }
  return [{ severity: LOW, file: path.join(root, 'README.md'), line: 0, code: 'DOCS001',
    message: 'No README found — project is undocumented',
    fix: 'Create README.md with: description, install steps, env vars, usage',
    autoFix: true, snippet: '' }];
}

function checkTests(root) {
  const found = findFiles(root).some(f =>
    f.includes('test') || f.includes('spec') || f.includes('__tests__'));
  if (found) return [];
  return [{ severity: MEDIUM, file: root, line: 0, code: 'TEST001',
    message: 'No test files found — critical paths are untested',
    fix: 'Add at least one test for your most critical function',
    autoFix: false, snippet: '' }];
}

// ── Auto-fix ─────────────────────────────────────────────────
function autoFixFile(filepath, issues) {
  let content;
  try { content = fs.readFileSync(filepath, 'utf8'); }
  catch { return 0; }

  const original = content;
  let fixed = 0;

  for (const issue of issues) {
    if (!issue.autoFix || issue.file !== filepath) continue;

    if (issue.code === 'ERR001') {
      const newContent = content.replace(
        /\.catch\s*\(\s*(?:\(\s*\)|_)\s*=>\s*\{\s*\}\s*\)/g,
        ".catch(err => console.error('[vibe-fix] unhandled error:', err))"
      );
      if (newContent !== content) { content = newContent; fixed++; }
    }

    if (issue.code === 'ERR002') {
      const newContent = content.replace(
        /}\s*catch\s*\(([^)]*)\)\s*\{\s*\}/g,
        '} catch ($1) { console.error("[vibe-fix] caught error:", $1); }'
      );
      if (newContent !== content) { content = newContent; fixed++; }
    }

    if (issue.code === 'STYLE001') {
      const newContent = content.replace(/\bvar\s+/g, 'const ');
      if (newContent !== content) { content = newContent; fixed++; }
    }

    if (issue.code === 'STYLE002') {
      const newContent = content.replace(/([^=!<>])==(?!=)/g, '$1===');
      if (newContent !== content) { content = newContent; fixed++; }
    }

    if (issue.code === 'DBG001') {
      const newContent = content.replace(
        /\s*console\.log\s*\(\s*['"`](?:debug|DEBUG|test|temp|TODO)[^)]*\);\n?/gi, ''
      );
      if (newContent !== content) { content = newContent; fixed++; }
    }

    if (issue.code === 'ASYNC001') {
      const newContent = content.replace(
        /setTimeout\s*\(\s*async\s*\(\s*\)\s*=>\s*\{/g,
        'setTimeout(async () => { try {'
      );
      if (newContent !== content) { content = newContent; fixed++; }
    }
  }

  if (content !== original) {
    fs.writeFileSync(filepath + '.vibe-fix-backup', original);
    fs.writeFileSync(filepath, content);
  }
  return fixed;
}

function createEnvExample(root, allContent) {
  const envPath = path.join(root, '.env.example');
  if (fs.existsSync(envPath)) return;

  const vars = new Set();
  const re = /process\.env\.([A-Z_][A-Z0-9_]*)/g;
  let m;
  while ((m = re.exec(allContent)) !== null) vars.add(m[1]);

  const lines = [
    '# vibe-fix auto-generated .env.example',
    '# Copy to .env and fill in real values',
    '# NEVER commit .env to git\n',
    ...[...vars].sort().map(v => `${v}=`),
  ];
  if (vars.size === 0) lines.push('OPENAI_API_KEY=', 'DATABASE_URL=', 'SECRET_KEY=');

  fs.writeFileSync(envPath, lines.join('\n') + '\n');
  console.log(C.green(`  ✅ Created .env.example with ${vars.size} variable(s)`));
}

function createGitignore(root) {
  const gi = path.join(root, '.gitignore');
  if (fs.existsSync(gi)) return;
  fs.writeFileSync(gi, [
    '# vibe-fix generated .gitignore',
    '.env', '.env.local', '.env.production',
    'node_modules/', 'dist/', 'build/', '.next/',
    '*.log', 'logs/', '.DS_Store',
    'coverage/', '.turbo/', '.vercel/',
  ].join('\n') + '\n');
  console.log(C.green('  ✅ Created .gitignore'));
}

// ── File walker ──────────────────────────────────────────────
function findFiles(root) {
  const files = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name));
      } else if (EXTENSIONS.has(path.extname(e.name))) {
        files.push(path.join(dir, e.name));
      }
    }
  }
  walk(root);
  return files;
}

// ── Health score ─────────────────────────────────────────────
function healthScore(issues) {
  const deductions = issues.reduce((sum, i) => sum + (WEIGHTS[i.severity] || 0), 0);
  return Math.max(0, 100 - deductions);
}

function grade(score) {
  if (score >= 90) return ['A', C.green];
  if (score >= 75) return ['B', C.yellow];
  if (score >= 50) return ['C', C.orange];
  return ['F', C.red];
}

function riskLevel(issues) {
  for (const sev of SEV_ORDER) {
    if (issues.some(i => i.severity === sev)) return sev;
  }
  return 'CLEAN';
}

// ── Report ───────────────────────────────────────────────────
function printReport(issues, rootDir, totalFiles, jsFiles, durationMs, scoreOnly = false) {
  const score       = healthScore(issues);
  const [g, gColor] = grade(score);
  const risk        = riskLevel(issues);
  const autoCount   = issues.filter(i => i.autoFix).length;

  const barFilled = Math.floor(score / 5);
  const bar       = gColor('█'.repeat(barFilled)) + C.dim('░'.repeat(20 - barFilled));

  const riskColor = { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.green, CLEAN: C.green };

  console.log('\n' + C.cyan('═'.repeat(62)));
  console.log(`  ${C.bold('🔧 VIBE-FIX v' + VERSION + ' — AUDIT REPORT')}`);
  console.log(C.cyan('═'.repeat(62)));
  console.log(`  ${C.dim('Project')}  : ${C.bold(path.basename(rootDir))}`);
  console.log(`  ${C.dim('Files')}    : ${totalFiles} total · ${jsFiles} JS/TS scanned`);
  console.log(`  ${C.dim('Issues')}   : ${C.bold(String(issues.length))} total · ${autoCount} auto-fixable`);
  console.log(`  ${C.dim('Risk')}     : ${EMOJI[risk] || '✅'} ${(riskColor[risk] || C.green)(risk)}`);
  console.log(`  ${C.dim('Score')}    : [${bar}] ${gColor(score + '/100')} ${gColor('Grade: ' + g)}`);
  console.log(`  ${C.dim('Duration')} : ${durationMs}ms`);
  console.log(C.cyan('═'.repeat(62)) + '\n');

  if (scoreOnly) return;

  for (const sev of SEV_ORDER) {
    const items = issues.filter(i => i.severity === sev);
    if (!items.length) continue;
    const color = colSev[sev] || (s => s);
    console.log(`${EMOJI[sev]}  ${color(sev)} ${C.dim(`(${items.length} issue${items.length !== 1 ? 's' : ''})`)}`);
    console.log(C.dim('─'.repeat(62)));
    for (const issue of items) {
      let loc = issue.file;
      try { loc = path.relative(process.cwd(), issue.file); } catch {}
      if (issue.line) loc += `:${issue.line}`;
      const fixTag = issue.autoFix ? C.green(' [AUTO-FIXABLE]') : '';
      console.log(`  ${C.dim('[' + loc + ']')}${fixTag}`);
      if (issue.snippet) console.log(`  ${C.cyan('> ' + issue.snippet)}`);
      console.log(`  ${C.bold('↳')} ${issue.message}`);
      console.log(`  ${C.green('✔ Fix:')} ${issue.fix}\n`);
    }
  }

  if (!issues.length) console.log(C.green("  ✅ No issues found. Cleanest vibe-code I've seen.\n"));

  if (autoCount > 0) console.log(C.cyan(`  💡 Run with --fix to auto-resolve ${autoCount} issue(s)`));
  console.log(C.cyan('═'.repeat(62)));
  console.log(`  --fix         Auto-fix ${autoCount} safe issue(s)`);
  console.log(`  --json        Export JSON report for CI/CD`);
  console.log(`  --fix-secrets Generate .env.example from env vars`);
  console.log(`  --watch       Re-scan on every file change`);
  console.log(C.cyan('═'.repeat(62)) + '\n');
}

// ── Watch mode ───────────────────────────────────────────────
function getHashes(root) {
  const h = {};
  for (const f of findFiles(root)) {
    try { h[f] = require('crypto').createHash('md5').update(fs.readFileSync(f)).digest('hex'); }
    catch {}
  }
  return h;
}

function watchMode(root) {
  console.log(C.cyan(`  👁  Watching ${root} for changes... (Ctrl+C to stop)\n`));
  let lastHashes = {};
  setInterval(() => {
    const current = getHashes(root);
    if (JSON.stringify(current) !== JSON.stringify(lastHashes)) {
      lastHashes = current;
      process.stdout.write('\x1Bc');
      const { issues, totalFiles, jsFiles, durationMs, allContent } = runAudit(root);
      printReport(issues, root, totalFiles, jsFiles, durationMs);
    }
  }, 2000);
}

// ── Core runner ──────────────────────────────────────────────
function runAudit(root) {
  const t0    = Date.now();
  const files = findFiles(root);
  let allContent = '';
  let totalFiles = 0;
  try {
    const all = fs.readdirSync(root, { withFileTypes: true });
    totalFiles = all.length;
  } catch {}

  let all_issues = [];
  for (const f of files) {
    try { allContent += fs.readFileSync(f, 'utf8'); } catch {}
    all_issues = all_issues.concat(scanFile(f));
  }

  // Project-level checks
  all_issues = all_issues.concat(
    checkGitignore(root),
    checkEnvExample(root, allContent),
    checkReadme(root),
    checkTests(root),
  );

  // Deduplicate
  const seen = new Set();
  const unique = all_issues.filter(i => {
    const k = `${i.file}:${i.line}:${i.code}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  // Sort by severity
  const sevIdx = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  unique.sort((a, b) => (sevIdx[a.severity] ?? 9) - (sevIdx[b.severity] ?? 9) || a.file.localeCompare(b.file));

  return {
    issues: unique,
    totalFiles,
    jsFiles: files.length,
    durationMs: Date.now() - t0,
    allContent,
    files,
  };
}

// ── Main ────────────────────────────────────────────────────
const args       = process.argv.slice(2);
const rootArg    = args.find(a => !a.startsWith('--')) || '.';
const rootDir    = path.resolve(rootArg);
const doFix      = args.includes('--fix');
const doJson     = args.includes('--json');
const doScore    = args.includes('--score');
const doWatch    = args.includes('--watch');
const doSecrets  = args.includes('--fix-secrets');

if (!fs.existsSync(rootDir)) {
  console.error(C.red(`  ❌ Path not found: ${rootDir}`));
  process.exit(1);
}

if (doWatch) {
  watchMode(rootDir);
} else {
  const { issues, totalFiles, jsFiles, durationMs, allContent, files } = runAudit(rootDir);
  const score = healthScore(issues);

  if (doJson) {
    console.log(JSON.stringify({ project: path.basename(rootDir), version: VERSION, score, issues }, null, 2));
    process.exit(issues.some(i => i.severity === CRITICAL) ? 1 : 0);
  }

  if (doScore) {
    const [g, gColor] = grade(score);
    console.log(gColor(`  Health Score: ${score}/100 (Grade ${g})`));
    process.exit(0);
  }

  printReport(issues, rootDir, totalFiles, jsFiles, durationMs, false);

  if (doFix || doSecrets) {
    if (doFix) {
      console.log(C.cyan('  🔧 Running auto-fix...\n'));
      let totalFixed = 0;
      for (const f of files) {
        const fixable = issues.filter(i => i.file === f && i.autoFix);
        if (fixable.length) {
          const fixed = autoFixFile(f, fixable);
          if (fixed) {
            console.log(C.green(`  ✅ Fixed ${fixed} issue(s) in ${path.basename(f)}`));
            totalFixed += fixed;
          }
        }
      }
      if (!totalFixed) console.log(C.dim('  ℹ No auto-fixable issues found.'));
      else {
        const after = runAudit(rootDir);
        const gained = healthScore(after.issues) - score;
        console.log(C.green(`\n  Score improved: ${score} → ${healthScore(after.issues)} (+${gained})`));
      }
    }
    if (doSecrets || issues.some(i => ['ENV001','ENV002'].includes(i.code))) {
      createEnvExample(rootDir, allContent);
    }
    if (issues.some(i => ['SEC006','SEC007'].includes(i.code))) {
      createGitignore(rootDir);
    }
  }

  process.exit(issues.some(i => i.severity === CRITICAL) ? 1 : 0);
}
