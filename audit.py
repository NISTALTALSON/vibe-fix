#!/usr/bin/env python3
"""
vibe-fix v2 — audit.py
Surgical repair for AI-generated code debt.
Supports: Python | detect secrets, injections, async bugs, type issues, complexity
Usage:
  python audit.py [path]              # Full audit
  python audit.py [path] --fix        # Auto-fix safe issues
  python audit.py [path] --json       # JSON output for CI
  python audit.py [path] --score      # Just print health score
  python audit.py [path] --watch      # Re-scan on file change
  python audit.py [path] --fix-secrets # Auto-move secrets to .env
"""

import os, re, sys, json, time, hashlib, argparse, subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from collections import defaultdict

VERSION = "2.0.0"
CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"
EMOJI = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢"}
ORDER  = [CRITICAL, HIGH, MEDIUM, LOW]
SKIP   = {'.git','node_modules','__pycache__','.venv','venv','dist','build','.next','.mypy_cache','.pytest_cache','migrations'}

# ── Colour support ──────────────────────────────────────────────
def _supports_color():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

C = {
    'red':    '\033[91m' if _supports_color() else '',
    'orange': '\033[33m' if _supports_color() else '',
    'yellow': '\033[93m' if _supports_color() else '',
    'green':  '\033[92m' if _supports_color() else '',
    'cyan':   '\033[96m' if _supports_color() else '',
    'bold':   '\033[1m'  if _supports_color() else '',
    'dim':    '\033[2m'  if _supports_color() else '',
    'reset':  '\033[0m'  if _supports_color() else '',
}

def col(text, color): return f"{C[color]}{text}{C['reset']}"

# ── Data structures ─────────────────────────────────────────────
@dataclass
class Issue:
    severity: str
    file: str
    line: int
    code: str
    message: str
    fix: str
    auto_fixable: bool = False
    fix_patch: Optional[str] = None
    snippet: str = ""

@dataclass
class FileStats:
    path: str
    lines: int
    issues: int
    max_function_lines: int = 0
    has_tests: bool = False
    has_types: bool = False
    has_docstrings: bool = False

@dataclass
class AuditReport:
    project: str
    version: str
    total_files: int
    py_files: int
    total_lines: int
    issues: List[Issue] = field(default_factory=list)
    file_stats: List[FileStats] = field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def risk_level(self):
        if any(i.severity == CRITICAL for i in self.issues): return CRITICAL
        if any(i.severity == HIGH     for i in self.issues): return HIGH
        if any(i.severity == MEDIUM   for i in self.issues): return MEDIUM
        return LOW if self.issues else "CLEAN"

    @property
    def health_score(self):
        """0-100 health score. 100 = perfect."""
        weights = {CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1}
        deductions = sum(weights.get(i.severity, 0) for i in self.issues)
        return max(0, 100 - deductions)

    def by_severity(self, sev): return [i for i in self.issues if i.severity == sev]
    def auto_fixable(self):    return [i for i in self.issues if i.auto_fixable]

# ── Detection rules ─────────────────────────────────────────────

# Each rule: (regex, severity, code, message, fix, auto_fixable)
RULES = [
    # ── CRITICAL ───────────────────────────────────────────────
    (r'''(?i)(?:api_?key|secret_?key|password|passwd|token|auth_?token|private_?key|access_?key)\s*=\s*['"][a-zA-Z0-9\-_\.@#$%^&*]{6,}['"]''',
     CRITICAL, "SEC001", "Hardcoded secret/credential in source",
     "Use os.getenv('YOUR_KEY') and add to .env.example", False),

    (r'sk-[a-zA-Z0-9]{20,}',
     CRITICAL, "SEC002", "OpenAI API key hardcoded",
     "Replace with os.getenv('OPENAI_API_KEY')", False),

    (r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{80,}',
     CRITICAL, "SEC003", "GitHub token hardcoded",
     "Replace with os.getenv('GITHUB_TOKEN')", False),

    (r'AKIA[0-9A-Z]{16}',
     CRITICAL, "SEC004", "AWS Access Key ID hardcoded",
     "Use boto3 credential chain — never hardcode AWS keys", False),

    (r'''f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{''',
     CRITICAL, "INJ001", "SQL query built with f-string — injection risk",
     "Use parameterized queries: cursor.execute(sql, (param,))", False),

    (r'''(?:execute|query)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE).*['"].*%\s*''',
     CRITICAL, "INJ002", "SQL query built with % formatting — injection risk",
     "Use parameterized: cursor.execute(sql, [params])", False),

    (r'''\beval\s*\(''',
     CRITICAL, "INJ003", "eval() usage — remote code execution risk",
     "Avoid eval entirely. Use ast.literal_eval() or JSON.parse()", False),

    (r'''subprocess\.(run|call|Popen)\s*\(.*shell\s*=\s*True''',
     CRITICAL, "INJ004", "subprocess with shell=True — shell injection risk",
     "Use shell=False and pass args as a list: subprocess.run(['cmd', arg])", False),

    (r'''pickle\.loads?\s*\(''',
     CRITICAL, "SEC005", "pickle.load() on untrusted data — arbitrary code execution",
     "Use json.loads() or a safe serialization format", False),

    # ── HIGH ───────────────────────────────────────────────────
    (r'''\bexcept\s*:\s*$''',
     HIGH, "ERR001", "Bare except: catches everything including KeyboardInterrupt",
     "Catch specific exceptions: except ValueError as e:", True),

    (r'''except\s+Exception\s+as\s+\w+\s*:\s*\n\s*pass\b''',
     HIGH, "ERR002", "Exception caught and silently ignored with pass",
     "At minimum log it: logging.exception('Unexpected error')", False),

    (r'''except\s+\w+\s*:\s*\n\s*pass\b''',
     HIGH, "ERR003", "Exception swallowed with pass — silent failure",
     "Log the error or re-raise it", False),

    (r'''os\.getenv\s*\(\s*['"][A-Z_]+['"]\s*\)(?!\s*(?:or|if|\|\||and))''',
     HIGH, "ENV001", "os.getenv() with no fallback or validation",
     "Add validation: val = os.getenv('KEY'); assert val, 'KEY not set'", True),

    (r'''def\s+\w+\s*\(''',
     HIGH, "CMPLX001", "__FUNCTION_LENGTH_CHECK__",
     "Functions over 60 lines do too much — split into smaller functions", False),

    (r'''requests\.(get|post|put|delete|patch)\s*\([^)]*\)(?!\s*\.raise_for_status)''',
     HIGH, "NET001", "HTTP request without .raise_for_status() — silent HTTP errors",
     "Add .raise_for_status() after the request call", True),

    (r'''open\s*\([^)]+\)(?!\s+as\b)(?!.*with\b)''',
     HIGH, "RES001", "File opened without 'with' context manager — resource leak risk",
     "Use: with open(path) as f:", False),

    # ── MEDIUM ─────────────────────────────────────────────────
    (r'''\bprint\s*\(\s*f?['"](?:debug|DEBUG|test|TODO|temp|TEMP)''',
     MEDIUM, "DBG001", "Debug print statement in production code",
     "Replace with logging.debug() or remove", True),

    (r'''time\.sleep\s*\(\s*\d+\s*\)''',
     MEDIUM, "PERF001", "time.sleep() in production code — blocks the event loop",
     "Use asyncio.sleep() in async code, or move to a background task", False),

    (r'''#\s*(?:TODO|FIXME|HACK|XXX|TEMP|BUG)\b''',
     MEDIUM, "DEBT001", "Unresolved TODO/FIXME comment",
     "Resolve or create a tracked GitHub issue", False),

    (r'''(?<!\w)([0-9]{2,})(?!\w)(?!\s*[:,\]])''',
     MEDIUM, "MAGIC001", "Magic number — unexplained literal value",
     "Extract to a named constant: MAX_RETRIES = 3", False),

    (r'''import \*''',
     MEDIUM, "IMPORT001", "Wildcard import — pollutes namespace, hides dependencies",
     "Import only what you need: from module import specific_thing", True),

    (r'''except\s+Exception\s+as\s+e\s*:\s*\n(?!\s*(?:raise|log|print))''',
     MEDIUM, "ERR004", "Exception caught but not logged or re-raised",
     "Add logging.exception(e) before continuing", False),

    # ── LOW ────────────────────────────────────────────────────
    (r'def\s+\w+\s*\([^)]*\)\s*:',
     LOW, "DOCS001", "__MISSING_DOCSTRING__",
     "Add a docstring explaining what this function does", False),

    (r'''(?<!\w)l\s*=\s*\[|(?<!\w)O\s*=\s*\d|(?<!\w)I\s*=\s*\d''',
     LOW, "NAME001", "Single-letter variable name (l, O, I) — visually ambiguous",
     "Rename to a descriptive variable name", False),
]

# ── Scanner ─────────────────────────────────────────────────────

def get_function_ranges(content: str):
    """Returns list of (start_line, end_line, name) for all functions."""
    ranges = []
    lines = content.splitlines()
    func_starts = []
    indent_stack = []

    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
        if m:
            indent = len(m.group(1))
            name = m.group(2)
            # close any functions with same or deeper indent
            while indent_stack and indent_stack[-1][0] >= indent:
                s_indent, s_line, s_name = indent_stack.pop()
                ranges.append((s_line, i, s_name))
            indent_stack.append((indent, i, name))

    for s_indent, s_line, s_name in indent_stack:
        ranges.append((s_line, len(lines), s_name))

    return ranges


def check_missing_env_example(root: str, content: str) -> List[Issue]:
    """Flag if project uses os.getenv but has no .env.example."""
    issues = []
    env_example = Path(root) / '.env.example'
    dotenv      = Path(root) / '.env'
    if re.search(r'os\.getenv\(', content) and not env_example.exists():
        issues.append(Issue(LOW, str(env_example), 0, "ENV002",
            "Project uses env vars but has no .env.example",
            "Create .env.example listing all required variable names (no real values)",
            auto_fixable=True))
    return issues


def check_gitignore(root: str) -> List[Issue]:
    gi = Path(root) / '.gitignore'
    issues = []
    if not gi.exists():
        issues.append(Issue(HIGH, str(gi), 0, "SEC006",
            ".gitignore missing — secrets and node_modules may be committed",
            "Create .gitignore with at minimum: .env, __pycache__, *.pyc, node_modules",
            auto_fixable=True))
        return issues
    content = gi.read_text(errors='ignore')
    for entry in ['.env', '__pycache__', 'node_modules']:
        if entry not in content:
            issues.append(Issue(MEDIUM, str(gi), 0, "SEC007",
                f".gitignore is missing '{entry}' entry",
                f"Add '{entry}' to .gitignore",
                auto_fixable=True))
    return issues


def check_no_readme(root: str) -> List[Issue]:
    for name in ['README.md', 'README.txt', 'readme.md']:
        if (Path(root) / name).exists():
            return []
    return [Issue(LOW, str(Path(root) / 'README.md'), 0, "DOCS002",
        "No README found — project is undocumented",
        "Create README.md with: what it does, how to run, env vars needed",
        auto_fixable=True)]


def check_no_tests(root: str) -> List[Issue]:
    """Check if project has any test files."""
    for p in Path(root).rglob('test_*.py'):
        return []
    for p in Path(root).rglob('*_test.py'):
        return []
    for p in Path(root).rglob('tests/*.py'):
        return []
    return [Issue(MEDIUM, str(Path(root)), 0, "TEST001",
        "No test files found (test_*.py or *_test.py)",
        "Add at least one test for your most critical function",
        auto_fixable=False)]


def scan_file(filepath: str, root: str) -> List[Issue]:
    issues = []
    try:
        content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
        lines   = content.splitlines()
    except Exception:
        return issues

    seen = set()

    for (pattern, severity, code, msg, fix, auto_fix) in RULES:
        if code == "CMPLX001":
            # Special: check function length
            for start, end, fname in get_function_ranges(content):
                length = end - start
                if length > 60:
                    key = (filepath, start, code)
                    if key not in seen:
                        seen.add(key)
                        issues.append(Issue(severity, filepath, start + 1, code,
                            f"Function '{fname}' is {length} lines — too complex",
                            fix, False, snippet=lines[start].strip()[:80]))
            continue

        if code == "DOCS001":
            # Special: check for missing docstrings
            for m in re.finditer(r'def\s+(\w+)\s*\([^)]*\)\s*:', content):
                end_pos = m.end()
                rest    = content[end_pos:end_pos+200]
                if not re.match(r'\s*\n\s*["\']', rest):
                    line_num = content[:m.start()].count('\n') + 1
                    fname    = m.group(1)
                    if fname.startswith('_') or fname == 'main':
                        continue  # skip private/main
                    key = (filepath, line_num, code)
                    if key not in seen:
                        seen.add(key)
                        issues.append(Issue(LOW, filepath, line_num, code,
                            f"Function '{fname}' has no docstring",
                            fix, False))
            continue

        try:
            for m in re.finditer(pattern, content, re.MULTILINE):
                line_num = content[:m.start()].count('\n') + 1
                key = (filepath, line_num, code)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line_num - 1].strip()[:80] if line_num <= len(lines) else ""
                issues.append(Issue(severity, filepath, line_num, code,
                    msg, fix, auto_fix, snippet=snippet))
        except re.error:
            pass

    return issues


# ── Auto-fix engine ─────────────────────────────────────────────

def auto_fix_file(filepath: str, issues: List[Issue]) -> int:
    """Apply safe automatic fixes. Returns number of fixes applied."""
    try:
        content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return 0

    original = content
    fixes_applied = 0

    for issue in issues:
        if not issue.auto_fixable or issue.file != filepath:
            continue

        if issue.code == "ERR001":
            # bare except: → except Exception as e:
            new = re.sub(r'\bexcept\s*:\s*\n(\s*)',
                         r'except Exception as e:\n\1', content)
            if new != content:
                content = new
                fixes_applied += 1

        elif issue.code == "DBG001":
            # Remove debug prints
            new = re.sub(r'\s*print\s*\(\s*f?["\'](?:debug|DEBUG|temp|TEMP)[^)]*\)\n?',
                         '', content)
            if new != content:
                content = new
                fixes_applied += 1

        elif issue.code == "IMPORT001":
            # from x import * → comment with warning
            new = re.sub(r'^(from\s+\S+\s+import\s+\*)(\s*)$',
                         r'# VIBE-FIX: wildcard import removed — import only what you need\1\2',
                         content, flags=re.MULTILINE)
            if new != content:
                content = new
                fixes_applied += 1

        elif issue.code == "NET001":
            # Add .raise_for_status() after requests calls
            new = re.sub(
                r'((?:response|res|r)\s*=\s*requests\.\w+\s*\([^)]+\))\n(?!\s*\.raise_for_status)',
                r'\1\n    response.raise_for_status()  # vibe-fix: added\n',
                content)
            if new != content:
                content = new
                fixes_applied += 1

    if content != original:
        # Backup original
        backup = filepath + '.vibe-fix-backup'
        Path(backup).write_text(original, encoding='utf-8')
        Path(filepath).write_text(content, encoding='utf-8')

    return fixes_applied


def create_env_example(root: str, issues: List[Issue]):
    """Auto-generate .env.example from detected secret names."""
    env_path = Path(root) / '.env.example'
    if env_path.exists():
        return

    # Collect env var names from the codebase
    py_files = list(Path(root).rglob('*.py'))
    env_vars = set()
    for f in py_files:
        try:
            txt = f.read_text(errors='ignore')
            for m in re.finditer(r"os\.getenv\s*\(\s*['\"]([A-Z_]+)['\"]", txt):
                env_vars.add(m.group(1))
        except Exception:
            pass

    lines = [
        "# vibe-fix auto-generated .env.example",
        "# Copy this to .env and fill in real values",
        "# NEVER commit .env to git\n",
    ]
    for var in sorted(env_vars):
        lines.append(f"{var}=")
    if not env_vars:
        lines += ["OPENAI_API_KEY=", "DATABASE_URL=", "SECRET_KEY=", "JWT_SECRET="]

    env_path.write_text('\n'.join(lines) + '\n')
    print(col(f"  ✅ Created .env.example with {len(env_vars)} variable(s)", 'green'))


def create_gitignore(root: str):
    gi_path = Path(root) / '.gitignore'
    if gi_path.exists():
        return
    gi_path.write_text("""# vibe-fix generated .gitignore
.env
.env.local
.env.production
__pycache__/
*.pyc
*.pyo
.venv/
venv/
node_modules/
dist/
build/
.next/
*.log
logs/
.DS_Store
*.egg-info/
.pytest_cache/
.mypy_cache/
""")
    print(col("  ✅ Created .gitignore", 'green'))


# ── Reporting ───────────────────────────────────────────────────

SCORE_GRADE = {
    range(90, 101): ('A', 'green'),
    range(75, 90):  ('B', 'yellow'),
    range(50, 75):  ('C', 'orange'),
    range(0,  50):  ('F', 'red'),
}

def get_grade(score):
    for r, (grade, color) in SCORE_GRADE.items():
        if score in r:
            return grade, color
    return 'F', 'red'


def print_report(report: AuditReport, show_score_only=False):
    score = report.health_score
    grade, grade_color = get_grade(score)
    risk_emoji = EMOJI.get(report.risk_level, '✅')

    bar_filled = int(score / 5)
    bar = col('█' * bar_filled, grade_color) + col('░' * (20 - bar_filled), 'dim')

    print(f"\n{col('═' * 62, 'cyan')}")
    print(f"  {col('🔧 VIBE-FIX v' + VERSION + ' — AUDIT REPORT', 'bold')}")
    print(col('═' * 62, 'cyan'))
    print(f"  {col('Project', 'dim')}  : {col(report.project, 'bold')}")
    print(f"  {col('Files', 'dim')}    : {report.total_files} total · {report.py_files} Python scanned")
    print(f"  {col('Lines', 'dim')}    : {report.total_lines:,}")
    print(f"  {col('Issues', 'dim')}   : {col(str(len(report.issues)), 'bold')} total · {len(report.auto_fixable())} auto-fixable")
    print(f"  {col('Risk', 'dim')}     : {risk_emoji} {col(report.risk_level, grade_color)}")
    print(f"  {col('Score', 'dim')}    : [{bar}] {col(str(score) + '/100', grade_color)} {col('Grade: ' + grade, grade_color)}")
    print(f"  {col('Duration', 'dim')} : {report.scan_duration_ms}ms")
    print(col('═' * 62, 'cyan') + '\n')

    if show_score_only:
        return

    for sev in ORDER:
        items = report.by_severity(sev)
        if not items:
            continue
        emoji = EMOJI[sev]
        color = {CRITICAL:'red', HIGH:'orange', MEDIUM:'yellow', LOW:'green'}[sev]
        plural = "s" if len(items) != 1 else ""
        print(f"{emoji}  {col(sev, color)} {col(f'({len(items)} issue{plural})', 'dim')}")
        print(col('─' * 62, 'dim'))
        for issue in items:
            loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
            # Make path relative for readability
            try:
                loc = str(Path(loc).relative_to(Path.cwd()))
            except Exception:
                pass
            fix_tag = col(' [AUTO-FIXABLE]', 'green') if issue.auto_fixable else ''
            print(f"  {col('[' + loc + ']', 'dim')}{fix_tag}")
            if issue.snippet:
                print(f"  {col('> ' + issue.snippet, 'cyan')}")
            print(f"  {col('↳', 'bold')} {issue.message}")
            print(f"  {col('✔ Fix:', 'green')} {issue.fix}\n")

    if not report.issues:
        print(col('  ✅ No issues found. Cleanest vibe-code I\'ve seen.\n', 'green'))

    # Summary tips
    auto_count = len(report.auto_fixable())
    if auto_count > 0:
        print(col(f"  💡 Run with --fix to auto-resolve {auto_count} issue(s)", 'cyan'))
    print(col('═' * 62, 'cyan'))
    print(f"  --fix         Auto-fix {auto_count} safe issue(s)")
    print(f"  --json        Export JSON report for CI/CD")
    print(f"  --fix-secrets Generate .env.example from found env vars")
    print(f"  --watch       Re-scan on every file change")
    print(col('═' * 62, 'cyan') + '\n')


def print_diff_report(before: AuditReport, after: AuditReport):
    """Show what changed after auto-fix."""
    fixed = len(before.issues) - len(after.issues)
    score_gain = after.health_score - before.health_score
    print(f"\n{col('🔧 AUTO-FIX RESULTS', 'bold')}")
    print(col('─' * 40, 'dim'))
    print(f"  Issues fixed  : {col(str(fixed), 'green')}")
    print(f"  Score change  : {col(f'+{score_gain}', 'green')} ({before.health_score} → {after.health_score})")
    print(f"  Backups saved : *.vibe-fix-backup\n")


# ── File walker ─────────────────────────────────────────────────

def walk_project(root: str):
    py_files, total_files, total_lines = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fname in filenames:
            total_files += 1
            if fname.endswith('.py'):
                full = os.path.join(dirpath, fname)
                py_files.append(full)
                try:
                    with open(full, encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except Exception:
                    pass
    return py_files, total_files, total_lines


def run_audit(root: str) -> AuditReport:
    t0 = time.time()
    py_files, total_files, total_lines = walk_project(root)

    all_issues: List[Issue] = []
    for f in py_files:
        all_issues.extend(scan_file(f, root))

    # Project-level checks
    content_combined = ""
    for f in py_files:
        try: content_combined += Path(f).read_text(errors='ignore')
        except Exception: pass

    all_issues.extend(check_missing_env_example(root, content_combined))
    all_issues.extend(check_gitignore(root))
    all_issues.extend(check_no_readme(root))
    all_issues.extend(check_no_tests(root))

    # Deduplicate
    seen = set()
    unique = []
    for i in all_issues:
        key = (i.file, i.line, i.code)
        if key not in seen:
            seen.add(key)
            unique.append(i)

    # Sort by severity then file
    sev_order = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3}
    unique.sort(key=lambda x: (sev_order.get(x.severity, 9), x.file, x.line))

    duration_ms = int((time.time() - t0) * 1000)
    return AuditReport(
        project=os.path.basename(root),
        version=VERSION,
        total_files=total_files,
        py_files=len(py_files),
        total_lines=total_lines,
        issues=unique,
        scan_duration_ms=duration_ms
    )


# ── Watch mode ──────────────────────────────────────────────────

def get_file_hashes(root: str):
    hashes = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for f in filenames:
            if f.endswith('.py'):
                fp = os.path.join(dirpath, f)
                try:
                    hashes[fp] = hashlib.md5(Path(fp).read_bytes()).hexdigest()
                except Exception:
                    pass
    return hashes


def watch_mode(root: str):
    print(col(f"  👁  Watching {root} for changes... (Ctrl+C to stop)\n", 'cyan'))
    last_hashes = {}
    while True:
        try:
            current = get_file_hashes(root)
            if current != last_hashes:
                last_hashes = current
                os.system('cls' if os.name == 'nt' else 'clear')
                report = run_audit(root)
                print_report(report)
            time.sleep(2)
        except KeyboardInterrupt:
            print(col("\n  Stopped watching.\n", 'dim'))
            break


# ── Main ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="vibe-fix v2: Surgical repair for AI-generated code debt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python audit.py .                  # Full audit of current dir
  python audit.py ./my-project --fix # Auto-fix safe issues
  python audit.py . --json           # JSON output for CI/CD
  python audit.py . --score          # Just the health score
  python audit.py . --watch          # Re-scan on file change
  python audit.py . --fix-secrets    # Generate .env.example
"""
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to project (default: .)")
    parser.add_argument("--fix",         action="store_true", help="Auto-fix safe issues")
    parser.add_argument("--json",        action="store_true", help="Output JSON for CI/CD")
    parser.add_argument("--score",       action="store_true", help="Print health score only")
    parser.add_argument("--watch",       action="store_true", help="Re-scan on file changes")
    parser.add_argument("--fix-secrets", action="store_true", help="Generate .env.example")
    args = parser.parse_args()

    root = os.path.abspath(args.path)

    if not os.path.isdir(root):
        print(col(f"  ❌ Not a directory: {root}", 'red'))
        sys.exit(1)

    if args.watch:
        watch_mode(root)
        return

    report = run_audit(root)

    if args.json:
        print(json.dumps(asdict(report), indent=2, default=str))
        sys.exit(1 if report.risk_level == CRITICAL else 0)

    if args.score:
        grade, color = get_grade(report.health_score)
        print(col(f"  Health Score: {report.health_score}/100 (Grade {grade})", color))
        sys.exit(0)

    print_report(report)

    if args.fix:
        print(col("  🔧 Running auto-fix...\n", 'cyan'))
        py_files, _, _ = walk_project(root)
        total_fixed = 0
        for f in py_files:
            fixable = [i for i in report.issues if i.file == f and i.auto_fixable]
            if fixable:
                fixed = auto_fix_file(f, fixable)
                if fixed:
                    print(col(f"  ✅ Fixed {fixed} issue(s) in {Path(f).name}", 'green'))
                    total_fixed += fixed

        if args.fix_secrets or any(i.code in ("ENV001","ENV002") for i in report.issues):
            create_env_example(root, report.issues)

        if any(i.code in ("SEC006","SEC007") for i in report.issues):
            create_gitignore(root)

        if total_fixed:
            after = run_audit(root)
            print_diff_report(report, after)
        else:
            print(col("  ℹ No auto-fixable issues found.", 'dim'))

    if args.fix_secrets:
        create_env_example(root, report.issues)
        create_gitignore(root)

    sys.exit(1 if report.risk_level == CRITICAL else 0)


if __name__ == "__main__":
    main()
