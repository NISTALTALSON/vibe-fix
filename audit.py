#!/usr/bin/env python3
"""
vibe-fix audit.py
Automated scanner for AI-generated code antipatterns in Python projects.
Usage: python scripts/audit.py [path] [--json] [--fix-secrets]
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Tuple

# ─────────────────────────────────────────
# Issue severity levels
# ─────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

SEVERITY_EMOJI = {
    CRITICAL: "🔴",
    HIGH:     "🟠",
    MEDIUM:   "🟡",
    LOW:      "🟢",
}

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW]

@dataclass
class Issue:
    severity: str
    file: str
    line: int
    code: str
    message: str
    fix: str

@dataclass
class AuditReport:
    project: str
    total_files: int
    total_lines: int
    issues: List[Issue] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if any(i.severity == CRITICAL for i in self.issues):
            return CRITICAL
        if any(i.severity == HIGH for i in self.issues):
            return HIGH
        if any(i.severity == MEDIUM for i in self.issues):
            return MEDIUM
        return LOW if self.issues else "CLEAN"

    def by_severity(self, sev: str) -> List[Issue]:
        return [i for i in self.issues if i.severity == sev]


# ─────────────────────────────────────────
# Detection rules
# ─────────────────────────────────────────
SECRET_PATTERNS = [
    (r'(?i)(api_?key|secret|password|token|auth)\s*=\s*["\'][a-zA-Z0-9\-_]{8,}["\']',
     "Hardcoded secret detected", "Move to environment variable via os.getenv()"),
    (r'sk-[a-zA-Z0-9]{20,}',
     "OpenAI API key pattern found in source", "Use os.getenv('OPENAI_API_KEY')"),
    (r'ghp_[a-zA-Z0-9]{36}',
     "GitHub personal access token in source", "Use os.getenv('GITHUB_TOKEN')"),
]

SQL_INJECTION_PATTERNS = [
    (r'execute\(["\'].*%s.*["\'].*%',
     "Possible SQL injection via % formatting", "Use parameterized queries: cursor.execute(sql, params)"),
    (r'f["\'].*SELECT.*\{',
     "SQL query built with f-string — injection risk", "Use parameterized queries"),
    (r'["\'].*SELECT.*["\'].*\+',
     "SQL query built with string concatenation", "Use parameterized queries"),
]

ASYNC_PATTERNS = [
    (r'await\s+\w+\([^)]*\)\s*\n(?!\s*(try|except|if))',
     "Awaited call without error handling", "Wrap in try/except block"),
]

MAGIC_NUMBER_PATTERNS = [
    (r'(?<!["\'\w])((?!0\b)\d{2,})(?!["\'\w%])',
     "Magic number — unexplained literal", "Extract to a named constant"),
]

PRINT_DEBUG_PATTERNS = [
    (r'\bprint\s*\(\s*["\']DEBUG',
     "Debug print statement left in code", "Remove or replace with logging.debug()"),
    (r'\bconsole\.log\s*\(\s*["\']debug',
     "Debug console.log left in code", "Remove before production"),
]

TODO_PATTERNS = [
    (r'#\s*(TODO|FIXME|HACK|XXX|TEMP)\b',
     "Unresolved TODO/FIXME comment", "Resolve or create a tracked issue"),
]

BARE_EXCEPT_PATTERNS = [
    (r'\bexcept\s*:\s*$',
     "Bare except clause — silently swallows all errors", "Catch specific exceptions: except ValueError as e:"),
    (r'\bexcept\s+Exception\s*:\s*\n\s*pass',
     "Exception caught and ignored with pass", "Log the error or re-raise"),
]


def scan_file(filepath: str) -> List[Issue]:
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except (IOError, OSError):
        return issues

    def check_patterns(patterns, severity, content_to_check=None, use_lines=False):
        target = content_to_check or content
        for pattern, msg, fix in patterns:
            if use_lines:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        issues.append(Issue(severity, filepath, i, pattern[:20], msg, fix))
            else:
                for m in re.finditer(pattern, target, re.MULTILINE):
                    line_num = target[:m.start()].count('\n') + 1
                    issues.append(Issue(severity, filepath, line_num, pattern[:20], msg, fix))

    check_patterns(SECRET_PATTERNS, CRITICAL)
    check_patterns(SQL_INJECTION_PATTERNS, CRITICAL)
    check_patterns(BARE_EXCEPT_PATTERNS, HIGH)
    check_patterns(ASYNC_PATTERNS, HIGH)
    check_patterns(PRINT_DEBUG_PATTERNS, MEDIUM, use_lines=True)
    check_patterns(TODO_PATTERNS, LOW, use_lines=True)

    # Check for missing .env.example
    project_root = Path(filepath).parent
    if filepath.endswith('.py') and not (project_root / '.env.example').exists():
        if re.search(r'os\.getenv\(', content):
            issues.append(Issue(
                LOW, filepath, 0, "no-env-example",
                "Project uses env vars but has no .env.example",
                "Create .env.example with all required variable names (no real values)"
            ))

    return issues


def walk_project(root: str) -> Tuple[List[str], int, int]:
    """Walk project directory, return (py_files, total_files, total_lines)."""
    skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.next'}
    py_files = []
    total_files = 0
    total_lines = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname.endswith('.py'):
                full = os.path.join(dirpath, fname)
                py_files.append(full)
                try:
                    with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except Exception:
                    pass
            total_files += 1

    return py_files, total_files, total_lines


def print_report(report: AuditReport):
    print("\n" + "═" * 60)
    print("  🔧 VIBE-FIX AUDIT REPORT")
    print("═" * 60)
    print(f"  Project  : {report.project}")
    print(f"  Files    : {report.total_files} total, {len(set(i.file for i in report.issues))} with issues")
    print(f"  Lines    : {report.total_lines:,}")
    print(f"  Risk     : {SEVERITY_EMOJI.get(report.risk_level, '✅')} {report.risk_level}")
    print(f"  Issues   : {len(report.issues)} total")
    print("═" * 60 + "\n")

    for sev in SEVERITY_ORDER:
        items = report.by_severity(sev)
        if not items:
            continue
        emoji = SEVERITY_EMOJI[sev]
        print(f"{emoji}  {sev} ({len(items)} issue{'s' if len(items) != 1 else ''})")
        print("─" * 60)
        for issue in items:
            loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
            print(f"  [{loc}]")
            print(f"  ↳ {issue.message}")
            print(f"  ✔ Fix: {issue.fix}\n")

    if not report.issues:
        print("  ✅ No issues found. Your vibe code is cleaner than expected!\n")

    print("═" * 60)
    print(f"  Run with --json to export this report.")
    print(f"  Run with --fix-secrets to auto-move hardcoded secrets to .env")
    print("═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="vibe-fix: Audit AI-generated Python code for technical debt"
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: current dir)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--fix-secrets", action="store_true", help="Auto-create .env.example from found secrets")
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    py_files, total_files, total_lines = walk_project(root)

    all_issues: List[Issue] = []
    for f in py_files:
        all_issues.extend(scan_file(f))

    # Deduplicate by (file, line, code)
    seen = set()
    unique_issues = []
    for i in all_issues:
        key = (i.file, i.line, i.code)
        if key not in seen:
            seen.add(key)
            unique_issues.append(i)

    report = AuditReport(
        project=os.path.basename(root),
        total_files=total_files,
        total_lines=total_lines,
        issues=unique_issues
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print_report(report)

    if args.fix_secrets:
        secret_issues = report.by_severity(CRITICAL)
        secret_files = set(i.file for i in secret_issues if "secret" in i.message.lower() or "key" in i.message.lower())
        env_path = os.path.join(root, '.env.example')
        if secret_files and not os.path.exists(env_path):
            with open(env_path, 'w') as f:
                f.write("# vibe-fix auto-generated .env.example\n")
                f.write("# Fill in your real values in .env (never commit .env!)\n\n")
                f.write("OPENAI_API_KEY=your_key_here\n")
                f.write("DATABASE_URL=your_db_url_here\n")
                f.write("SECRET_KEY=your_secret_here\n")
            print(f"✅ Created {env_path}")

    sys.exit(1 if report.risk_level == CRITICAL else 0)


if __name__ == "__main__":
    main()
