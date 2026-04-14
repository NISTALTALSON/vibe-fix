<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=32&duration=3000&pause=1000&color=FF4444&center=true&vCenter=true&width=600&lines=Your+AI-generated+code...;...is+a+disaster.;vibe-fix+is+here." alt="Typing SVG" />

<br/>

```
██╗   ██╗██╗██████╗ ███████╗      ███████╗██╗██╗  ██╗
██║   ██║██║██╔══██╗██╔════╝      ██╔════╝██║╚██╗██╔╝
██║   ██║██║██████╔╝█████╗  █████╗█████╗  ██║ ╚███╔╝ 
╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════╝██╔══╝  ██║ ██╔██╗ 
 ╚████╔╝ ██║██████╔╝███████╗      ██║     ██║██╔╝ ██╗
  ╚═══╝  ╚═╝╚═════╝ ╚══════╝      ╚═╝     ╚═╝╚═╝  ╚═╝
```

**Surgical repair for AI-generated spaghetti code**

[![Stars](https://img.shields.io/github/stars/NISTALTALSON/vibe-fix?style=for-the-badge&color=FF4444&labelColor=1a1a1a)](https://github.com/NISTALTALSON/vibe-fix/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge&labelColor=1a1a1a)](LICENSE)
[![Works With Claude](https://img.shields.io/badge/Works%20With-Claude%20Code-orange?style=for-the-badge&logo=anthropic&logoColor=white&labelColor=1a1a1a)](https://claude.ai/code)
[![Works With Cursor](https://img.shields.io/badge/Works%20With-Cursor-blue?style=for-the-badge&labelColor=1a1a1a)](https://cursor.sh)
[![Works With Codex](https://img.shields.io/badge/Works%20With-Codex%20CLI-green?style=for-the-badge&labelColor=1a1a1a)](https://github.com/openai/codex)
[![Works With Gemini](https://img.shields.io/badge/Works%20With-Gemini%20CLI-4285F4?style=for-the-badge&labelColor=1a1a1a)](https://ai.google.dev)
[![Works With Antigravity](https://img.shields.io/badge/Works%20With-Antigravity-purple?style=for-the-badge&labelColor=1a1a1a)](https://antigravity.dev)

<br/>

> *You vibe-coded it in a weekend. Now it's 3 AM. Production is down. Secrets are exposed. Tests don't exist. You don't even remember what half this code does.*
>
> **vibe-fix was built for this exact moment.**

</div>

---

## 🤯 The Problem Nobody Talks About

Everyone's shipping with AI. Cursor. Claude Code. Codex. Gemini CLI. Antigravity.

The code **looks** fine. It **runs** fine. Until it doesn't.

<table>
<tr>
<td width="50%">

**What AI gives you** ✨
```python
# Here's a user registration endpoint!
@app.post("/register")
async def register(data: dict):
    api_key = "sk-proj-abc123secretkey"  # 🔴 EXPOSED
    user = db.execute(
        f"INSERT INTO users VALUES ('{data['email']}')"  # 🔴 SQL INJECTION
    )
    return {"ok": True}  # 🟠 No error handling
                         # 🟠 No validation
                         # 🟡 No types
                         # 🟢 No tests, no docs
```

</td>
<td width="50%">

**What vibe-fix gives you** 🔧
```
VIBE-FIX AUDIT REPORT
═══════════════════════════════
Project  : my-startup
Risk     : 🔴 CRITICAL
Issues   : 6 total

🔴 CRITICAL (2)
  [app.py:3] Hardcoded API key detected
  ✔ Fix: Move to os.getenv("OPENAI_API_KEY")

  [app.py:5] SQL injection via f-string
  ✔ Fix: Use parameterized queries

🟠 HIGH (2) ...
🟡 MEDIUM (1) ...
🟢 LOW (1) ...
═══════════════════════════════
```

</td>
</tr>
</table>

---

## ⚡ What vibe-fix Does

| Phase | What Happens |
|-------|-------------|
| 🔍 **DIAGNOSE** | Scans your codebase for 30 AI-generated antipatterns across 4 severity tiers |
| 📋 **REPORT** | Outputs a prioritized triage report: exact file, line, issue, and fix |
| 🔧 **FIX** | Surgically repairs issues one tier at a time — **never rewrites what works** |
| 🛡️ **HARDEN** | Adds `.env.example`, error boundaries, logging, README, `.gitignore` |

### What vibe-fix catches:
- 🔴 **Hardcoded secrets** (API keys, passwords, tokens in source)
- 🔴 **SQL injection** (f-strings, string concat in queries)
- 🔴 **Missing auth** on sensitive routes
- 🟠 **Silent error swallowing** (empty catch blocks)
- 🟠 **God functions** (1 function doing 10 things)
- 🟠 **No input validation** (user data accepted raw)
- 🟡 **Missing loading/error states** in React
- 🟡 **Infinite re-render loops** (useEffect antipatterns)
- 🟡 **Magic numbers** everywhere
- 🟢 **No README, no `.env.example`, no `.gitignore`**

*Full catalog: [references/vibe-code-patterns.md](references/vibe-code-patterns.md)*

---

## 🚀 Install

### Option 1 — npx (Claude Code / Cursor / Codex / Gemini CLI / Antigravity)
```bash
npx skills add NISTALTALSON/vibe-fix
```

### Option 2 — Manual
```bash
# Clone into your skills directory
git clone https://github.com/NISTALTALSON/vibe-fix ~/.claude/skills/vibe-fix

# Or project-local
git clone https://github.com/NISTALTALSON/vibe-fix .claude/skills/vibe-fix
```

### Option 3 — Run the scanner standalone (no AI agent needed)
```bash
# Python projects
python ~/.claude/skills/vibe-fix/scripts/audit.py ./my-project

# Node.js projects
node ~/.claude/skills/vibe-fix/scripts/audit.js ./my-project

# Export JSON report
python scripts/audit.py . --json > report.json
```

----

## 🎯 Usage

Once installed, just describe your problem naturally:

```
"My codebase is a mess, fix it"
"Clean up this AI-generated code"
"Audit my project for security issues"
"My vibe code is broken, help"
"Fix my spaghetti"
```

vibe-fix triggers automatically. No slash command needed.

### Or use the audit scripts directly:

```bash
# Python — full audit
python scripts/audit.py /path/to/project

# Node.js — full audit  
node scripts/audit.js /path/to/project

# Auto-generate .env.example from found secrets
python scripts/audit.py . --fix-secrets

# JSON output (for CI/CD pipelines)
node scripts/audit.js . --json | jq '.issues[] | select(.severity == "CRITICAL")'
```

---

## 📸 Example Session

```
You: "My codebase is a disaster, it's all AI-generated and I think there are security issues"

Claude: Running vibe-fix audit...

VIBE-FIX AUDIT REPORT
═══════════════════════════════════════════════════
Project  : findmypg-api
Files    : 23 total, 8 with issues
Risk     : 🔴 CRITICAL
Issues   : 14 total

🔴 CRITICAL (3)
  [src/config.js:4]
  > const stripeKey = "sk_live_xxxxxxxxxxx"
  ↳ Hardcoded Stripe secret key in source
  ✔ Move to process.env.STRIPE_SECRET_KEY

  [src/routes/users.js:18]
  > db.query(`SELECT * FROM users WHERE email = '${email}'`)
  ↳ SQL injection via string interpolation
  ✔ Use parameterized: db.query('... WHERE email = $1', [email])

  [src/routes/admin.js:3]
  > app.get('/admin/export', async (req, res) => {
  ↳ Sensitive route with no auth middleware
  ✔ Add requireAuth middleware before handler

🟠 HIGH (4 issues) ...
🟡 MEDIUM (5 issues) ...
🟢 LOW (2 issues) ...

═══════════════════════════════════════════════════
Which tier would you like me to fix first?.
```

---

## 🌐 Works Everywhere

vibe-fix uses the universal `SKILL.md` format. One install, every AI agent:

| Platform | Status |
|---------|--------|
| Claude Code | ✅ Full support |
| Cursor | ✅ Full support |
| Codex CLI | ✅ Full support |
| Gemini CLI | ✅ Full support |
| Antigravity IDE | ✅ Full support |
| Amp CLI | ✅ Full support |
| OpenCode | ✅ Full support |

---

## 📁 Structure

```
vibe-fix/
├── SKILL.md                    ← Main skill (loaded by AI agents)
├── scripts/
│   ├── audit.py                ← Python project scanner
│   └── audit.js                ← Node.js project scanner
└── references/
    ├── vibe-code-patterns.md   ← Catalog of 30 AI antipatterns
    └── fix-templates.md        ← Copy-paste fix snippets
```

---

## 🤝 Contributing

Found a new AI antipattern? Open a PR adding it to `references/vibe-code-patterns.md` and the relevant scanner.

1. Fork this repo
2. Add your pattern to `references/vibe-code-patterns.md`
3. Add detection to `scripts/audit.py` and/or `scripts/audit.js`
4. Add a fix template to `references/fix-templates.md`
5. Open a PR with a real example of the pattern "in the wild"

---

## 💬 Who Built This

Built by [Nistal Talson](https://github.com/NISTALTALSON) — BCA Cybersecurity student,
founder of [FindMyPG India](https://findmypgindia.vercel.app) and [N7 Productions](https://n7productions.vercel.app),
builder of [RepoSec](https://github.com/NISTALTALSON/reposec).

This skill was born from real pain: vibe-coding a production app, shipping it, and
watching it expose secrets and crash in front of users.

If this saved your project, give it a ⭐ and share it.

---

<div align="center">

**vibe-fix** — because shipping fast shouldn't mean shipping broken.

[![Star on GitHub](https://img.shields.io/badge/⭐_Star_this_repo-FF4444?style=for-the-badge)](https://github.com/NISTALTALSON/vibe-fix)
[![Share on X](https://img.shields.io/badge/Share_on_X-000000?style=for-the-badge&logo=x)](https://twitter.com/intent/tweet?text=just+found+vibe-fix+%E2%80%94+a+Claude%2FCursor%2FCodex+skill+that+automatically+audits+and+fixes+AI-generated+spaghetti+code+%F0%9F%94%A5+%40NISTALTALSON+https%3A%2F%2Fgithub.com%2FNISTALTALSON%2Fvibe-fix)

MIT License · Made with 🔥 in Kerala, India

</div>
