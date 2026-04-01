# Vibe-Code Antipatterns Catalog
## The 30 Most Common AI-Generated Code Mistakes

This is a living catalog of patterns that AI coding tools (Claude, Copilot, Cursor, Codex)
generate that look correct but cause real problems in production.

---

## 🔴 CRITICAL

### VP-001: Hardcoded Secrets
**Seen in**: Every AI-generated project, ~100% of first-draft code
**What happens**: API keys, DB passwords, JWT secrets embedded in source.
If this hits GitHub (even for 30 seconds), bots harvest it immediately.
**Pattern**:
```python
client = OpenAI(api_key="sk-abc123...")
```
**Fix**: `os.getenv("OPENAI_API_KEY")` + `.env.example`

---

### VP-002: String-Interpolated SQL
**Seen in**: ~70% of AI-generated database code
**What happens**: User input flows directly into a query string.
**Pattern**:
```python
query = f"SELECT * FROM users WHERE email = '{user_input}'"
```
**Fix**: Parameterized queries: `cursor.execute("SELECT * FROM users WHERE email = %s", [user_input])`

---

### VP-003: No Auth on Sensitive Routes
**Seen in**: ~60% of AI-generated APIs
**What happens**: `/admin`, `/delete`, `/export` endpoints generated without middleware.
**Pattern**:
```javascript
app.get('/admin/users', async (req, res) => {  // No auth check!
  const users = await db.getAll('users')
  res.json(users)
})
```
**Fix**: Add auth middleware before every sensitive route.

---

### VP-004: Bare eval()
**Seen in**: ~20% of AI-generated parsing code
**What happens**: Remote code execution. Game over.
**Pattern**:
```javascript
const result = eval(userInput)
```
**Fix**: Use `JSON.parse()`, a sandboxed runner, or a proper parser.

---

## 🟠 HIGH

### VP-005: Silent Error Swallowing
**Seen in**: ~80% of AI-generated async code
**What happens**: Errors disappear. Users see nothing. You debug for hours.
**Pattern**:
```javascript
try {
  await riskyOperation()
} catch (e) {}  // Swallowed
```
**Fix**: Always log + surface the error appropriately.

---

### VP-006: God Functions
**Seen in**: ~90% of first-draft AI code
**What happens**: One function validates, transforms, persists, emails, and logs.
Untestable. Unmaintainable.
**Pattern**:
```python
def process_order(data):
    # 150 lines doing everything
```
**Fix**: Single Responsibility Principle. One function, one job.

---

### VP-007: Copy-Paste Logic
**Seen in**: ~75% of AI-generated multi-feature projects
**What happens**: AI regenerates similar logic rather than reusing. Bug fixed in one
place, persists in 3 others.
**Fix**: Extract to a shared utility on first duplication.

---

### VP-008: No Input Validation
**Seen in**: ~65% of AI-generated form/API handlers
**What happens**: Garbage in, garbage out. Or worse — crashes.
**Pattern**:
```python
def create_user(name, email, age):
    db.insert('users', {'name': name, 'email': email, 'age': age})
```
**Fix**: Validate before processing. Zod (TS), Pydantic (Python), Joi (Node).

---

### VP-009: Missing Loading + Error States
**Seen in**: ~85% of AI-generated React components
**What happens**: Blank screen while fetching. White screen on error. Users confused.
**Pattern**:
```jsx
const [data, setData] = useState(null)
useEffect(() => { fetch('/api/data').then(r => r.json()).then(setData) }, [])
return <DataView data={data} />  // crashes if data is null
```
**Fix**: Always handle 3 states: loading, error, success.

---

### VP-010: Infinite Re-render Loops
**Seen in**: ~50% of AI-generated useEffect hooks
**What happens**: Component re-renders on every tick. CPU spikes. Browser hangs.
**Pattern**:
```jsx
useEffect(() => {
  setData(transform(data))  // data is in deps → infinite loop
}, [data])
```
**Fix**: Derive values in render, or use useMemo. Avoid setting state from state in useEffect.

---

## 🟡 MEDIUM

### VP-011: Magic Numbers Everywhere
### VP-012: process.env without validation
### VP-013: No TypeScript (when project could easily use it)
### VP-014: Synchronous file reads in request handlers
### VP-015: N+1 query patterns in loops
### VP-016: No pagination on list endpoints
### VP-017: Blocking the event loop with CPU work
### VP-018: Missing CORS configuration (either too open or forgotten)
### VP-019: No rate limiting on public endpoints
### VP-020: console.log('debug:') left in production code

---

## 🟢 LOW

### VP-021: No README
### VP-022: Missing .gitignore (node_modules, .env committed)
### VP-023: No .env.example
### VP-024: Unused imports creating confusion
### VP-025: var instead of const/let (JS)
### VP-026: == instead of === (JS)
### VP-027: Inconsistent naming (camelCase + snake_case mixed)
### VP-028: No comments on complex business logic
### VP-029: Hardcoded localhost URLs
### VP-030: TODO comments never resolved
