# vibe-fix: Copy-Paste Fix Templates

Quick fixes for the most common vibe-code issues, organized by language.

---

## Python

### Secret → Env Var
```python
# ❌ Before
api_key = "sk-abc123"

# ✅ After
import os
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY is not set. See .env.example")
```

### Bare Except → Specific Exception
```python
# ❌ Before
try:
    result = risky_call()
except:
    pass

# ✅ After
import logging
logger = logging.getLogger(__name__)
try:
    result = risky_call()
except ValueError as e:
    logger.error("[module] Validation error: %s", e)
    raise
except Exception as e:
    logger.exception("[module] Unexpected error")
    raise
```

### God Function → Single Responsibility
```python
# ❌ Before (does everything)
def handle_registration(data):
    if not data.get('email'): return {'error': 'no email'}
    data['password'] = hashlib.sha256(data['password'].encode()).hexdigest()
    db.execute("INSERT INTO users ...", data)
    send_mail(data['email'], "Welcome!")
    return {'ok': True}

# ✅ After
def validate_registration(data: dict) -> dict:
    if not data.get('email'): raise ValueError("Email required")
    if not data.get('password'): raise ValueError("Password required")
    return data

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def register_user(data: dict) -> dict:
    validated = validate_registration(data)
    validated['password'] = hash_password(validated['password'])
    user = db.create_user(validated)
    send_welcome_email(user['email'])
    return user
```

### SQL Injection → Parameterized
```python
# ❌ Before
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# ✅ After
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

---

## JavaScript / TypeScript

### Secret → Env Var
```javascript
// ❌ Before
const stripe = new Stripe("sk_live_abc123")

// ✅ After
const stripeKey = process.env.STRIPE_SECRET_KEY
if (!stripeKey) throw new Error("STRIPE_SECRET_KEY is not set. See .env.example")
const stripe = new Stripe(stripeKey)
```

### Empty Catch → Logged Error
```javascript
// ❌ Before
try {
  await fetchData()
} catch (e) {}

// ✅ After
try {
  await fetchData()
} catch (error) {
  console.error('[fetchData] Failed:', error.message)
  // Re-throw if caller needs to handle it
  throw error
}
```

### React: Missing States
```jsx
// ❌ Before
const [data, setData] = useState(null)
useEffect(() => { api.get('/items').then(setData) }, [])
return <List items={data} />  // crashes when data is null

// ✅ After
const [data, setData] = useState(null)
const [loading, setLoading] = useState(true)
const [error, setError] = useState(null)

useEffect(() => {
  api.get('/items')
    .then(setData)
    .catch(err => setError(err.message))
    .finally(() => setLoading(false))
}, [])

if (loading) return <Spinner />
if (error) return <ErrorMessage message={error} />
return <List items={data} />
```

### Infinite useEffect Loop
```jsx
// ❌ Before (infinite loop if items is in deps)
useEffect(() => {
  setFiltered(items.filter(active))
}, [items, active])

// ✅ After (derive in render, no effect needed)
const filtered = useMemo(() => items.filter(active), [items, active])
```

### No Auth Middleware
```javascript
// ❌ Before
app.delete('/api/users/:id', async (req, res) => {
  await db.deleteUser(req.params.id)
  res.json({ ok: true })
})

// ✅ After
const requireAuth = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' })
  next()
}

app.delete('/api/users/:id', requireAuth, async (req, res) => {
  await db.deleteUser(req.params.id)
  res.json({ ok: true })
})
```

---

## .env.example Template
```bash
# vibe-fix: Copy this to .env and fill in real values
# NEVER commit .env to git

# AI APIs
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# Database
DATABASE_URL=
REDIS_URL=

# Auth
JWT_SECRET=
SESSION_SECRET=

# Payments
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# App
PORT=3000
NODE_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

---

## .gitignore Essentials
```gitignore
# Secrets
.env
.env.local
.env.production

# Dependencies
node_modules/
.venv/
venv/

# Build
dist/
build/
.next/
__pycache__/
*.pyc

# Logs
*.log
logs/

# IDE
.vscode/settings.json
.idea/
```
