# Fix: SQL injection in invoice search  (CWE-89 / OWASP A03)

> This is the PR-writeup template for every class. Copy it for 02–06.

**Impact / business risk.**
An authenticated user can read any table — including `users` password hashes and other
tenants' invoices — by injecting a `UNION SELECT`. That is a full data breach and, for
EU users, a GDPR-reportable incident.

**Reproduction.**
```
GET /invoices/search?q=x%25' UNION SELECT password, username, 0 FROM users -- 
```
(`%25` = URL-encoded `%`.) The response contains bcrypt hashes from `users`.
Automated proof: `tests/security/sqli.test.ts`.

**Root cause.**
User input is concatenated into a SQL **template literal**, so the attacker controls the
query shape:
```ts
db.prepare(`SELECT id, description, amount FROM invoices WHERE description LIKE '%${q}%'`)
```
Why it shipped: a LIKE search was added quickly; the template literal worked in local
testing and was never reviewed.

**Fix.**
Parameterize — the value is bound, never parsed as SQL:
```ts
const q = String(req.query.q ?? '');
db.prepare('SELECT id, description, amount FROM invoices WHERE description LIKE ?').all(`%${q}%`);
```
See `fix.diff`. After the fix, the exploit input returns normal (empty) results and the
regression test flips from "leak = true" to "leak = false".

**Prevention (so it can't come back).**
Custom Semgrep rule `sqli-template-literal-in-query` (in `semgrep-rules/`) fires on any
interpolated query passed to `prepare/query/exec/all/get`, and runs in CI — any future PR
that reintroduces the pattern fails the build.

**Detection metric.**
- Custom rule: **fires** on the vulnerable line, **silent** on the fixed line.
- Community `p/typescript` alone: _[measure and record in RESULTS.md]_.

**Residual risk / notes.**
LIKE wildcards in user input remain allowed (functional behaviour, not a security issue);
documented and accepted.
