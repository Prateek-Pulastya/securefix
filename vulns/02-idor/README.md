# Fix: IDOR in invoice detail  (CWE-639 / OWASP A01)

**Impact / business risk.**
Any authenticated user can read any other user's invoice — amounts, descriptions, notes —
just by changing the id in the URL. No injection, no special tooling: incrementing an
integer. Cross-tenant data exposure and, for EU users, a GDPR-reportable incident.

**Reproduction.**
```
GET /invoices/3      header:  x-user-id: 1
```
Invoice 3 belongs to bob (`owner_id 2`); the caller is alice (`x-user-id 1`). The response
still returns bob's row (`"Pentest engagement"`). Automated proof: `tests/security/idor.test.ts`.

**Root cause.**
The row is fetched by the path id with no ownership predicate — the principal is never
compared to `invoices.owner_id`:
```ts
db.prepare('SELECT id, description, amount, note FROM invoices WHERE id = ?').get(id)
```
Why it shipped: "fetch invoice by id" is the obvious one-liner; the owner scope lived in
the developer's head ("you only ever see your own"), never in the query.

**Fix.**
Bind the principal into the query and scope the row to its owner. A miss returns 404,
indistinguishable from "no such invoice" (don't leak existence):
```ts
const ownerId = Number(req.header('x-user-id'));
if (!Number.isInteger(ownerId)) return res.status(401).json({ error: 'auth required' });
db.prepare('SELECT id, description, amount, note FROM invoices WHERE id = ? AND owner_id = ?')
  .get(id, ownerId);
```
See `fix.diff`. After the fix, the cross-owner request returns 404 and the regression test
flips its cross-owner expectation from `200` to `404`.

**Prevention (so it can't come back).**
Custom Semgrep rule `idor-query-by-id-missing-owner-scope` (in `semgrep-rules/`) fires on a
`SELECT ... WHERE id = ...` fetched through `db.prepare(...)` that carries no
`owner_id`/`user_id`/`tenant_id` predicate, and runs in CI — any future PR that drops the
owner scope fails the build.

**Detection metric.**
- Custom rule: **fires** on the vulnerable line (no owner predicate), **silent** on the
  fixed line (the `AND owner_id = ?` clause puts `owner_id` in the query text).
- Community `p/typescript` / `p/owasp-top-ten`: _[measure and record in RESULTS.md]_.

**Residual risk / notes.**
- The rule is a **LOW-confidence heuristic** (regex over the query string), not taint
  analysis: it can't prove the id is request-controlled, and it's blind to authorization
  done in code rather than in SQL (e.g. a separate `assertOwner(id, user)` check, or an ORM
  `.where({ ownerId })`). It catches the common raw-SQL shape; treat hits as review prompts.
  See `semgrep-rules/README.md`.
- `x-user-id` is a stand-in for a verified principal (JWT `sub` / session). Trusting a raw
  header is itself insecure — that's the JWT class (#5); here the point is the missing owner
  scope, holding the principal source constant.
