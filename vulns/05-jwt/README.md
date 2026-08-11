# Fix: JWT signature not verified  (CWE-347 / OWASP A07)

**Impact / business risk.**
Authentication is decorative: the server reads the token's claims without checking its
signature, so anyone can mint a token with any `sub` (or `role: admin`) and act as any user.
Full account takeover and authorization bypass across every endpoint that trusts the token.

**Reproduction.**
```
# attacker signs with their OWN secret — they never learn the server's:
token = jwt.sign({ sub: 2 }, 'attacker-secret')
GET /invoices/mine    Authorization: Bearer <token>
```
Returns bob's invoices (`owner_id 2`). Automated proof: `tests/security/jwt.test.ts`.

**Root cause.**
`jwt.decode()` only base64-decodes; it never verifies the signature:
```ts
const payload = jwt.decode(token) as jwt.JwtPayload | null;   // trusts unsigned claims
return { sub: payload.sub };
```

**Fix.**
Verify the signature **and pin the algorithm** — a naive `jwt.verify(token, secret)` without
pinning is still wrong (attacker can present `alg: none` or trigger RS256/HS256 key
confusion), which is why rule 05 flags that form too:
```ts
const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as jwt.JwtPayload;
if (typeof payload.sub !== 'number') return null;
return { sub: payload.sub };
```
See `fix.diff`. After the fix the forged (wrong-key) token fails verification and the exploit
test flips from `200` to `401`.

**Prevention (so it can't come back).**
Custom Semgrep rule file `05-jwt-insecure-verify.yml` ships two rules that run in CI:
- `jwt-decode-used-for-auth` (**HIGH**) — any `jwt.decode(...)` (decode is never authentication).
- `jwt-verify-without-pinned-algorithm` (**MEDIUM**) — `jwt.verify(t, s)` with no options, or
  an `algorithms` list containing `"none"`.

Only `jwt.verify(token, secret, { algorithms: ['HS256'] })` clears both.

**Detection metric.**
- Custom rules: `jwt.decode` **fires** HIGH; naive `jwt.verify(t,s)` **fires** MEDIUM; the
  pinned `verify` is **silent**.
- Community `p/typescript` / `p/owasp-top-ten`: _[measure and record in RESULTS.md]_.

**Residual risk / notes.**
- The rule is a **syntactic** matcher on `jwt.*` from the `jsonwebtoken` API. It won't catch
  a hand-rolled verifier, another JWT library's API (`jose`, `fast-jwt`), or a verify whose
  `algorithms` is built dynamically. Treat it as a floor, not a proof of correctness.
- Pinning the algorithm is necessary but not sufficient: the secret must be strong and secret
  (the dev fallback in `auth.ts` is a placeholder), token expiry (`exp`) must be enforced, and
  `sub` must map to a real, still-active account.
