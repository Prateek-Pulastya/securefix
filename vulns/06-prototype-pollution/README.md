# Fix: prototype pollution in prefs merge  (CWE-1321 / OWASP A08)

**Impact / business risk.**
A request can write onto `Object.prototype`, changing the behaviour of *every* object in the
process. Depending on what code later reads those inherited properties this becomes privilege
escalation (`isAdmin`), denial of service, or — with the right downstream "gadget" — remote
code execution. It is process-global and persists until restart.

**Reproduction.**
```
POST /invoices/prefs
Content-Type: application/json

{ "__proto__": { "polluted": "yes" } }
```
Afterwards a brand-new object inherits the property: `({}).polluted === "yes"`. Automated
proof: `tests/security/proto.test.ts`.

**Root cause.**
A recursive merge assigns keys dynamically with no prototype guard:
```ts
for (const key of Object.keys(source)) {
  // …
  target[key] = source[key];   // key can be "__proto__"; target["__proto__"] is Object.prototype
}
```
`JSON.parse` creates `"__proto__"` as an **own** enumerable key, so `Object.keys` yields it and
the recursion walks straight into `Object.prototype`.

**Fix.**
Reject the dangerous keys, and assign through a local so the value never flows as the raw
`target[key] = source[key]` shape; rename to `safeMerge`:
```ts
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
export function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue;
    const value = source[key];
    if (value && typeof value === 'object' && target[key] && typeof target[key] === 'object') {
      safeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}
```
(Equally valid: `Object.create(null)` accumulators, a `Map`, or a vetted library.) See
`fix.diff`. After the fix the payload is ignored and the exploit test flips from
`polluted === "yes"` to `polluted === undefined`.

**Prevention (so it can't come back).**
Custom Semgrep rule file `06-prototype-pollution-merge.yml` ships two rules that run in CI:
- `prototype-pollution-dynamic-assign` — the `target[key] = source[key]` shape.
- `prototype-pollution-unsafe-merge-of-user-input` — `_.merge`/`Object.assign`/`deepMerge`
  called with `req.body`.

**Detection metric.**
- Custom rules: **fire** on the raw dynamic assign and on `deepMerge(prefs, req.body)`;
  **silent** once the assign uses a local RHS and the call is renamed to a guarded `safeMerge`.
- Community `p/typescript` / `p/owasp-top-ten`: _[measure and record in RESULTS.md]_.

**Residual risk / notes (this is a LOW-confidence heuristic).**
- Rule 1 matches the **syntactic** `$T[$K] = $S[$K]` — it fires on a guarded merge too (it
  can't see an early-`continue`/`Set` check), and misses the same bug written differently
  (`Reflect.set`, computed spreads, a library's internal loop). Treat hits as review prompts.
- Rule 2 keys off literal call names (`deepMerge`, `_.merge`, `Object.assign`) with a literal
  `req.body` argument — trivially evaded by a local alias (`const b = req.body; deepMerge(x, b)`)
  or a differently named merger. It is a floor, not a proof.
- The real fix is the runtime guard, not the rule; the rule just stops the obvious shape from
  landing again.
