# Custom Semgrep rules

One rule (file) per seeded vulnerability class. These are **hand-authored** — the point
of the project is to detect the seeded classes at least as well as the community packs,
and to explain each rule's precision and limits like an engineer, not a scanner operator.

Run them:

```bash
# custom rules only
semgrep scan --config ./semgrep-rules

# custom + community (what CI runs)
semgrep scan --config ./semgrep-rules --config p/typescript --config p/owasp-top-ten --error
```

| File | Class | CWE / OWASP | Confidence | Notes / known limits |
|------|-------|-------------|------------|----------------------|
| 01-sqli-template-literal-in-query.yml | SQL injection | CWE-89 / A03 | HIGH | Catches interpolation into `prepare/query/exec/all/get`. Won't catch SQL built by `+` concatenation across statements — add a variant if you seed that. |
| 02-idor-query-missing-owner-scope.yml | Broken access control (IDOR) | CWE-639 / A01 | LOW | **Heuristic.** IDOR is semantic; this regex flags `SELECT ... WHERE id = ...` lacking an `owner_id/user_id/tenant_id` predicate. Expect false positives on legitimately-global queries — that FP-tuning story is an interview talking point. Prefer CodeQL for real dataflow (see stretch). |
| 03-ssrf-user-controlled-url.yml | SSRF | CWE-918 / A10 | HIGH | Taint mode: `req.*` → outbound HTTP sink. Sanitizers `isAllowedUrl()/assertPublicHost()` clear the taint — name your fix helper one of those or edit the rule. |
| 04-xss-unescaped-response.yml | Stored/reflected XSS | CWE-79 / A03 | MEDIUM | Taint mode: `req.*` → `res.send/write/end`. Only meaningful when the response is HTML; JSON responses are not XSS sinks (documented limit). |
| 05-jwt-insecure-verify.yml | JWT verification flaw | CWE-347 / A07 | HIGH/MED | Two rules: `jwt.decode` used for auth (HIGH); `jwt.verify` without pinned `algorithms` or allowing `none` (MED). |
| 06-prototype-pollution-merge.yml | Prototype pollution | CWE-1321 / A08 | LOW | **Heuristic.** Flags dynamic `target[key]=source[key]` without a `__proto__/constructor` guard, and unsafe deep-merge of `req.body`. Noisy by nature — tune with `pattern-not-inside`. |

## How to develop a rule fast
Use the Semgrep Playground: https://semgrep.dev/playground — paste the vulnerable snippet
and the fixed snippet, then iterate the pattern until it fires on the first and is silent
on the second. That "fires-on-vuln / silent-on-fix" invariant is the whole game.

## The metric (fill RESULTS.md)
For each class, record whether it is caught by (a) your custom rule and (b) the community
packs alone. The honest delta — e.g. custom 6/6 vs community 3/6, 0 false positives on
`main` — is the headline number in the README.
