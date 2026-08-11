# CI proof: red on seed, green on main

The same pipeline runs on both branches. On `seed/all-vulns` the SAST gate fails because the six planted bugs are present. On `main` the fixes are in and it passes. That red-to-green swing is the evidence the loop actually works.

These numbers come from running the pipeline locally, not from a GitHub Actions run. Two reasons: native Semgrep doesn't run on Windows (its Python-to-core bridge needs a Unix syscall), so I run it in the official Docker image; and semgrep.dev is blocked on this box, so the community-pack half of the SAST step can't download here. The custom-rule scan is the honest local signal. In GitHub CI the workflow in `.github/workflows/security-ci.yml` runs the full thing on a Linux runner.

## Results

| Step | `seed/all-vulns` | `main` |
|------|------------------|--------|
| `npm run typecheck` | pass | pass |
| `npm run test:security` | 12/12 pass (exploits fire) | 12/12 pass (exploits blocked) |
| SAST — custom rules, `--error` | 7 findings, exit 1 (**red**) | 0 findings, exit 0 (**green**) |

A note on the test row: the exploit tests pass on both branches, but they assert opposite things. On seed each one proves the bug works. On main the same input is expected to be blocked (404, 401, escaped output, no pollution). The assertion flip is the regression guard.

## The seven findings on seed

Six classes, seven findings — prototype pollution trips two sub-rules (the dynamic assign in `merge.ts` and the unsafe merge call in the route).

| Rule | File | Class |
|------|------|-------|
| `sqli-template-literal-in-query` | `src/routes/invoices.ts` | SQL injection |
| `idor-query-by-id-missing-owner-scope` | `src/routes/invoices.ts` | IDOR |
| `ssrf-user-controlled-url` | `src/routes/invoices.ts` | SSRF |
| `xss-user-input-in-html-response` | `src/routes/invoices.ts` | reflected XSS |
| `jwt-decode-used-for-auth` | `src/security/auth.ts` | JWT |
| `prototype-pollution-dynamic-assign` | `src/util/merge.ts` | prototype pollution |
| `prototype-pollution-unsafe-merge-of-user-input` | `src/routes/invoices.ts` | prototype pollution |

On `main`, all seven are gone and the scan exits clean.

## Reproduce

```bash
# red side
git checkout seed/all-vulns
npm run typecheck && npm run test:security
npm run sast:docker:rules   # 7 findings, non-zero exit

# green side
git checkout main
npm run typecheck && npm run test:security
npm run sast:docker:rules   # 0 findings, clean exit
```

The raw capture is in `pipeline-proof.txt` next to this file.
