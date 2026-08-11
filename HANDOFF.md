# SecureFix — handoff / status

Where the project stands and how to pick it back up. Repo: `E:\Learning\Projects\securefix\`. Full plan: `E:\Learning\Projects\Project1-SecureFix-build-plan.md`.

## Context

Portfolio piece for an application/AI-security role (Berlin, targeting the 2026 cycle). The point is to show secure code review and remediation in TypeScript — the language gap that comes up most for junior AppSec roles — plus DevSecOps CI, custom detection rules, and writeups a developer would actually read. Depth over breadth: six classes done properly beat twelve half-done. Not being rewritten in Python. Not a Juice Shop clone.

## Status: all six classes done and verified

Each class is a full slice: vulnerable endpoint, an exploit test that passes on seed, the fix, a custom Semgrep rule that fires on the bug and stays quiet on the fix, and a writeup in `vulns/0X-*/`.

```
securefix/
├── package.json                 # scripts: dev / typecheck / test / test:security / sast / sast:docker[:rules]
├── tsconfig.json                # ES2022, strict
├── vitest.config.ts
├── README.md                    # thesis + results + the 6 classes + run/branch model
├── HANDOFF.md                   # this file
├── src/
│   ├── app.ts                   # express app (exported for tests) + /health
│   ├── server.ts                # listen wrapper
│   ├── db.ts                    # in-memory node:sqlite; users + invoices seed
│   ├── routes/invoices.ts       # ALL six vulnerable endpoints (seed branch)
│   ├── security/
│   │   ├── urlGuard.ts          # assertPublicHost (SSRF sanitizer, class 3)
│   │   ├── html.ts              # escapeHtml (XSS sanitizer, class 4)
│   │   └── auth.ts              # JWT auth — the vuln lives here (class 5)
│   └── util/merge.ts            # deepMerge — the vuln lives here (class 6)
├── tests/security/              # sqli / idor / ssrf / xss / jwt / proto  (2 tests each, 12 total)
├── semgrep-rules/               # 6 rule files (8 rules; jwt + proto have 2 each) + README
├── .github/workflows/security-ci.yml
└── vulns/                       # 01-sqli … 06-prototype-pollution, each README.md + fix.diff
```

## Verify (all green on this machine)

```bash
cd E:\Learning\Projects\securefix
npm install               # zero native deps, nothing to compile
npm run typecheck         # clean
npm run test:security     # 12/12 pass — every exploit fires on seed
npm run sast:docker:rules # 6 findings, one per class (custom rules, via Docker)
```

Semgrep note: native Semgrep is broken on Windows (its Python-to-core RPC calls `socketpair`, which Windows doesn't have), so I run it in Docker. And semgrep.dev is blocked on this box, so the full `npm run sast` (which pulls the community packs) only completes in GitHub CI. The custom-rule scan is the local signal.

## The six, as built

| # | Endpoint | The bug | The fix | What the rule keys on |
|---|----------|---------|---------|-----------------------|
| 1 SQLi | `GET /invoices/search` | template literal in `db.prepare(...)` | parameterize with `?` | interpolated query string |
| 2 IDOR | `GET /invoices/:id` | `WHERE id = ?`, no owner check | add `AND owner_id = ?` | select-by-id with no owner predicate |
| 3 SSRF | `POST /invoices/import` | `fetch(req.body.url)` | `assertPublicHost(url)` first | taint: `req.*` into `fetch` without a sanitizer |
| 4 XSS | `POST /invoices/:id/note/preview` | note interpolated into `res.send` HTML | `escapeHtml(note)` | taint: `req.*` into `res.send` without encoding |
| 5 JWT | `GET /invoices/mine` (`auth.ts`) | `jwt.decode()` used as auth | `jwt.verify(t, s, { algorithms: ['HS256'] })` | `jwt.decode`, and `verify` with no pinned alg |
| 6 Proto | `POST /invoices/prefs` (`merge.ts`) | `deepMerge(prefs, req.body)`, `t[k] = s[k]` | reject `__proto__/constructor/prototype`, `safeMerge` | dynamic key assign + unsafe merge of `req.body` |

## Two things I had to fix in the rules themselves

Both were shipped but never run, which is exactly what "confirm the rule fires" is supposed to catch:

- Rule 02 (IDOR) used a `$DB.prepare("=~/regex/")` construct that isn't valid Semgrep. It matched a literal string and fired on nothing. Rewrote it with `metavariable-regex` on the SQL plus a `pattern-not-regex` for the owner predicate.
- Rule 05 had a YAML parse error on line 29 — an unquoted `algorithms:` inside a pattern value — which stopped the whole file from loading. Quoted it.

Design lesson for the heuristic rules: the vulnerable code must not contain the token the rule excludes. The IDOR vuln `SELECT` deliberately omits the `owner_id` column, otherwise the rule suppresses itself on the bug.

## Still open (not blocking)

- Fill the `RESULTS.md` detection numbers (custom rule vs community pack). The placeholders are in each `vulns/0X/README.md` under "Detection metric". Needs a network where semgrep.dev is reachable.
- Optional: a short blog-style writeup in `docs/`.

## Guardrails

- Stay in TypeScript. Python adds nothing here.
- The custom rules are the point — running stock Semgrep only would be low signal.
- Write each `vulns/0X` writeup during the work, not after.
- Keep the app minimal. The bugs, fixes, and rules are the product.
