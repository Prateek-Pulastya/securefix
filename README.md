<p align="center">
  <img src="docs/assets/cover.png" alt="SecureFix — six ways to break a web app, and how to fix every one" width="100%">
</p>

# SecureFix

> Six real web vulnerabilities, each taken all the way around the loop: a working exploit, the fix, a custom Semgrep rule that catches it next time, and a CI gate that fails the build if it comes back.

![security-ci](https://github.com/Prateek-Pulastya/securefix/actions/workflows/security-ci.yml/badge.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![Semgrep](https://img.shields.io/badge/Semgrep-6%20custom%20rules-e0a458?labelColor=1b212c)
![tests](https://img.shields.io/badge/tests-12%2F12%20passing-3fb950?labelColor=1b212c)
![SAST gate](https://img.shields.io/badge/SAST%20gate-7%20%E2%86%92%200-3fb950?labelColor=f2635f)
![license](https://img.shields.io/badge/license-MIT-3178C6)

I spend most of my time trying to break into systems. This project points the other way: I built a small app, planted six classic bugs in it, and then made it hard for future-me to ever ship them again. Every bug is shown from **both sides of the desk** — the attacker's exploit and the engineer's fix, detection rule, and CI gate.

It is deliberately not a Juice Shop clone. The app is plain on purpose; the value is the loop and the hand-written detection rules, not the surface area.

**▶ Live beginner walkthrough — [prateek-pulastya.github.io/securefix](https://prateek-pulastya.github.io/securefix/)**

**Jump to:** [See it work](#see-it-work) · [The six bugs](#the-six-vulnerabilities) · [How it works](#how-it-works) · [What this demonstrates](#what-this-demonstrates) · [Quickstart](#quickstart)

---

## See it work

The same pipeline runs on two branches. On `seed/all-vulns` the six bugs are present and the SAST gate fails with 7 findings. On `main` they're fixed and it passes with 0. Red before, green after.

<p align="center">
  <img src="docs/assets/redgreen.gif" alt="Terminal: the SAST gate finds 7 issues on the buggy branch and 0 on the fixed branch" width="760">
</p>

---

## The six vulnerabilities

Each class carries two write-ups on purpose: the **finder's report** (bug-bounty format, CVSS + CWE) and the **defender's fix** (the PR view). Same bug, both perspectives.

| # | Class | CWE / OWASP | Severity | Endpoint | Finder's report | The fix |
|---|-------|-------------|----------|----------|-----------------|---------|
| 1 | SQL injection | CWE-89 / A03 | High | `GET /invoices/search` | [report](vulns/01-sqli/report.md) | [README](vulns/01-sqli/README.md) · [diff](vulns/01-sqli/fix.diff) |
| 2 | IDOR | CWE-639 / A01 | Medium | `GET /invoices/:id` | [report](vulns/02-idor/report.md) | [README](vulns/02-idor/README.md) · [diff](vulns/02-idor/fix.diff) |
| 3 | SSRF | CWE-918 / A10 | Critical | `POST /invoices/import` | [report](vulns/03-ssrf/report.md) | [README](vulns/03-ssrf/README.md) · [diff](vulns/03-ssrf/fix.diff) |
| 4 | Reflected XSS | CWE-79 / A03 | Medium | `POST /invoices/:id/note/preview` | [report](vulns/04-xss/report.md) | [README](vulns/04-xss/README.md) · [diff](vulns/04-xss/fix.diff) |
| 5 | JWT signature bypass | CWE-347 / A07 | Critical | `GET /invoices/mine` | [report](vulns/05-jwt/report.md) | [README](vulns/05-jwt/README.md) · [diff](vulns/05-jwt/fix.diff) |
| 6 | Prototype pollution | CWE-1321 / A08 | High | `POST /invoices/prefs` | [report](vulns/06-prototype-pollution/report.md) | [README](vulns/06-prototype-pollution/README.md) · [diff](vulns/06-prototype-pollution/fix.diff) |

Every vulnerable endpoint lives in [`src/routes/invoices.ts`](src/routes/invoices.ts), with a comment above each one explaining the exploit and the fix.

---

## How it works

Every bug goes through the same four steps. Once you've seen it once, the other five are variations.

<p align="center">
  <img src="docs/assets/loop.png" alt="The loop: exploit, fix, rule, gate" width="880">
</p>

**Branch model**

- `seed/all-vulns` — all six bugs present. Exploit tests pass, the SAST gate goes red.
- `main` — remediated. The same exploit inputs are blocked, the gate goes green.

**The detection layer.** Six custom Semgrep rules, two kinds: pattern rules that match a shape of code (a query built with string interpolation), and taint rules that follow a request value into a dangerous sink (a URL from the body reaching `fetch()` without passing a validation step). Proof of the red→green swing lives in [`docs/ci-proof/`](docs/ci-proof/RESULTS.md).

---

## What this demonstrates

For anyone reading this as a work sample:

- **Secure code review across six OWASP classes** — not just naming them, but exploiting, fixing, and regression-testing each one.
- **Detection-as-code** — authoring and *verifying* custom Semgrep rules, including taint analysis. Three of the six rules were silently broken when I first ran them; I only caught it by testing each rule against a live bug and its fix. Details below.
- **DevSecOps** — a CI security gate (type check, SAST, dependency audit, secret scan, regression tests) with a proven red-to-green pipeline.
- **Communication** — a CVSS-scored report and a remediation PR for every bug, plus a beginner-friendly walkthrough. Security work that nobody can read is security work that doesn't land.
- **Honesty about coverage** — documented residual risk (DNS rebinding past the SSRF check, stored-XSS the taint rule can't see) instead of claiming the fixes are complete.

### The part I tell people about

When I sat down to confirm each rule fired, three of the six were broken and matched nothing:

- The IDOR rule used a Semgrep construct that isn't valid, so it matched a literal string and fired on nothing.
- The JWT rule had a YAML error that stopped the whole file from loading.
- The SQL injection rule flagged the *correct* parameterized fix as if it were the bug.

All three "worked" in the sense that they ran clean. A detection rule that matches nothing looks exactly like a codebase with no bugs. I found them because I run every rule twice — once against the vulnerable code expecting a hit, once against the fix expecting silence. Test your security tooling like you test your code.

---

## Quickstart

```bash
git clone https://github.com/Prateek-Pulastya/securefix.git
cd securefix
npm install            # zero native build — data layer is Node's built-in node:sqlite
npm run typecheck      # tsc, strict
npm run test:security  # 12 exploit/regression tests
```

Run the scanner. In CI it's plain `pip install semgrep && semgrep scan`; locally I run it in Docker (native Semgrep doesn't run on Windows):

```bash
npm run sast:docker:rules   # my custom rules, offline, fast
npm run sast:docker         # full gate: custom rules + community packs
```

Try the red→green yourself:

```bash
git checkout seed/all-vulns && npm run test:security && npm run sast:docker:rules   # 7 findings
git checkout main            && npm run test:security && npm run sast:docker:rules   # 0 findings
```

> `node:sqlite` prints an ExperimentalWarning on startup — expected, not a bug.

---

## Project structure

```
securefix/
├── src/
│   ├── routes/invoices.ts    # all six vulnerable endpoints (seed branch)
│   ├── security/             # the sanitizers: urlGuard, html, auth
│   ├── util/merge.ts         # the prototype-pollution merge
│   └── db.ts                 # in-memory node:sqlite, seed data
├── tests/security/           # 6 exploit suites, 12 tests
├── semgrep-rules/            # 6 hand-written rule files (+ README on confidence/limits)
├── vulns/0X-*/               # per class: report.md, README.md (fix), fix.diff
├── docs/
│   ├── learn.html            # beginner walkthrough
│   └── ci-proof/             # red/green pipeline evidence
└── .github/workflows/        # the CI security gate
```

---

## Tech

TypeScript (strict) · Express · Node `node:sqlite` · Semgrep · GitHub Actions · Docker · Vitest · Supertest · `jsonwebtoken`

## License

MIT — see [LICENSE](LICENSE).

Built by [Prateek Pulastya](https://github.com/Prateek-Pulastya) as a portfolio piece. New here? Start with the [live walkthrough](https://prateek-pulastya.github.io/securefix/).
