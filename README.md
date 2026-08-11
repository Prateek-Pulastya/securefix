# SecureFix

Six bugs I'd file on a bug bounty, and how I'd close them as the engineer who owns the code.

It's a small TypeScript/Express API with six planted vulnerabilities, one per common class. For each one the repo walks the whole defender loop: an exploit test that actually fires, the fix that kills it, a Semgrep rule I wrote by hand to catch that exact shape, a CI gate that fails the build if it comes back, and a short writeup that explains the root cause in terms a reviewer (or a manager) cares about.

It is deliberately not a Juice Shop clone. The app is plain and a little boring on purpose. The interesting part is the loop and the detection rules, not the surface area.

## Results

| Metric | Value |
|--------|-------|
| Seeded vuln classes | 6 |
| Caught by my custom Semgrep rules | 6 / 6 |
| Caught by community packs alone (`p/typescript`, `p/owasp-top-ten`) | not measured yet (see note) |
| False positives on remediated `main` | 0 |
| Exploit tests: pass on `seed` / blocked on `main` | 6 / 6 |

Note on the community-pack number: measuring it needs the Semgrep registry (semgrep.dev), which is blocked on my current dev box, so I left it honest rather than guessed. It runs in GitHub CI, where the registry is reachable. Details in `vulns/*/README.md` under "Detection metric".

## The six classes

| # | Class | CWE / OWASP | Endpoint | Rule confidence |
|---|-------|-------------|----------|-----------------|
| 1 | SQL injection | CWE-89 / A03 | `GET /invoices/search` | HIGH |
| 2 | Broken access control (IDOR) | CWE-639 / A01 | `GET /invoices/:id` | LOW (regex heuristic) |
| 3 | SSRF | CWE-918 / A10 | `POST /invoices/import` | HIGH (taint) |
| 4 | Reflected XSS | CWE-79 / A03 | `POST /invoices/:id/note/preview` | MEDIUM (taint) |
| 5 | JWT signature not verified | CWE-347 / A07 | `GET /invoices/mine` | HIGH + MEDIUM |
| 6 | Prototype pollution | CWE-1321 / A08 | `POST /invoices/prefs` | LOW (heuristic) |

Every vulnerable endpoint lives in `src/routes/invoices.ts`. The exploit and its fix sit side by side: the seed branch ships the bug, the JSDoc above each handler spells out the exploit and the fix, and `vulns/0X-*/fix.diff` is the patch you apply on `main`.

## Run it

```bash
npm install            # no native build step; data layer is Node's built-in node:sqlite
npm run typecheck      # tsc, strict
npm run test:security  # the exploit/regression suite (12 tests, 6 classes)
npm run dev            # http://localhost:3000
```

Static analysis is the one thing that isn't a plain `npm run`. Native Semgrep doesn't run on Windows (its Python-to-core bridge calls a Unix-only syscall), so locally I run it in the official Docker image:

```bash
npm run sast:docker:rules   # my custom rules only, offline, fast
npm run sast:docker         # full CI command: custom rules + community packs (needs network)
```

In GitHub CI it's just `pip install semgrep && semgrep scan …` on a Linux runner. The `npm run sast` script is that Linux command, kept as the source of truth.

One quirk worth knowing: `node:sqlite` prints an ExperimentalWarning on startup. It's expected, not a bug.

## Branch model

- `seed/all-vulns` — all six bugs present. Exploit tests pass, the SAST gate goes red.
- `main` — remediated. Same exploit inputs are blocked, SAST goes green.
- One patch per class in `vulns/0X-*/fix.diff`, plus the writeup next to it. That set of six is the portfolio artifact.

## What I'd do next

- Port the SQLi and IDOR slices to Java/Spring, since most of the roles I'm aiming at are still JVM shops.
- Add a CodeQL taint query for the SSRF case and turn on GitHub code scanning, so there's a second engine backing up my Semgrep rules.
- Publish the ruleset as a reusable GitHub Action.

Full plan and rationale: `Project1-SecureFix-build-plan.md` in the parent folder.
