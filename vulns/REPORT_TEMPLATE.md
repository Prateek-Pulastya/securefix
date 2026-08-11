# Bug bounty report template

This is the skeleton every `vulns/0X-*/report.md` follows. It's the finder's view of the bug — the report you'd submit to a program — as opposed to the `README.md` next to it, which is the defender's PR writeup for the fix.

The structure is the common ground between the two platforms I checked: HackerOne's quality-report guidance (title, numbered steps, expected vs actual, impact, supporting material, optional remediation) and Bugcrowd's submission model (where it is, who it affects, how to reproduce, affected parameters, proof of concept, plus a VRT/CWE tag and a CVSS vector). Sources at the bottom.

Fill every section. If one doesn't apply, say why rather than leaving it blank — a triager reads a blank field as "didn't check."

---

## Title

One line. `[Vulnerability type] in [component/endpoint] allows [what the attacker gets]`. No fluff, no severity words — the CVSS carries that.

## Summary

Two or three sentences a triager can read in ten seconds: what the bug is, where, and why it matters. If they read nothing else, this decides whether they keep going.

## Vulnerability details

- **Type / CWE:** the class and its CWE id.
- **Severity:** CVSS v3.1 vector and score, plus the band (Low/Medium/High/Critical). This is the reporter's estimate; the program may re-score. Show the vector so the reasoning is auditable.
- **Affected endpoint / asset:** exact URL, method, and the parameter that carries the payload.
- **Authentication:** what access the attacker needs (none / any logged-in user / specific role).

## Description

What the bug actually is and the root cause — the line or pattern that's wrong, and why the input reaches it. Enough that an engineer who's never seen the code understands the mechanism, not just the symptom.

## Steps to reproduce

Numbered. Exact. Include the request, the parameter, and the account/role if one is needed. Someone should be able to paste these and see the same result with no guessing.

## Proof of concept

The actual request and the response that proves it — `curl` or the raw HTTP, and the part of the response that shows the bug fired (leaked data, reflected payload, changed state). Redact real secrets; keep enough to be convincing.

## Impact

What an attacker does with this in the real product, tied to business consequences — data exposed, accounts taken over, systems reached. Be concrete about the worst realistic case and honest about what's required to get there. This is the section that sets the payout, so it's worth getting right.

## Remediation

The fix you'd recommend, specific to the root cause — not "sanitize input" but the actual control (parameterize the query, scope by owner, verify the signature). Optional on most programs, but it's the difference between a report and a good report.

## References

CWE entry, the relevant OWASP page or cheat sheet, and any prior art. Grounds the class and helps the fixer.

---

Sources: [HackerOne — Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports), [Bugcrowd — Reporting a Bug](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/), [Bugcrowd — Submission Page](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/submission-page/). CVSS: [FIRST CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document). CWE: [MITRE CWE](https://cwe.mitre.org/).
