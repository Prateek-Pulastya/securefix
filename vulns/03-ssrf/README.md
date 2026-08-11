# Fix: SSRF in invoice import  (CWE-918 / OWASP A10)

**Impact / business risk.**
The server fetches any URL a caller supplies. An attacker uses the server as a proxy into
the network it trusts: cloud instance metadata (`http://169.254.169.254/…` → IAM
credentials), internal admin panels, RFC1918 services, `localhost`. On a cloud host this is
commonly a direct path to credential theft and lateral movement.

**Reproduction.**
```
POST /invoices/import
{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```
The response body is whatever that internal endpoint returned. Automated proof:
`tests/security/ssrf.test.ts` stands up a `127.0.0.1` service and shows the app reaches it.

**Root cause.**
User input flows into an outbound request with no validation:
```ts
const url = req.body?.url;
const upstream = await fetch(url);   // attacker controls the destination
```
A guard (`src/security/urlGuard.ts::assertPublicHost`) already existed — the import handler
just never called it. That's the usual SSRF story: the control exists, one code path skips it.

**Fix.**
Route the URL through the allowlist/deny check before fetch; the taint is cleared and
internal targets are rejected:
```ts
import { assertPublicHost } from '../security/urlGuard';
// …
let safe: string;
try { safe = assertPublicHost(url); }
catch { return res.status(400).json({ error: 'url host is not permitted' }); }
const upstream = await fetch(safe);
```
See `fix.diff`. After the fix, the metadata/loopback payloads return 400 and the exploit
test flips its expectation from `200` to `400`.

**Prevention (so it can't come back).**
Custom Semgrep rule `ssrf-user-controlled-url` (taint mode) tracks `req.body/query/params`
into `fetch`/`axios`/`http.request` sinks and treats `assertPublicHost(...)` /
`isAllowedUrl(...)` as sanitizers. It runs in CI — any import path that fetches a
request-derived URL without the guard fails the build. This is a **HIGH-confidence** rule:
real dataflow, not a regex heuristic (unlike rules 02/06).

**Detection metric.**
- Custom rule: **fires** on the raw `fetch(url)` path, **silent** once the value passes
  through `assertPublicHost(...)`.
- Community `p/owasp-top-ten`: _[measure and record in RESULTS.md]_.

**Residual risk / notes.**
- `assertPublicHost` validates the **literal** host, not the resolved IP. A public hostname
  that resolves to a private address (**DNS rebinding**), or an HTTP redirect to an internal
  host, still gets through. Hardening: resolve DNS and re-check the IP, pin the resolved
  address for the actual connection, and disable/verify redirects. Documented and accepted
  for this slice; the taint rule only proves the value was *validated*, not that the
  validator is complete.
- IPv4/IPv6 private ranges are covered by literal parsing; exotic encodings (decimal/octal
  IPs, IPv4-mapped IPv6) are a known gap.
