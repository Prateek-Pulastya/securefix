import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * PROVES the exploit on the vulnerable (seed) branch: a <script> in the note is reflected
 * verbatim into a text/html response, so it executes when previewed.
 *
 * On `main` (after escapeHtml on output), flip the exploit assertions: the raw tag must be
 * gone and the escaped entity (&lt;script&gt;) present instead.
 */
describe('Reflected XSS in POST /invoices/:id/note/preview', () => {
  const payload = `<script>alert(document.cookie)</script>`;

  it('reflects an unescaped <script> into the HTML response (vulnerable branch)', async () => {
    const res = await request(app).post('/invoices/1/note/preview').send({ note: payload });

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.text).toContain(payload); // on `main`: .not.toContain(payload), expect '&lt;script&gt;'
  });

  it('rejects a missing note (input guard, green on both branches)', async () => {
    const res = await request(app).post('/invoices/1/note/preview').send({});
    expect(res.status).toBe(400);
  });
});
