import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * PROVES the exploit on the vulnerable (seed) branch: a caller-supplied URL makes the
 * server reach an internal-only service it shouldn't. The stand-in "internal" server binds
 * 127.0.0.1 and returns a secret — the same shape as cloud metadata at 169.254.169.254.
 *
 * On `main` (after `assertPublicHost` is wired in), flip the exploit expectation from 200
 * to 400 — a private/link-local host must be rejected before any fetch happens.
 */
describe('SSRF in POST /invoices/import', () => {
  let internal: http.Server;
  let internalUrl: string;

  beforeAll(async () => {
    internal = http.createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ secret: 'INTERNAL-METADATA-token-abc123' }));
    });
    await new Promise<void>((resolve) => internal.listen(0, '127.0.0.1', resolve));
    const { port } = internal.address() as AddressInfo;
    internalUrl = `http://127.0.0.1:${port}/latest/meta-data/`;
  });

  afterAll(() => new Promise<void>((resolve) => internal.close(() => resolve())));

  it('reaches an internal-only host via a user url (vulnerable branch)', async () => {
    const res = await request(app).post('/invoices/import').send({ url: internalUrl });

    expect(res.status).toBe(400); // assertPublicHost rejects the private host before any fetch
    expect(JSON.stringify(res.body)).not.toContain('INTERNAL-METADATA'); // nothing was fetched
  });

  it('rejects a missing url (input guard, green on both branches)', async () => {
    const res = await request(app).post('/invoices/import').send({});
    expect(res.status).toBe(400);
  });
});
