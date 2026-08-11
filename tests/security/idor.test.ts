import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * This test PROVES the exploit on the vulnerable (seed) branch: alice reads bob's invoice.
 * On `main` (after the owner-scope fix), flip the cross-owner `.status` expectation from
 * 200 to 404 — the same request must no longer return another user's row. That red->green
 * flip is the regression guard and the evidence in the PR writeup.
 *
 * Seed data (src/db.ts): invoice 1,2 -> owner 1 (alice); invoice 3 -> owner 2 (bob).
 * The principal is carried in `x-user-id` (stands in for a JWT `sub` / session user).
 */
describe('IDOR in GET /invoices/:id', () => {
  it('lets alice read bob\'s invoice by id (vulnerable branch)', async () => {
    const res = await request(app).get('/invoices/3').set('x-user-id', '1'); // alice, bob's invoice

    expect(res.status).toBe(200); // on `main`: .toBe(404)
    expect(res.body.description).toBe('Pentest engagement'); // bob's data leaked cross-owner
  });

  it('alice reading her own invoice still works (functional regression guard)', async () => {
    const res = await request(app).get('/invoices/1').set('x-user-id', '1');
    expect(res.status).toBe(200);
    expect(res.body.description).toBe('Cloud hosting - August');
  });
});
