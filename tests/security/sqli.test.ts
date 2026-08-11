import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * This test PROVES the exploit on the vulnerable (seed) branch.
 * On `main` (after the parameterized fix), flip `.toBe(true)` to `.toBe(false)`
 * — the same input must no longer leak the users table. That red->green flip is
 * your regression guard and the evidence in the PR writeup.
 */
describe('SQLi in GET /invoices/search', () => {
  it('leaks the users table via a UNION payload (vulnerable branch)', async () => {
    const payload = `x%' UNION SELECT password, username, 0 FROM users -- `;
    const res = await request(app).get('/invoices/search').query({ q: payload });

    const leakedHash = /\$2[aby]\$/.test(JSON.stringify(res.body)); // bcrypt hash pattern
    expect(res.status).toBe(200);
    expect(leakedHash).toBe(true);
  });

  it('normal search still works (functional regression guard)', async () => {
    const res = await request(app).get('/invoices/search').query({ q: 'Domain' });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});
