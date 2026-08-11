import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * PROVES the exploit on the vulnerable (seed) branch: the server trusts a token it never
 * signed. The attacker signs with THEIR OWN secret (they don't know the server's), claims
 * `sub: 2` (bob), and reads bob's invoices — because jwt.decode() skips signature checks.
 *
 * On `main` (jwt.verify with the real secret + pinned algorithm), the forged signature
 * fails and the request is 401. Flip the exploit expectation from 200 to 401.
 */
describe('JWT forgery in GET /invoices/mine', () => {
  it('accepts a token signed with the wrong secret (vulnerable branch)', async () => {
    const forged = jwt.sign({ sub: 2 }, 'attacker-secret-not-the-servers'); // bob, wrong key
    const res = await request(app).get('/invoices/mine').set('authorization', `Bearer ${forged}`);

    expect(res.status).toBe(401); // forged signature fails verification
    expect(JSON.stringify(res.body)).not.toContain('Pentest engagement'); // no data leaked
  });

  it('rejects a request with no token (green on both branches)', async () => {
    const res = await request(app).get('/invoices/mine');
    expect(res.status).toBe(401);
  });
});
