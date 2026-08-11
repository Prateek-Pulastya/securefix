import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app';

/**
 * PROVES the exploit on the vulnerable (seed) branch: a "__proto__" key in the merge body
 * writes onto Object.prototype, so a brand-new {} inherits the injected property.
 *
 * The payload is sent as a raw JSON string with an explicit JSON content-type so express.json
 * parses "__proto__" as an OWN property (a JS object literal `{ __proto__: … }` would set the
 * prototype instead of creating that key). On `main` (safeMerge rejects the key), flip the
 * exploit assertion: ({} as any).polluted stays undefined.
 */
describe('Prototype pollution in POST /invoices/prefs', () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).polluted; // don't leak across tests
  });

  it('pollutes Object.prototype via __proto__ in the body (vulnerable branch)', async () => {
    expect(({} as Record<string, unknown>).polluted).toBeUndefined(); // clean before

    const res = await request(app)
      .post('/invoices/prefs')
      .set('Content-Type', 'application/json')
      .send('{"__proto__":{"polluted":"yes"}}');

    expect(res.status).toBe(200);
    expect(({} as Record<string, unknown>).polluted).toBe('yes'); // on `main`: .toBeUndefined()
  });

  it('merges an ordinary key without polluting (green on both branches)', async () => {
    const res = await request(app)
      .post('/invoices/prefs')
      .set('Content-Type', 'application/json')
      .send('{"theme":"dark"}');

    expect(res.status).toBe(200);
    expect((res.body.prefs as Record<string, unknown>).theme).toBe('dark');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
