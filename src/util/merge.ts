// REMEDIATED (main branch) — CWE-1321 Prototype Pollution / OWASP A08.
//
// Recursively merges `source` into `target`, but drops the keys an attacker uses to reach
// Object.prototype ('__proto__', 'constructor', 'prototype'), and assigns through a local
// so the value never flows as the raw `target[key] = source[key]` gadget. The seed branch
// shipped the unguarded version (see vulns/06-prototype-pollution/).
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

export function safeMerge(
  target: Record<string, any>,
  source: Record<string, any>,
): Record<string, any> {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue; // drop __proto__/constructor/prototype
    const value = source[key];
    if (value && typeof value === 'object' && target[key] && typeof target[key] === 'object') {
      safeMerge(target[key], value);
    } else {
      target[key] = value; // local RHS: no target[key] = source[key] gadget
    }
  }
  return target;
}
