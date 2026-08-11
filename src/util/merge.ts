// VULNERABLE (seed/all-vulns branch) — CWE-1321 Prototype Pollution / OWASP A08.
//
// Recursively copies every key from `source` into `target` with no prototype guard. When
// `source` is request-derived JSON containing an own "__proto__" key (JSON.parse creates it
// as an own property), the recursion walks target["__proto__"] === Object.prototype and the
// assignment `target[key] = source[key]` writes onto Object.prototype — polluting EVERY
// object in the process.
//
// FIX (applied on `main`, PR #6) — see src/util/merge.ts on main / vulns/06-prototype-pollution:
//   reject '__proto__'/'constructor'/'prototype', assign via a local (so the value never
//   flows as target[key] = source[key]), and rename to safeMerge.
export function deepMerge(
  target: Record<string, any>,
  source: Record<string, any>,
): Record<string, any> {
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      target[key] &&
      typeof target[key] === 'object'
    ) {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key]; // <-- pollutes Object.prototype when key === '__proto__'
    }
  }
  return target;
}
