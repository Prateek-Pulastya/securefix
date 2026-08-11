import type { Request } from 'express';
import jwt from 'jsonwebtoken';

// Symmetric signing key. In prod this comes from the environment; the fallback is a dev-only
// placeholder (a weak/hardcoded secret is its own issue, out of scope for this slice).
export const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-only-change-me';

export interface Principal {
  sub: number;
}

function bearer(req: Request): string {
  return (req.header('authorization') ?? '').replace(/^Bearer /, '');
}

/**
 * VULNERABLE (seed/all-vulns branch) — CWE-347 / OWASP A07.
 *
 * jwt.decode() ONLY base64-decodes the token; it does NOT check the signature. Any attacker
 * can mint a token with arbitrary claims (any `sub`, `role: admin`, …) and this trusts it.
 *
 * FIX (applied on `main`, PR #5) — verify the signature AND pin the algorithm:
 *   const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as jwt.JwtPayload;
 * Pinning blocks the `alg: none` downgrade and RS256/HS256 key-confusion attacks.
 */
export function authenticate(req: Request): Principal | null {
  const token = bearer(req);
  if (!token) return null;
  const payload = jwt.decode(token) as jwt.JwtPayload | null; // <-- no signature verification
  if (!payload || typeof payload.sub !== 'number') return null;
  return { sub: payload.sub };
}
