// SSRF guard. `assertPublicHost` is the sanitizer name that Semgrep rule 03
// (03-ssrf-user-controlled-url.yml) recognizes — routing a user URL through it before
// fetch() clears the taint. Blocks non-http(s) schemes, loopback, RFC1918, link-local
// (incl. 169.254.169.254 cloud metadata), and *.local/*.internal names.

export class SsrfBlockedError extends Error {}

function isPrivateIpv4(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 0 || a === 10 || a === 127) return true;      // this-host / 10.0.0.0/8 / loopback
  if (a === 169 && b === 254) return true;                // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true;       // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                // 192.168.0.0/16
  return false;
}

function isPrivateIpv6(host: string): boolean {
  if (!host.includes(':')) return false;
  return host === '::1' || host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80');
}

/**
 * Returns the normalized URL if its host is a public destination; otherwise throws
 * SsrfBlockedError. Note: this validates the *literal* host, not the resolved IP, so a
 * hostname that resolves to a private address (DNS rebinding) is a documented residual
 * risk — see vulns/03-ssrf/README.md.
 */
export function assertPublicHost(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SsrfBlockedError('malformed URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new SsrfBlockedError(`scheme ${u.protocol} not allowed`);
  }
  const host = u.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host === '0.0.0.0' ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    isPrivateIpv4(host) ||
    isPrivateIpv6(host)
  ) {
    throw new SsrfBlockedError(`host ${host} is not a public destination`);
  }
  return u.toString();
}

export const isAllowedUrl = (raw: string): boolean => {
  try {
    assertPublicHost(raw);
    return true;
  } catch {
    return false;
  }
};
