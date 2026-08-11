// Output encoding for HTML body context. `escapeHtml` is the sanitizer name that Semgrep
// rule 04 (04-xss-unescaped-response.yml) recognizes — wrapping a user value in it before
// res.send() clears the taint. This is HTML *element/text* escaping; it is NOT sufficient
// for attribute-without-quotes, URL, JS, or CSS contexts (see vulns/04-xss/README.md).

const ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(input: string): string {
  return input.replace(/[&<>"']/g, (ch) => ENTITIES[ch]);
}
