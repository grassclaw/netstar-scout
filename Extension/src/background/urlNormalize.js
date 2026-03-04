/**
 * Normalize a raw URL or domain into a clean hostname for caching and API
 * requests. This mirrors the server's normalization (see
 * Docs/url-sanitization-policy.md) so that both layers produce the same
 * canonical domain for a given input.
 *
 * Steps:
 *  1. Coerce to string and trim whitespace.
 *  2. Parse as a URL (prepend "https://" if no scheme) to extract hostname.
 *     On parse failure, fall back to the raw string (best effort).
 *  3. Lowercase and strip trailing dots.
 *  4. Strip leading "www." so the scoring engine gets the apex domain.
 *
 * This function does NOT reject invalid input — it returns an empty string
 * or a best-effort hostname. Actual blocking happens in messages.js (TLD
 * check for manual scans) and on the server (400 for invalid targets).
 *
 * @param {string} rawInput - A URL or bare domain entered by the user or
 *   obtained from a browser tab.
 * @returns {string} The normalized hostname, or "" if input was empty.
 */
export function normalizeScanDomain(rawInput) {
  let raw = String(rawInput ?? "").trim();
  if (!raw) return "";

  // Parse as URL to reliably extract the hostname.
  // If the input has no scheme (e.g. "capitalone.com"), prepend "https://"
  // so the URL constructor can handle it.
  let hostname = raw;
  try {
    const u = raw.includes("://") ? new URL(raw) : new URL(`https://${raw}`);
    hostname = u.hostname;
  } catch {
    // If parsing fails, fall back to raw (best effort).
    hostname = raw;
  }

  hostname = String(hostname).toLowerCase().replace(/\.+$/, "");
  if (hostname.startsWith("www.")) hostname = hostname.slice(4);
  return hostname;
}
