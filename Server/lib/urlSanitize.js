/**
 * Normalize and validate a user-provided domain or URL into a scan target.
 *
 * ── How it works ──────────────────────────────────────────────────────────
 *  1. Coerce to string and trim whitespace.
 *  2. If the input contains "://", parse it as a URL and extract the hostname.
 *     Otherwise treat the raw input as a bare hostname.
 *  3. Lowercase the hostname for consistent caching and comparison.
 *  4. Strip a leading "www." — the scoring engine is domain-oriented
 *     (MAIL/RDAP/DNS) and "www.example.com" produces different results.
 *  5. Strip any trailing dots (valid in DNS, unwanted here).
 *
 * ── What is blocked (returns { ok: false, reason }) ──────────────────────
 *  • Empty or whitespace-only input.
 *  • Input that cannot be parsed into a hostname.
 *  • "localhost" (and equivalents like "127.0.0.1", "::1", "0.0.0.0").
 *  • Plain IP addresses (no letter-based TLD).
 *
 * See Docs/url-sanitization-policy.md for the full policy.
 *
 * @param {string} raw - The domain or URL string from the query parameter.
 * @returns {{ ok: true, domain: string } | { ok: false, reason: string }}
 */
function normalizeScanTarget(raw) {
  let target = String(raw ?? "").trim();

  // 1. Empty check
  if (!target) {
    return { ok: false, reason: "No domain or URL provided." };
  }

  // 2. Extract hostname from a full URL (contains "://")
  try {
    if (target.includes("://")) {
      const u = new URL(target);
      target = u.hostname;
    }
  } catch {
    return { ok: false, reason: "Malformed URL — could not extract a hostname." };
  }

  // 3. Lowercase
  target = target.toLowerCase();

  // 4. Strip leading "www."
  if (target.startsWith("www.")) target = target.slice(4);

  // 5. Strip trailing dots
  target = target.replace(/\.+$/, "");

  // ── Validation ──────────────────────────────────────────────────────

  // Block empty result after normalization
  if (!target) {
    return { ok: false, reason: "Domain resolved to an empty string after normalization." };
  }

  // Block localhost and loopback equivalents
  const LOCALHOST_PATTERNS = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
  if (LOCALHOST_PATTERNS.includes(target)) {
    return { ok: false, reason: "Scanning localhost or loopback addresses is not allowed." };
  }

  // Block plain IP addresses (no letter-based TLD).
  // IPv4 pattern: digits and dots only (e.g. "192.168.1.1")
  // IPv6 pattern: hex digits, colons, optional brackets (e.g. "::1", "2001:db8::1")
  const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  const IPV6_RE = /^[\da-f:]+$/i;
  if (IPV4_RE.test(target) || IPV6_RE.test(target)) {
    return { ok: false, reason: "Plain IP addresses are not supported. Please enter a domain name." };
  }

  // Require at least one dot followed by 2+ letters (letter-based TLD)
  if (!/\.[a-z]{2,}$/i.test(target)) {
    return { ok: false, reason: "Invalid domain — no recognizable top-level domain (e.g. .com, .org)." };
  }

  return { ok: true, domain: target };
}

module.exports = { normalizeScanTarget };
