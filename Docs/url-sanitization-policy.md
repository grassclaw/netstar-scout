# URL Sanitization & Normalization Policy

> This document is the single source of truth for how scan targets are
> sanitized and validated across the Extension, Server, and Scoring Engine.
> All three layers should follow the rules described here.

## Normalization Steps

Both the **Extension** (`normalizeScanDomain` in `scan.js`) and the
**Server** (`normalizeScanTarget` in `server.js`) apply the same
normalization pipeline:

1. **Coerce & trim** — convert the input to a string and strip leading /
   trailing whitespace.
2. **Extract hostname** — if the input contains `://`, parse it as a full
   URL and take only the hostname. Otherwise treat the input as a bare
   hostname (the extension prepends `https://` so `URL()` can parse it).
3. **Lowercase** — convert the hostname to lowercase for consistent
   caching and comparison.
4. **Strip `www.`** — remove a leading `www.` prefix. The scoring engine
   is domain-oriented (MAIL/RDAP/DNS), and `www.example.com` produces
   different (often worse) results than `example.com`.
5. **Strip trailing dots** — remove any trailing `.` characters (valid in
   DNS but unwanted here).

After these steps the result should be a clean hostname like
`example.com` or `sub.example.co.uk`.

## What Is Allowed

- Domain names that include a valid-looking letter-based TLD  
  (e.g. `example.com`, `sub.example.co.uk`, `example.org`).

## What Is Blocked

| # | Input type                        | Where blocked         | Response / behavior                |
|---|-----------------------------------|-----------------------|------------------------------------|
| 1 | Empty or whitespace-only          | Server                | 400 Bad Request                    |
| 2 | Invalid URL / no parseable domain | Server                | 400 Bad Request                    |
| 3 | `localhost` and equivalents       | Server                | 400 Bad Request                    |
| 4 | Non-http(s) schemes (auto-scan)   | Extension (`tabs.js`) | Silently skipped (no request sent) |
| 5 | Plain IP addresses (manual scan)  | Extension (`messages.js`) TLD check | Error shown in popup           |
| 6 | Input without a letter-based TLD  | Extension (`messages.js`) TLD check | Error shown in popup           |

### Notes

- **Plain IPs are not allowed for now.** The extension's TLD regex
  (`/\.[a-z]{2,}/i`) rejects bare IPv4/IPv6 addresses for manual scans.
  This may be relaxed in a future version.
- The **server is the security boundary**. Even if the extension check is
  bypassed, the server will reject empty, invalid, and localhost targets
  with a 400 response.
- The **Scoring Engine** receives its target via the `-t` CLI argument
  from the server. It expects a pre-sanitized hostname (no scheme, no
  path). No additional validation is performed there.
