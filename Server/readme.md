# NetSTAR Shield Server

Express API that serves the `/scan` endpoint for the NetSTAR Shield browser extension. It normalizes and validates scan targets, then invokes the Python scoring engine to produce security scores.

> **Shared policy:** The normalization and validation rules below follow the project-wide [URL Sanitization & Normalization Policy](../Docs/url-sanitization-policy.md), which is the single source of truth for how scan targets are handled across the Extension, Server, and Scoring Engine.

---

## URL Sanitization & Normalization

Scan targets (domains or URLs) are sanitized and validated before being passed to the scoring engine. The logic lives in [`lib/urlSanitize.js`](lib/urlSanitize.js), which exports `normalizeScanTarget`.

### Normalization Steps

1. Coerce to string and trim whitespace
2. If the input contains `://`, parse as a URL and extract the hostname; otherwise treat as a bare hostname
3. Lowercase the hostname
4. Strip a leading `www.`
5. Strip trailing dots

### Validation (Blocked Inputs)

Invalid inputs cause the server to return **400 Bad Request** with a JSON body containing `error: true` and a descriptive `message`. Blocked inputs include:

- Empty or whitespace-only
- Malformed URLs (e.g. `https://` with no host)
- `localhost` and loopback addresses (`127.0.0.1`, `::1`, `0.0.0.0`)
- Plain IP addresses (IPv4 or IPv6)
- Inputs without a letter-based TLD (e.g. `.com`, `.org`)

See [`Docs/url-sanitization-policy.md`](../Docs/url-sanitization-policy.md) for the full policy shared with the extension.

---

## Unit Tests

Tests use **Jest** and **supertest**. Run them with:

```bash
npm test
```

### Test Structure

| File | Purpose |
|------|---------|
| [`__tests__/urlSanitize.test.js`](__tests__/urlSanitize.test.js) | Unit tests for `normalizeScanTarget` |
| [`__tests__/scan.test.js`](__tests__/scan.test.js) | Integration tests for `GET /scan` |

### How `urlSanitize.test.js` Works

Tests the `normalizeScanTarget` function in isolation:

- **Valid inputs** — Asserts that full URLs, bare domains, and whitespace/`www.`/trailing-dot variants normalize to the expected hostname (e.g. `https://www.Example.COM/path` → `example.com`).
- **Blocked inputs** — Asserts that empty, localhost, plain IPs, and inputs without a TLD return `{ ok: false, reason: "..." }` instead of a domain.

No mocks are used; it exercises the normalization and validation logic directly.

### How `scan.test.js` Works

Uses **supertest** to send real HTTP requests to the Express app. The Python scoring engine is **never executed** because:

- `child_process.spawn` is mocked to return a fake child process that emits predefined stdout/stderr and an exit code.
- `fs.existsSync` is mocked so `resolvePythonScript()` always finds `scoring_main.py`, allowing the handler to run.

The mock child process uses `setImmediate` to schedule events (spawn, data, close) *after* the handler attaches listeners, so the success path (200) and failure paths (500) work as expected.

Tests cover:

- **400 responses** — Blocked inputs (localhost, plain IPs, no TLD, etc.) return the expected error payload.
- **200 responses** — Valid domains return a JSON body with `safetyScore`, `aggregatedScore`, and `indicators` when the mock emits valid scoring JSON.
- **500 responses** — Non-zero exit code or invalid JSON from the mock triggers the appropriate error response.

### App Export for Testing

The server only calls `app.listen()` when run directly (`require.main === module`). When the test suite `require`s `server.js`, it receives the Express `app` via `module.exports = { app }` without starting a listener, so tests can use supertest against the app in-process.
