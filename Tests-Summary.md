# NetSTAR Shield — Test Coverage Summary

This document lists the tests implemented in the project. It is intended for sharing with sponsors and stakeholders.

---

## 1. Server (Jest)

**Location:** `Server/__tests__/`  
**Run:** `cd Server && npm test`  
**Runs in CI:** Yes

### URL sanitization — `urlSanitize.test.js`

Tests for `normalizeScanTarget()` (input validation and normalization before scanning).

| Category | Tests |
|----------|--------|
| **Valid inputs** | Extracts hostname from https URL and lowercases; from http URL; bare domain; trims whitespace; strips leading `www.`; strips trailing dots; lowercases; handles subdomains |
| **Blocked — empty** | Rejects empty string; whitespace-only; null; undefined |
| **Blocked — malformed URL** | Rejects `https://` (no host); rejects invalid URL with `://` |
| **Blocked — localhost/loopback** | Rejects localhost, 127.0.0.1, ::1, 0.0.0.0; rejects http://localhost/path; rejects https://127.0.0.1:8080 |
| **Blocked — IP addresses** | Rejects private IPv4 (192.168.1.1); public IPv4 (8.8.8.8); 10.0.0.1; IPv6-like string |
| **Blocked — no TLD** | Rejects single word (no dot); rejects "notadomain"; rejects single-letter TLD (e.g. example.x) |

### Scan API — `scan.test.js`

Tests for `GET /scan` (mocked scoring engine; no real Python or external APIs).

| Category | Tests |
|----------|--------|
| **400 — blocked inputs** | Rejects when no domain/url provided; rejects localhost; 127.0.0.1; plain IPv4; input without TLD; http://localhost/path via ?url=; returns expected JSON shape on 400 (error, message, safetyScore, aggregatedScore, indicators, timestamp) |
| **200 — valid domain** | Returns 200 with safetyScore for valid domain; returns correct aggregated score; indicators array has id, name, score, status; handles ?url= with full URL that resolves to valid domain |
| **500 — engine failure** | Returns 500 when scoring engine exits non-zero; returns 500 when scoring engine outputs invalid JSON |

---

## 2. Extension (Vitest)

**Location:** `Extension/__tests__/urlNormalize.test.js`, `Extension/test/example.test.jsx`  
**Run:** `cd Extension && npm test`  
**Runs in CI:** No

### URL normalization — `urlNormalize.test.js`

Tests for `normalizeScanDomain()` (same normalization behavior as server for cache/API).

| Category | Tests |
|----------|--------|
| **Normalized hostname** | Extracts hostname from https URL; from http URL; bare domain; trims whitespace; strips www.; strips trailing dots; lowercases; subdomains; strips www. from full URL |
| **Empty input** | Returns '' for empty string; whitespace-only; null; undefined |
| **Fallback** | Best-effort for single word (no dot); does not throw for unusual input (e.g. ://bad) |
| **Parity with server** | Same hostname as server for: https www URL, http subdomain, trimmed domain, www., trailing dot, mixed case |

### Example — `example.test.jsx`

| Test | Description |
|------|-------------|
| Simple math | 1 + 1 === 2 |
| Component render | HelloWorld component renders "Hello, World!" |

---

## 3. Scoring Engine (pytest)

**Location:** `Scoring Engine/test_score_engine.py`  
**Run:** `cd "Scoring Engine" && pytest test_score_engine.py -v`  
**Runs in CI:** No  
**Details:** See `Scoring Engine/TESTING.md`

### Test classes and coverage

| Class | What it tests |
|-------|----------------|
| **TestCertScoring** | Valid cert good expiration; expired cert; expiring soon (15 days, 5 days); missing/malformed cert data; cert not yet valid; hostname mismatch; chain not verified |
| **TestDNSScoring** | Optimal DNS config; poor config; no IPv6; single A record; single AAAA record; incomplete/low rcode |
| **TestHVALScoring** | Optimal HVAL (HTTPS, TLS, headers); HTTP-only site; missing one critical header; weak cipher; outdated TLS |
| **TestMailScoring** | Optimal mail config; no MX records; single MX; no DMARC; weak DMARC policy; no SPF; SPF softfail |
| **TestMethodScoring** | Optimal (HEAD/GET); acceptable (HEAD/GET/POST); dangerous (PUT/DELETE/TRACE); CONNECT/PATCH |
| **TestRDAPScoring** | Optimal RDAP (nameservers); single nameserver; two same vendor; three diverse; empty nameserver list |
| **TestFinalScoreCalculation** | All perfect scores; mixed scores; zero score returns 1; partial scores; empty scores |
| **TestCredentialSafetyScoring** | Good TLS and HSTS; outdated TLS; missing HSTS header |
| **TestSecurityScoreCalculation** | Complete scan (optimal); poor scan (integration-style) |
| **TestCurlExecution** | Successful curl; failed execution; timeout; curl not found (mocked) |

---

## 4. Full-system E2E (CI)

**Location:** `.github/workflows/ci.yml`  
**Runs:** On every push to `main` and every pull request targeting `main`

| Step | What it does |
|------|----------------|
| Setup | Checkout; Python 3.11; install Scoring Engine deps; Node 20; install Server deps |
| Server unit tests | `cd Server && npm test` |
| Full-system scan | Start server with `USE_SCORING_TEST_DATA=1`; `curl` `GET /scan?domain=example.com`; assert response is JSON with `error !== true` and `safetyScore` is a number |

---

## Quick reference

| Layer | Framework | Test files | In CI |
|-------|-----------|------------|--------|
| Server | Jest | `Server/__tests__/urlSanitize.test.js`, `Server/__tests__/scan.test.js` | Yes |
| Extension | Vitest | `Extension/__tests__/urlNormalize.test.js`, `Extension/test/example.test.jsx` | No |
| Scoring Engine | pytest | `Scoring Engine/test_score_engine.py` | No |
| Full system | Bash/curl | `.github/workflows/ci.yml` | Yes |
