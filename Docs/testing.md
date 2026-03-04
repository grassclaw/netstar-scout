# Testing Guide

This document describes how to run tests across every layer of NetSTAR Shield and what the CI pipeline covers.

For a detailed, stakeholder-facing list of every individual test case, see [Tests-Summary.md](../Tests-Summary.md). For the project/course testing narrative, see [Project-Testing.md](../Project-Testing.md).

---

## Quick Reference

| Layer | Framework | Command | In CI |
|-------|-----------|---------|-------|
| Server | Jest + Supertest | `cd Server && npm test` | Yes |
| Extension | Jest | `cd Extension && npm test` | No |
| Scoring Engine | pytest | `cd "Scoring Engine" && pytest test_score_engine.py -v` | No |
| Full-system E2E | Bash + curl | Runs automatically in CI | Yes |

---

## Server (Jest)

**Test location:** `Server/__tests__/`

```bash
cd Server && npm test
```

Two test files:

- **`urlSanitize.test.js`** — Unit tests for `normalizeScanTarget()`. Covers valid URL extraction, lowercasing, `www.` stripping, trailing-dot removal, and blocked inputs (empty, localhost, loopback, raw IPs, missing TLD, malformed URLs).
- **`scan.test.js`** — Integration tests for `GET /scan`. Uses Supertest with a mocked `child_process.spawn` (no real Python or external APIs). Asserts correct 400/200/500 response shapes.

For detailed test structure and how mocking works, see [Server/readme.md](../Server/readme.md).

---

## Extension (Jest)

**Test location:** `Extension/__tests__/`

```bash
cd Extension && npm test
```

Two test files:

- **`urlNormalize.test.js`** — Tests for `normalizeScanDomain()` to ensure the browser-side normalization matches the server. Covers hostname extraction, lowercasing, `www.` stripping, empty/null fallbacks, and parity with server behavior.
- **`example.test.jsx`** — Basic smoke test (math assertion and a simple component render).

The Extension tests are not yet part of CI. The normalization tests verify that URLs are cleaned identically on both client and server, per the shared [url-sanitization-policy.md](url-sanitization-policy.md).

---

## Scoring Engine (pytest)

**Test location:** `Scoring Engine/test_score_engine.py`

```bash
cd "Scoring Engine" && pytest test_score_engine.py -v
```

Optional coverage report:

```bash
pytest test_score_engine.py --cov=score_engine --cov-report=html
```

The suite includes 60+ tests and >80% coverage of `score_engine.py`. Test classes cover certificate, DNS, HVAL, mail, method, RDAP scoring, final weighted-score calculation, credential safety, integration-style complete scans, curl subprocess mocking, and edge cases.

For the full test class breakdown, fixtures, and troubleshooting, see [Scoring Engine/TESTING.md](../Scoring%20Engine/TESTING.md).

---

## CI (GitHub Actions)

**Workflow:** [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)

Runs on every push to `main` and every pull request targeting `main`.

### Steps

1. **Setup** — Checkout, Python 3.11, install Scoring Engine dependencies, Node 20, install Server dependencies.
2. **Server unit tests** — `cd Server && npm test`.
3. **Full-system E2E scan** — Starts the Node server with `USE_SCORING_TEST_DATA=1` (so the Python engine uses test data, no external API calls), then runs `curl GET /scan?domain=example.com` and asserts the response is valid JSON with `error !== true` and `safetyScore` as a number.

The E2E step confirms the entire request path works: server receives request, spawns scoring engine subprocess, parses output, and returns a well-formed response.

---

## What Is Not Yet Tested

- Extension popup UI and background service worker behavior (messaging, caching, icon updates).
- Scoring Engine production modules (`scoring_main.py`, `scoring_logic.py`) — the pytest suite targets `score_engine.py`; adding tests for the live modules would strengthen coverage.
- Extension tests are not run in CI.

See [Project-Testing.md](../Project-Testing.md) for discussion on adequacy and plans to optimize.
