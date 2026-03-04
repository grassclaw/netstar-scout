# 3. Project Testing (30 points)

Testing is a critical step in system design and ensures that your product meets the requirements of your sponsor.

We have focused on creating a testing suite that ensures the application is behaving as intended. On the extension, we leverage **Vitest** to verify that URL sanitization occurs before URLs are passed to the server. The **Server** uses **Jest** (with Supertest) to test URL normalization, input validation, and the `/scan` API contract. The **Scoring Engine** includes a **pytest** suite for scoring logic and edge cases. Finally, **CI** runs Server unit tests and a **full-system (E2E)** scan to confirm the end-to-end flow works on every push and pull request.

---

## What Testing Has Been Done

### Extension (Vitest)

- **Artifacts:** `Extension/__tests__/urlNormalize.test.js`, `Extension/test/example.test.jsx`, `Extension/vitest.config.js`
- **Purpose:** Ensure URLs are normalized correctly in the browser before being sent to the server. Tests cover hostname extraction from full URLs, lowercasing, stripping `www` and trailing dots, trimming whitespace, and parity with the server’s normalization rules (see `Docs/url-sanitization-policy.md`). Empty, null, and unparseable inputs are handled without throwing.
- **Run:** `cd Extension && npm test`

### Server (Jest)

- **Artifacts:** `Server/__tests__/urlSanitize.test.js`, `Server/__tests__/scan.test.js`
- **urlSanitize.test.js:** Unit tests for `normalizeScanTarget()` — valid URLs return a normalized domain; blocked cases include empty input, localhost, loopback and raw IP addresses, missing TLD, and malformed URLs. Behavior is aligned with `Docs/url-sanitization-policy.md`.
- **scan.test.js:** API tests for `GET /scan`. Asserts 400 for invalid input (no domain, localhost, IPs, no TLD, etc.) with the correct JSON shape; 200 with mocked scoring engine output (safetyScore, aggregatedScore, indicators); 500 when the scoring subprocess fails or returns invalid JSON. Uses Supertest and mocks `child_process.spawn` and `fs.existsSync` so no real Python or external APIs run.
- **Run:** `cd Server && npm test` (this is what CI runs)

### Scoring Engine (pytest)

- **Artifacts:** `Scoring Engine/test_score_engine.py`, `Scoring Engine/TESTING.md`
- **Purpose:** Unit and integration-style tests for the scoring engine: certificate, DNS, HVAL, mail, method, and RDAP scoring; final weighted score calculation; edge cases (missing/malformed data). Subprocess and data-fetch behavior are mocked so tests do not call external APIs. The suite documents 60+ tests and >80% coverage of `score_engine.py`.
- **Run:** `cd "Scoring Engine" && pytest test_score_engine.py -v` (optionally with `--cov=score_engine --cov-report=html`)

### Full-System E2E (CI)

- **Artifact:** `.github/workflows/ci.yml`
- **Purpose:** On every push to `main` and every pull request targeting `main`, CI (1) installs Server and Scoring Engine dependencies, (2) runs Server unit tests, (3) starts the Node server, (4) calls `GET /scan?domain=example.com` with `USE_SCORING_TEST_DATA=1` so the Python engine uses test data only, (5) verifies the response is valid JSON with `error !== true` and `safetyScore` as a number. This confirms the full request path (server → scoring subprocess → response) works in a production-like environment.

---

## Is That Testing Adequate to Fully Verify Functionality?

- **URL handling and security:** Adequately covered. Both Extension and Server test normalization and validation; Server tests also verify that blocked inputs never reach the scoring engine and that error responses have the expected shape.
- **Scan API contract:** Adequately covered. Server tests assert success and failure responses (400/500/200), and CI asserts the E2E response shape.
- **Scoring logic:** The Scoring Engine pytest suite gives strong coverage of `score_engine.py`. The production path uses `scoring_main.py` and `scoring_logic.py`; adding tests that target those modules would make verification of the live scoring path more complete.
- **Extension UI and background behavior:** Currently only URL normalization and an example component are tested. Additional tests for popup/options UI, background scan flow, and messaging would strengthen coverage.

---

## Summarize Your Test Results / Reference Test Artifacts

| Layer            | Tool   | Test Artifacts                                      | CI |
|-----------------|--------|-----------------------------------------------------|----|
| Extension       | Vitest | `Extension/__tests__/urlNormalize.test.js`, `Extension/test/example.test.jsx` | No |
| Server          | Jest   | `Server/__tests__/urlSanitize.test.js`, `Server/__tests__/scan.test.js`      | Yes |
| Scoring Engine  | pytest | `Scoring Engine/test_score_engine.py`, `Scoring Engine/TESTING.md`            | No |
| Full system     | Bash/curl | `.github/workflows/ci.yml` (step “Run full-system scan (E2E)”)            | Yes |

To reproduce results locally:

- **Server:** `cd Server && npm test`
- **Extension:** `cd Extension && npm test`
- **Scoring Engine:** `cd "Scoring Engine" && pytest test_score_engine.py -v`
- **E2E (manual):** Start server with `USE_SCORING_TEST_DATA=1`, then `curl -s "http://localhost:3000/scan?domain=example.com"` and inspect JSON for `safetyScore` and `error`.

CI run history and logs are the primary artifact for “test results” in the pipeline; they are available in the repository’s GitHub Actions tab for the workflow named **CI**.

---

## Does Your Project Meet Your Requirements? If Not, What Is Your Plan to Optimize?

[ *Fill in your sponsor or project requirements here (e.g., “Block malicious/localhost URLs,” “Return a numeric safety score,” “Support extension and API usage”).* ]

- Where requirements are **met:** Point to the tests above (e.g., URL blocking and scan API behavior are validated by Server tests and E2E).
- Where requirements are **not fully met:** Describe the gap and your plan (e.g., “Add pytest tests for `scoring_logic.py` and run Scoring Engine tests in CI,” “Add Extension tests to CI,” “Add UI tests for the popup”).

---

## Do Preliminary Test Results Indicate That the Project Outcome Will Be Successful?

Yes, for the behaviors that are tested:

- Server unit tests and the E2E scan in CI pass when the codebase is healthy, so the core flow (request → validation → scoring subprocess → JSON response) is verified.
- Extension and Server URL normalization tests ensure consistent, safe handling of user input before it reaches the backend.
- Scoring Engine tests give confidence in score computation and edge-case handling for the engine under test.

Extending tests to the production scoring path and to the Extension (CI + more UI/background coverage) would further increase confidence that the final product will behave correctly under all required scenarios.

---

## Have You Done a Preliminary Validation with Your Sponsor to Ensure the Final Product Will Meet Their Needs?

[ *Describe any demos, walkthroughs, or feedback sessions with your sponsor. Include: what was shown (e.g., extension flow, scan API, score display), what was validated (e.g., “URL blocking,” “score interpretation”), and any agreed follow-ups or changes. If not yet done, state that and outline the plan (e.g., “Schedule a demo of the scan flow and score UI; confirm acceptance criteria for ‘safe’ vs ‘unsafe’ domains.”).* ]
