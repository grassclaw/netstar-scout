# NetSTAR Shield Extension ↔ Server ↔ Scoring Engine Flow

This document explains how the Chrome extension, Node server, and Python scoring
engine work together, including how the service worker interacts with the UI and
how flavor text is added to the API response.

## Components

- Extension UI (popup React app)
  - Reads scan results from the service worker
  - Renders scores, indicators, and flavor text
- Extension service worker (background script)
  - Resolves the current tab domain
  - Calls the Node server `/scan` endpoint
  - Caches results for reuse
  - Responds to UI requests via `chrome.runtime` messaging
- Node server (Express)
  - Accepts `/scan?domain=...`
  - Spawns the Python scoring engine
  - Parses JSON output
  - Enriches with flavor text
  - Returns a single JSON payload for the UI
- Python scoring engine
  - Fetches scan data
  - Computes raw scores
  - Outputs JSON only (no human-readable logs on stdout)

## High-Level Data Flow

1. Popup UI opens and asks the service worker for current tab + scan data.
2. Service worker resolves the active tab domain.
3. Service worker calls `GET /scan?domain=<domain>` on the Node server.
4. Node server spawns the Python scoring engine process.
5. Python returns JSON with raw scores + metadata.
6. Node server adds flavor text and indicator mapping.
7. Service worker caches the result and returns it to the UI.
8. UI renders the score, indicators, and flavor text.

## Service Worker Interaction

The popup should never call the server directly. The service worker is the single
source of truth for scan requests and caching.

Recommended responsibilities:

- Determine current tab URL/hostname.
- Deduplicate requests per domain (avoid repeated scans).
- Add timeout handling for server requests.
- Store the latest scan in memory and/or `chrome.storage.local`.
- Answer UI requests with `{ url, securityData }`.

Example message flow:

- UI → service worker: `{ action: "getCurrentTab" }`
- Service worker:
  - gets active tab URL
  - calls server if cache is stale
  - returns `{ url, securityData }`

## Suggested Response Schema

The server should return a single object that the UI can render directly.
This keeps UI logic small and keeps copy centralized on the server.

```json
{
  "schemaVersion": 1,
  "domain": "example.com",
  "timestamp": 1736961245000,
  "aggregatedScore": 82.4,
  "scores": {
    "Connection_Security": 88,
    "Certificate_Health": 91,
    "DNS_Record_Health": 72,
    "Domain_Reputation": 78,
    "Credential_Safety": 66
  },
  "indicators": [
    {
      "id": "connection",
      "score": 88,
      "status": "good",
      "message": "Secure HTTPS with modern TLS."
    },
    {
      "id": "cert",
      "score": 91,
      "status": "excellent",
      "message": "Certificate is valid and healthy."
    }
  ]
}
```

## Flavor Text Strategy (Server-Side)

Store copy on the server and attach it to each indicator. This avoids duplicating
copy logic in the extension and allows quick updates without redeploying the UI.

Recommended mapping:

- Normalize each score to a `status` bucket: `excellent | good | moderate | poor`
- Map `(indicator_id, status)` → `message`
- Include `message` in each indicator in the response

Example mapping:

```
connection:
  excellent: "Secure HTTPS with modern TLS."
  good: "HTTPS is enabled with minor improvements available."
  moderate: "HTTPS is present but has notable gaps."
  poor: "Connection security is weak or missing."
```

## Node Server Responsibilities

- Spawn `python3 score_engine.py -t <domain>`
- Parse JSON from stdout
- Handle process errors and invalid JSON
- Build UI-ready response:
  - map raw score keys to indicator IDs
  - attach `status` and `message`
  - include `schemaVersion` and timestamp

## Python Scoring Engine Responsibilities

- Output JSON only on stdout
- Send logs to stderr (or guard behind a `--verbose` flag)
- Return raw scores without any UI copy

## Error Handling and Fallbacks

- Service worker should return an error response if:
  - server is unreachable
  - server returns non-JSON
  - scan times out
- UI should:
  - show an error state if `error: true`
  - use default indicator data if any field is missing

## Caching Guidance

To avoid overloading the server:

- cache by domain in `chrome.storage.local`
- set a TTL (e.g., 15 minutes)
- keep the most recent in memory for quick UI open/close

## Summary

The scoring engine stays focused on score computation, the server owns JSON
formatting + flavor text, and the service worker coordinates requests and caching.
This keeps UI simple and makes updates safe and centralized.
