// Shared constants for the background service worker.

// Threat-MCP API base. Used by scan.js to call /api/v1/scout/categorize for
// category resolution (Polaris lookup → Ethos fallback). Auth: CF Access
// service token (CF-Access-Client-Id + CF-Access-Client-Secret) stored in
// chrome.storage.sync — see background/auth.js. If no token is configured,
// the request still runs but CF Access returns 403 and Scout falls back to
// the client-side metadata categorization. Override per-build via
// chrome.storage.sync.set({scanApiBase: "..."}) — useful for staging hosts.
export const SCAN_API_BASE = "https://scan.netstarlabs.com";

export const ICON_THRESHOLDS = {
  SAFE: 75,
  WARNING: 60,
};

export const ICON_STATES = {
  SAFE: "safe",
  WARNING: "warning",
  DANGER: "danger",
};

// Cache TTL for scan results
export const CACHE_DURATION_MS = 1000 * 5 * 60; // 5 minutes

// Score threshold to trigger a warning notification
export const ALERT_THRESHOLD = 60;

// Max time to wait for the scan API before aborting the fetch
export const SCAN_FETCH_TIMEOUT_MS = 10_000; // 10 seconds

// Cache key prefix for live page signals captured by content-inspect.js
export const SIGNALS_CACHE_PREFIX = "signals_";

