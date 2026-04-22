// Shared constants for the background service worker.

// Scan API base. Currently UNUSED — scan.js runs in placeholder mode and does
// not fetch. Value kept here for when we swap performSecurityScan() back to a
// real fetch against threat-mcp (`https://scan.wildcatdashboard.com`) or a
// local dev server (`http://localhost:3000`). Capstone Linode was 69.164.202.138:3000.
export const SCAN_API_BASE = "http://localhost:3000";

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

