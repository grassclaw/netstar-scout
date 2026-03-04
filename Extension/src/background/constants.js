// Shared constants for the background service worker.

// Scan API base — use "http://localhost:3000" for local dev, "http://69.164.202.138:3000" for live
export const SCAN_API_BASE = "http://69.164.202.138:3000";

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

