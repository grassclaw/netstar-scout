import { ICON_THRESHOLDS } from "./constants.js";

/**
 * Recent scans list
 */
export function updateRecentScans(url, safetyScore) {
  const safeStatus =
    safetyScore >= ICON_THRESHOLDS.SAFE
      ? "safe"
      : safetyScore >= ICON_THRESHOLDS.WARNING
        ? "warning"
        : "danger";

  chrome.storage.local.get("recentScans", (data) => {
    let recent = data.recentScans || [];

    recent = recent.filter((entry) => entry.url !== url);

    const newEntry = {
      url,
      safe: safeStatus,
      timestamp: Date.now(),
    };
    recent.unshift(newEntry);

    if (recent.length > 3) {
      recent = recent.slice(0, 3);
    }

    chrome.storage.local.set({ recentScans: recent });
  });
}

