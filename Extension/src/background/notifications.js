import { ALERT_THRESHOLD, ICON_THRESHOLDS } from "./constants.js";

/**
 * Notifications gating and helpers
 *
 * Follows the Settings soft toggle + Chrome permission model:
 *  - Soft toggle key: notificationsEnabledSoft (boolean)
 *  - Chrome optional permission: "notifications"
 * Only notify when both are true.
 */

/** Read the soft toggle the popup controls. */
function readSoftToggle() {
  return new Promise((resolve) => {
    chrome.storage.local.get("notificationsEnabledSoft", (res) => {
      resolve(Boolean(res && res.notificationsEnabledSoft));
    });
  });
}

/** Check Chrome permission for notifications. */
function hasNotificationsPermission() {
  return new Promise((resolve) => {
    if (!chrome || !chrome.permissions) return resolve(false);
    chrome.permissions.contains({ permissions: ["notifications"] }, (has) =>
      resolve(Boolean(has))
    );
  });
}

/** True only if soft toggle and Chrome permission are both enabled. */
async function canNotifyNow() {
  const [soft, perm] = await Promise.all([readSoftToggle(), hasNotificationsPermission()]);
  return soft && perm;
}

/** Create a native notification if allowed by canNotifyNow. */
export async function maybeShowRiskNotification(url, safetyScore) {
  if (safetyScore >= ALERT_THRESHOLD) return; // only warn for risky scores
  if (!(await canNotifyNow())) return;
  if (!(chrome && chrome.notifications)) return;

  const iconUrl = chrome.runtime.getURL("src/icons/icon-danger-128.png");
  chrome.notifications.create(
    `risky-site-${Date.now()}`,
    {
      type: "basic",
      iconUrl,
      title: "Risky site detected",
      message: `This page scored ${safetyScore}/100\nURL: ${url}`,
      priority: 2,
    },
    () => {
      if (chrome.runtime && chrome.runtime.lastError) {
        console.warn("Notification error:", chrome.runtime.lastError.message);
      }
    }
  );
}

/** Show in-page alert overlay via content script for risky sites. */
export async function maybeShowInPageAlert(tabId, url, safetyScore) {
  // Only show alert for scores below 75 (warning or danger)
  if (safetyScore >= ICON_THRESHOLDS.SAFE) return;

  // Only show on HTTP/HTTPS pages
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

  // Send alert message to content script (it's auto-injected via manifest)
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: "showAlert",
      safetyScore,
      url,
    });
  } catch (error) {
    // Content script not ready or page doesn't support it - silently fail
    console.log("[NetSTAR] Could not show alert:", error.message);
  }
}

