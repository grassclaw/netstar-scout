import { ICON_STATES, ICON_THRESHOLDS } from "./constants.js";

/**
 * Browser action icon state. Wrapped so an icon-resolution error (the icon
 * is non-critical for functionality) doesn't surface as an uncaught promise
 * rejection in the service worker console.
 */
export function updateIcon(tabId, safetyScore) {
  const iconState =
    safetyScore >= ICON_THRESHOLDS.SAFE
      ? ICON_STATES.SAFE
      : safetyScore >= ICON_THRESHOLDS.WARNING
        ? ICON_STATES.WARNING
        : ICON_STATES.DANGER;

  const iconPath = (size) =>
    chrome.runtime.getURL(`icons/icon-${iconState}-${size}.png`);

  chrome.action
    .setIcon({
      tabId,
      path: {
        16: iconPath(16),
        48: iconPath(48),
        128: iconPath(128),
      },
    })
    .catch(() => {
      // Icon resolution can fail transiently during extension reload or on
      // pages where the action API is restricted. Non-fatal.
    });
}

