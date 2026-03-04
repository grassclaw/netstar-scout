import { ICON_STATES, ICON_THRESHOLDS } from "./constants.js";

/**
 * Browser action icon state
 */
export function updateIcon(tabId, safetyScore) {
  const iconState =
    safetyScore >= ICON_THRESHOLDS.SAFE
      ? ICON_STATES.SAFE
      : safetyScore >= ICON_THRESHOLDS.WARNING
        ? ICON_STATES.WARNING
        : ICON_STATES.DANGER;

  const iconPath = (size) => `src/icons/icon-${iconState}-${size}.png`;

  chrome.action.setIcon({
    tabId,
    path: {
      16: iconPath(16),
      48: iconPath(48),
      128: iconPath(128),
    },
  });
}

