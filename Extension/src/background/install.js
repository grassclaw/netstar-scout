import { ICON_STATES } from "./constants.js";

/**
 * Install defaults and icon.
 */
export function registerInstallListener() {
  chrome.runtime.onInstalled.addListener(() => {
    console.log("NetSTAR extension installed");

    const defaultIconPath = (size) => `src/icons/icon-${ICON_STATES.SAFE}-${size}.png`;
    chrome.action.setIcon({
      path: {
        16: defaultIconPath(16),
        48: defaultIconPath(48),
        128: defaultIconPath(128),
      },
    });

    chrome.storage.local.set({
      recentScans: [],
      settings: {
        autoScan: true,
        notifications: true,
      },
    });
  });
}

