/**
 * Active-tab tracker.
 *
 * Instead of relying on chrome.tabs.query at popup-open time (which can
 * return surprising results in multi-window setups or when Chrome is
 * loading/unloading backgrounded tabs), this module observes tab/window
 * focus events as they happen and stores the most recently focused
 * scannable tab.
 *
 * Storage: chrome.storage.session — survives service worker restarts
 * within the same browser session, dies on browser quit. Perfect for
 * tracking "what tab were you just on?"
 */

const SESSION_KEY = "lastActiveScannableTab";

export function isScannableUrl(url) {
  if (!url) return false;
  if (!/^https?:\/\//i.test(url)) return false;
  if (url.startsWith("chrome-extension://")) return false;
  if (url.startsWith("chrome://")) return false;
  if (url.startsWith("edge://")) return false;
  if (url.startsWith("about:")) return false;
  return true;
}

async function rememberTab(tab) {
  if (!tab || !isScannableUrl(tab.url)) return;
  try {
    await chrome.storage.session.set({
      [SESSION_KEY]: {
        id: tab.id,
        url: tab.url,
        title: tab.title || "",
        windowId: tab.windowId,
        t: Date.now(),
      },
    });
  } catch {
    // chrome.storage.session unavailable on some early MV3 builds
  }
}

/**
 * @returns {Promise<{id:number,url:string,title:string,windowId:number,t:number}|null>}
 */
export async function getLastActiveScannableTab() {
  try {
    const data = await chrome.storage.session.get(SESSION_KEY);
    return data[SESSION_KEY] || null;
  } catch {
    return null;
  }
}

export function registerActiveTabTracker() {
  // User clicked / keyboard-switched to a different tab.
  chrome.tabs.onActivated.addListener(async ({ tabId, windowId }) => {
    try {
      const tab = await chrome.tabs.get(tabId);
      await rememberTab(tab);
    } catch {
      // Tab may have been closed before we could read it.
    }
  });

  // Tab URL changed (navigation within an active tab).
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (!tab.active) return;
    if (!changeInfo.url && changeInfo.status !== "complete") return;
    await rememberTab(tab);
  });

  // Window focus moved. Capture the active tab in the newly-focused window.
  chrome.windows.onFocusChanged.addListener(async (windowId) => {
    if (windowId === chrome.windows.WINDOW_ID_NONE) return;
    try {
      const tabs = await chrome.tabs.query({ active: true, windowId });
      if (tabs[0]) await rememberTab(tabs[0]);
    } catch {
      // ignore
    }
  });

  // Prime on service-worker startup: capture whatever active tab exists
  // in the most recently focused window.
  (async () => {
    try {
      const tabs = await chrome.tabs.query({
        active: true,
        lastFocusedWindow: true,
      });
      if (tabs[0]) await rememberTab(tabs[0]);
    } catch {
      // ignore
    }
  })();
}
