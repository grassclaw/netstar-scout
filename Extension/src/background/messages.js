import { getCachedOrScan } from "./scan.js";
import { updateIcon } from "./icon.js";
import { updateRecentScans } from "./recentScans.js";
import { maybeShowRiskNotification } from "./notifications.js";

/**
 * Messaging used by popup and other pages.
 */
export function registerMessageListeners() {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "highlightExtension") {
      // Flash the extension icon badge to guide user to click it
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#6366f1" });
      setTimeout(() => {
        chrome.action.setBadgeText({ text: "" });
      }, 3000);
      sendResponse({ success: true });
      return false;
    }

    if (request.action === "scanUrl") {
      (async () => {
        try {
          // Block inputs that don't contain a letter-based TLD (e.g. ".com", ".org").
          // Rejects single words, plain IPs, and strings with no TLD.
          // See Docs/url-sanitization-policy.md.
          if (!/\.[a-z]{2,}/i.test(request.url)) {
            console.log("Invalid URL entered:", request.url);
            sendResponse({
              error: true,
              message:
                "Invalid URL. Please enter a valid website address with a top-level domain (e.g., .com, .org, .net)",
            });
            return;
          }

          const result = await getCachedOrScan(request.url);
          sendResponse(result);

          // Fire-and-forget side-effects so the popup is unblocked immediately
          void (async () => {
            try {
              const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
              if (tabs[0]) {
                updateIcon(tabs[0].id, result.safetyScore);
                updateRecentScans(request.url, result.safetyScore);
                await maybeShowRiskNotification(request.url, result.safetyScore);
              }
            } catch (e) {
              console.error("[NetSTAR] scanUrl side-effects error:", e);
            }
          })();
        } catch (error) {
          console.error("Error in scanUrl:", error);
          sendResponse({ error: true, message: error.message });
        }
      })();

      return true;
    }

    if (request.action === "getCurrentTab") {
      (async () => {
        const t0 = Date.now();
        try {
          const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
          let targetTab = activeTabs[0];

          if (
            !targetTab ||
            !targetTab.url ||
            !/^https?:\/\//i.test(targetTab.url) ||
            targetTab.url.startsWith("chrome-extension://") ||
            targetTab.url.startsWith("chrome://") ||
            targetTab.url.startsWith("edge://") ||
            targetTab.url.startsWith("about:")
          ) {
            const allTabs = await chrome.tabs.query({ currentWindow: true });
            for (const t of allTabs) {
              if (
                t.url &&
                /^https?:\/\//i.test(t.url) &&
                !t.url.startsWith("chrome-extension://") &&
                !t.url.startsWith("chrome://") &&
                !t.url.startsWith("edge://") &&
                !t.url.startsWith("about:")
              ) {
                targetTab = t;
                break;
              }
            }
          }

          let response;
          if (targetTab && targetTab.url) {
            const url = targetTab.url;
            if (!/^https?:\/\//i.test(url)) {
              response = { url, title: targetTab.title, securityData: null };
            } else {
              const result = await getCachedOrScan(url);
              response = {
                url,
                title: targetTab.title,
                securityData: result || null,
              };
            }
          } else {
            response = { url: null, title: null, securityData: null };
          }

          console.log("[NetSTAR][timing] getCurrentTab: done", Date.now() - t0, "ms");
          sendResponse(response);
        } catch (error) {
          console.error("[NetSTAR] getCurrentTab error:", Date.now() - t0, "ms", error);
          sendResponse({ url: null, title: null, securityData: null, error: error.message });
        }
      })();

      return true;
    }

    return false;
  });
}

