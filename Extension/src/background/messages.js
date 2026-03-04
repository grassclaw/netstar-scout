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
          // ── Manual-scan validation ────────────────────────────────────
          // Block inputs that don't contain a letter-based TLD (e.g.
          // ".com", ".org", ".co.uk"). This rejects:
          //   • Single words with no dot  ("hello")
          //   • Plain IP addresses        ("192.168.1.1", "::1")
          //   • Strings with only numeric TLDs or no TLD at all
          //
          // Plain IPs are intentionally blocked for now; this may change
          // in a future version. See Docs/url-sanitization-policy.md.
          // The server also validates and will return 400 for anything
          // that slips past this check.
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

          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tabs[0]) {
            updateIcon(tabs[0].id, result.safetyScore);
            updateRecentScans(request.url, result.safetyScore);
            await maybeShowRiskNotification(request.url, result.safetyScore);
          }

          sendResponse(result);
        } catch (error) {
          console.error("Error in scanUrl:", error);
          sendResponse({ error: true, message: error.message });
        }
      })();

      // Return true to indicate we will send a response asynchronously
      return true;
    }

    if (request.action === "getCurrentTab") {
      if (request.requestId) {
        (async () => {
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

            chrome.runtime
              .sendMessage({
                action: "getCurrentTabResponse",
                requestId: request.requestId,
                data: response,
              })
              .catch(() => {});
          } catch (error) {
            console.error("Error in getCurrentTab handler:", error);
            chrome.runtime
              .sendMessage({
                action: "getCurrentTabResponse",
                requestId: request.requestId,
                data: { url: null, title: null, securityData: null, error: error.message },
              })
              .catch(() => {});
          }
        })();
        return false;
      } else {
        (async () => {
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

            if (targetTab && targetTab.url) {
              const url = targetTab.url;
              if (!/^https?:\/\//i.test(url)) {
                sendResponse({ url, title: targetTab.title, securityData: null });
                return;
              }
              const result = await getCachedOrScan(url);
              sendResponse({
                url,
                title: targetTab.title,
                securityData: result || null,
              });
            } else {
              sendResponse({ url: null, title: null, securityData: null });
            }
          } catch (error) {
            console.error("Error in getCurrentTab handler:", error);
            sendResponse({ url: null, title: null, securityData: null, error: error.message });
          }
        })();
        return true;
      }
    }

    return false;
  });
}

