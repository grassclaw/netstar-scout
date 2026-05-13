import { getCachedOrScan } from "./scan.js";
import { updateIcon } from "./icon.js";
import { updateRecentScans } from "./recentScans.js";
import { maybeShowRiskNotification } from "./notifications.js";
import { SIGNALS_CACHE_PREFIX } from "./constants.js";
import { normalizeScanDomain } from "./urlNormalize.js";
import { getRedirectSummary } from "./redirects.js";

/**
 * Ensure live page signals are cached for the given tab before scoring.
 * Content scripts only auto-fire at `document_idle` on fresh page loads, so a
 * popup opened on a pre-existing tab would otherwise hit the URL-only fallback
 * path. This injects content-inspect.js on demand and waits briefly for the
 * pageSignals message to populate the cache. Idempotent: re-injection on a
 * page that already ran the script just produces another cache write.
 */
async function ensurePageSignals(tabId, url) {
  try {
    if (!chrome?.scripting?.executeScript || !tabId) return;
    const domain = normalizeScanDomain(url);
    if (!domain) return;

    const cacheKey = `${SIGNALS_CACHE_PREFIX}${domain}`;
    const existing = await chrome.storage.local.get(cacheKey);
    const cached = existing[cacheKey];
    // Skip injection if we already have fresh-enough signals (< 30s old).
    if (cached && Date.now() - (cached.timestamp || 0) < 30_000) return;

    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content-scripts/content-inspect.js"],
    });

    // Poll briefly for the pageSignals message to land in cache.
    const deadline = Date.now() + 600;
    while (Date.now() < deadline) {
      const fresh = await chrome.storage.local.get(cacheKey);
      const c = fresh[cacheKey];
      if (c && c.timestamp && c.timestamp > (cached?.timestamp || 0)) return;
      await new Promise((r) => setTimeout(r, 60));
    }
  } catch (e) {
    // Injection can fail on chrome:// pages, webstore, pdf viewer, etc.
    // The scorer will fall back to URL-only — no need to surface this.
  }
}

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

    if (request.action === "pageSignals") {
      // Live DOM signals + metadata captured by content-inspect.js.
      // Fire-and-forget cache keyed on the same normalized domain that
      // scan.js will look up by, so the two layers line up.
      //
      // We do NOT invalidate the scan cache here. A page reload re-fires
      // content-inspect; that's a refresh of the underlying signals, not a
      // request for fresh categorization. The user explicitly invokes
      // rescan via the popup rescan button — that path clears both caches.
      const { signals, meta, content, url } = request;
      if ((signals || meta || content) && url) {
        try {
          const domain = normalizeScanDomain(url);
          if (domain) {
            const cacheKey = `${SIGNALS_CACHE_PREFIX}${domain}`;
            chrome.storage.local.set({
              [cacheKey]: { signals, meta, content, url, timestamp: Date.now() },
            });
          }
        } catch (e) {
          console.error("Error caching page signals:", e);
        }
      }
      return false;
    }

    if (request.action === "rescan") {
      // Explicit user-initiated cache bust + fresh scan. Clears both signals
      // and scan results for the supplied URL, then re-runs the scan path.
      (async () => {
        try {
          const url = request.url;
          if (!url) {
            sendResponse({ error: true, message: "url required" });
            return;
          }
          const domain = normalizeScanDomain(url);
          if (domain) {
            const signalsKey = `${SIGNALS_CACHE_PREFIX}${domain}`;
            const scanKey = `scan_${encodeURIComponent(domain)}`;
            await chrome.storage.local.remove([signalsKey, scanKey]);
          }
          // Re-trigger signal extraction + scoring through the standard path.
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tabs[0]?.id) {
            await ensurePageSignals(tabs[0].id, url);
          }
          const result = await getCachedOrScan(url);
          sendResponse(result);
        } catch (e) {
          console.error("Error in rescan:", e);
          sendResponse({ error: true, message: e.message });
        }
      })();
      return true;
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
              // On-demand injection: if this tab was opened before the
              // extension was installed/reloaded, its content script never
              // ran. Inject now so the popup can score from real page signals
              // rather than falling back to URL-only. Some sites (perplexity,
              // etc.) block content scripts via CSP — ensurePageSignals
              // silently no-ops in that case and we proceed without signals.
              await ensurePageSignals(targetTab.id, url);
              const redirectSummary = getRedirectSummary(targetTab.id);
              const result = await getCachedOrScan(url, {
                redirectSummary,
                tabTitle: targetTab.title,
              });
              response = {
                url,
                title: targetTab.title,
                securityData: result || null,
                redirectSummary,
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

