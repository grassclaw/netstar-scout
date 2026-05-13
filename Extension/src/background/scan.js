import {
  CACHE_DURATION_MS,
  SIGNALS_CACHE_PREFIX,
} from "./constants.js";
import { normalizeScanDomain } from "./urlNormalize.js";
import { scoreFromContext } from "../lib/clientScoring.js";
import { categorize } from "./categorize.js";

/**
 * Cached-or-scan entry point. Returns a SecurityData object shaped for the
 * popup UI. The result is always computed client-side first from the cached
 * page signals (content-inspect.js) + page metadata so the popup never blocks
 * on backend latency. In parallel we kick off backend categorization
 * (threat-mcp /api/v1/scout/categorize → Polaris lookup, Ethos fallback) and
 * merge the result into cache for the next popup open. When the user reopens
 * the popup, the merged result is what they see.
 */
export async function getCachedOrScan(url, ctx = {}) {
  const domain = normalizeScanDomain(url);
  const cacheKey = `scan_${encodeURIComponent(domain || url)}`;
  const data = await chrome.storage.local.get(cacheKey);
  const now = Date.now();

  if (data[cacheKey]) {
    const cached = data[cacheKey];
    if (now - cached.timestamp < CACHE_DURATION_MS) {
      return cached;
    }
    await chrome.storage.local.remove(cacheKey);
  }

  const pageCtx = await readCachedPageContext(domain);
  const clientResult = scoreFromContext(url, pageCtx.signals, pageCtx.meta, {
    content: pageCtx.content,
    redirectSummary: ctx.redirectSummary || null,
  });

  // Fall back to the tab title when content-inspect didn't run (CSP-strict
  // sites like perplexity, chatgpt, banks). Ethos can still classify
  // reasonably from a title alone.
  const metaForBackend = pageCtx.meta || (ctx.tabTitle ? { title: ctx.tabTitle } : null);

  // Mark category as "in flight" so the popup shows a placeholder. The
  // threat score doesn't wait — it's computed locally and returned now.
  const initialResult = {
    ...clientResult,
    category: "Resolving…",
    categorySource: "pending",
  };
  await chrome.storage.local.set({ [cacheKey]: initialResult });

  // Backend categorization runs in the background. When it completes, the
  // merged result is written to cache + a runtime message is broadcast so
  // the popup can swap the category in place without a full re-fetch.
  // Latencies:
  //   Polaris hit  → <100ms
  //   Ethos        → ~500ms warm, ~1.5s cold
  //   LLM (gpt-5-mini, 2-stage pipeline) → 8-18s
  void resolveCategoryAsync(url, pageCtx.content, metaForBackend, cacheKey, clientResult);

  return initialResult;
}

async function resolveCategoryAsync(url, content, meta, cacheKey, clientResult) {
  try {
    const cat = await categorize(url, content, meta);
    const merged = cat
      ? {
          ...clientResult,
          category: cat.category,
          categoryId: cat.categoryId,
          categorySecondary: cat.categorySecondary,
          categorySource: cat.source,
          categoryConfidence: cat.confidence,
          categoryTier: cat.tier,
        }
      : clientResult; // backend failed/empty → keep client-side category

    await chrome.storage.local.set({ [cacheKey]: merged });

    // Notify any open popup that the category has resolved. Popup listens
    // via chrome.runtime.onMessage and updates state in place.
    try {
      chrome.runtime.sendMessage({
        action: "categoryResolved",
        url,
        securityData: merged,
      });
    } catch {
      // No popup listening — that's fine, cache is the source of truth.
    }
  } catch (e) {
    // Defensive: never let async resolution throw unhandled.
    console.error("[NetSTAR] resolveCategoryAsync failed:", e);
  }
}

export async function performSecurityScan(url, ctx = {}) {
  const domain = normalizeScanDomain(url) || url;
  const { signals, meta, content } = await readCachedPageContext(domain);
  return scoreFromContext(url, signals, meta, {
    content,
    redirectSummary: ctx.redirectSummary || null,
  });
}

async function readCachedPageContext(domain) {
  if (!domain) return { signals: null, meta: null, content: null };
  try {
    const key = `${SIGNALS_CACHE_PREFIX}${domain}`;
    const data = await chrome.storage.local.get(key);
    const cached = data[key];
    if (!cached) return { signals: null, meta: null, content: null };
    // Signals live for as long as the page exists in the tab; we cap freshness
    // at 30 min so stale captures don't haunt later visits.
    if (Date.now() - (cached.timestamp || 0) > 30 * 60 * 1000) {
      return { signals: null, meta: null, content: null };
    }
    return {
      signals: cached.signals || null,
      meta: cached.meta || null,
      content: cached.content || null,
    };
  } catch {
    return { signals: null, meta: null, content: null };
  }
}

