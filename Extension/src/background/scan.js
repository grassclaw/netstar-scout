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

  // Wait for backend categorization so the FIRST popup open shows the real
  // Polaris/Ethos category, not the client-side metadata fallback. Polaris
  // hits in <100ms; Ethos averages ~500ms warm, ~1.5s cold. Budget 4s — the
  // popup is already waiting for ensurePageSignals (600ms) before this, so
  // total worst-case popup latency is ~4.6s. If it times out, return client
  // result and let next open pick up the merge.
  const backendCat = await Promise.race([
    categorize(url, pageCtx.content, metaForBackend),
    new Promise((resolve) => setTimeout(() => resolve(null), 4000)),
  ]);

  const merged = backendCat
    ? {
        ...clientResult,
        category: backendCat.category,
        categoryId: backendCat.categoryId,
        categorySource: backendCat.source,
        categoryConfidence: backendCat.confidence,
        categoryTier: backendCat.tier,
      }
    : clientResult;

  await chrome.storage.local.set({ [cacheKey]: merged });
  return merged;
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

