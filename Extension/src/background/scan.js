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
  const result = scoreFromContext(url, pageCtx.signals, pageCtx.meta, {
    content: pageCtx.content,
    redirectSummary: ctx.redirectSummary || null,
  });
  await chrome.storage.local.set({ [cacheKey]: result });

  // Backend categorization runs in parallel — does not block this return.
  // When the response lands we merge into cache; the next popup open picks
  // up the upgraded category + source badge.
  void categorizeInBackground(url, pageCtx, cacheKey, result);

  return result;
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

/**
 * Async backend categorization. On success, merges {category, categoryId,
 * categorySource, confidence, tier} into the cached scan result and writes
 * back so the next popup open displays it. Failure modes (no token, network
 * error, CF Access 403) leave the client-side result untouched — silent.
 */
async function categorizeInBackground(url, pageCtx, cacheKey, clientResult) {
  // Require real-looking domain. IPs / extension URLs skipped.
  if (!url || !/\.[a-z]{2,}/i.test(url)) return;

  const cat = await categorize(url, pageCtx.content, pageCtx.meta);
  if (!cat) return;

  const merged = {
    ...clientResult,
    category: cat.category,
    categoryId: cat.categoryId,
    categorySource: cat.source,
    categoryConfidence: cat.confidence,
    categoryTier: cat.tier,
  };
  await chrome.storage.local.set({ [cacheKey]: merged });
}
