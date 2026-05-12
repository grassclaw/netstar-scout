import {
  CACHE_DURATION_MS,
  SIGNALS_CACHE_PREFIX,
  SCAN_API_BASE,
  SCAN_FETCH_TIMEOUT_MS,
} from "./constants.js";
import { normalizeScanDomain } from "./urlNormalize.js";
import { scoreFromContext, mergeBackendEnrichment } from "../lib/clientScoring.js";

/**
 * Cached-or-scan entry point. Returns a SecurityData object shaped for the
 * popup UI. The result is always computed client-side first from the cached
 * page signals (content-inspect.js) + page metadata. If a backend enrichment
 * endpoint is reachable, we kick it off asynchronously and write the merged
 * result back to cache for the next popup open — the current open returns
 * immediately with the client-side result.
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

  const result = await performSecurityScan(url, ctx);
  await chrome.storage.local.set({ [cacheKey]: result });

  // Fire-and-forget backend enrichment. If the lite endpoint is reachable,
  // merge and rewrite cache so the next popup open sees the richer result.
  void enrichInBackground(url, domain, cacheKey, result);

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
 * Attempt threat-mcp /scan/lite enrichment. Currently inert — the endpoint
 * does not exist yet (Launch Readiness §3.2). When it lands, this will start
 * augmenting cert/dns/ip/whois indicators automatically.
 */
async function enrichInBackground(url, domain, cacheKey, clientResult) {
  if (!SCAN_API_BASE) return;
  // Only attempt enrichment when we have a real-looking domain.
  if (!domain || !/\.[a-z]{2,}/i.test(domain)) return;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(`${SCAN_API_BASE}/api/v1/scan/lite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, client_source: "scout" }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return;
    const backend = await resp.json();
    const merged = mergeBackendEnrichment(clientResult, backend);
    await chrome.storage.local.set({ [cacheKey]: merged });
  } catch {
    // Backend unreachable or aborted — client result stands. Silent by design;
    // we don't want demo logs spammed when /scan/lite is offline.
  } finally {
    clearTimeout(timer);
  }
}
