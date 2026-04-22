import { CACHE_DURATION_MS } from "./constants.js";
import { normalizeScanDomain } from "./urlNormalize.js";

// Placeholder scan layer. Returns a synthesized "safe" result for every URL
// until threat-mcp lands (Launch Readiness §3.1–3.5). Keeps the existing
// getCachedOrScan contract — chrome.storage.local caching still runs so the
// UI behaves realistically. Swap performSecurityScan() for a real fetch when
// the threat-mcp lite endpoint is ready; nothing downstream needs to change.

export async function getCachedOrScan(url) {
  const domain = normalizeScanDomain(url);
  const cacheKey = `scan_${encodeURIComponent(domain || url)}`;
  const data = await chrome.storage.local.get(cacheKey);
  const now = Date.now();

  if (data[cacheKey]) {
    const cached = data[cacheKey];
    if (now - cached.timestamp < CACHE_DURATION_MS) {
      return cached;
    } else {
      await chrome.storage.local.remove(cacheKey);
    }
  }

  const result = await performSecurityScan(url);
  await chrome.storage.local.set({ [cacheKey]: result });
  return result;
}

export async function performSecurityScan(url) {
  const domain = normalizeScanDomain(url) || url;

  return {
    safetyScore: 95,
    category: "GenAI: Chat",
    indicators: [
      { id: "connection",  name: "Connection Security", score: 95, status: "excellent" },
      { id: "cert",        name: "Certificate Health",  score: 95, status: "excellent" },
      { id: "dns",         name: "DNS Record Health",   score: 95, status: "excellent" },
      { id: "domain",      name: "Domain Reputation",   score: 95, status: "excellent" },
      { id: "whois",       name: "WHOIS Pattern",       score: 95, status: "excellent" },
      { id: "ip",          name: "IP Reputation",       score: 95, status: "excellent" },
      { id: "credentials", name: "Credential Safety",   score: 95, status: "excellent" },
    ],
    domain,
    placeholder: true,
    timestamp: Date.now(),
  };
}
