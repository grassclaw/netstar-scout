/**
 * Cloudflare Access service-token auth for threat-mcp calls.
 *
 * The token (Client ID + Secret) is stored in chrome.storage.sync so it
 * roams across the user's browser profile. Settings UI lets the user paste
 * the pair; for the demo build we can also seed via build-time env if needed.
 *
 * Token format from CF Zero Trust dashboard:
 *   CF-Access-Client-Id:     <uuid>.access
 *   CF-Access-Client-Secret: <hex-secret>
 *
 * If either is missing, requests still go out — CF Access will return 403
 * and the caller is expected to handle that gracefully (Scout falls back to
 * client-side scoring).
 */

import { SCAN_API_BASE } from "./constants.js";

const TOKEN_KEYS = ["cfAccessClientId", "cfAccessClientSecret", "scanApiBase"];

/**
 * Read the CF Access service token + API base from chrome.storage.sync.
 * Returns empty strings when unset — caller handles absence.
 */
export async function getAuthConfig() {
  try {
    if (!chrome?.storage?.sync) {
      return { clientId: "", clientSecret: "", apiBase: SCAN_API_BASE };
    }
    const stored = await chrome.storage.sync.get(TOKEN_KEYS);
    return {
      clientId: stored.cfAccessClientId || "",
      clientSecret: stored.cfAccessClientSecret || "",
      apiBase: stored.scanApiBase || SCAN_API_BASE,
    };
  } catch {
    return { clientId: "", clientSecret: "", apiBase: SCAN_API_BASE };
  }
}

/**
 * Wrapper around fetch() that attaches CF Access service-token headers if
 * configured. Returns the Response object — callers decide how to interpret
 * non-2xx status. Times out via AbortController.
 *
 * @param {string} path - Path relative to the API base (e.g. "/api/v1/scout/categorize").
 * @param {RequestInit} init
 * @param {number} timeoutMs
 * @returns {Promise<Response>}
 */
export async function authedFetch(path, init = {}, timeoutMs = 12_000) {
  const { clientId, clientSecret, apiBase } = await getAuthConfig();

  const headers = new Headers(init.headers || {});
  headers.set("Accept", "application/json");
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  if (clientId && clientSecret) {
    headers.set("CF-Access-Client-Id", clientId);
    headers.set("CF-Access-Client-Secret", clientSecret);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${apiBase}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}
