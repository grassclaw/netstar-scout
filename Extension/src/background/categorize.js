/**
 * Categorization client for threat-mcp /api/v1/scout/categorize.
 *
 * Scout's premise: we're already on the page. Send the content Scout
 * extracted — title, meta, headings, body text sample — and let threat-mcp
 * resolve to a category via Polaris lookup → Ethos fallback. The backend
 * never re-fetches.
 *
 * Failure mode: any error (network, 403 CF Access denial, 5xx) returns null
 * so callers fall back to the client-side metadata category without surfacing
 * the error. Errors logged for development; quiet in production demo flow.
 */

import { authedFetch } from "./auth.js";

/**
 * @typedef {Object} CategorizeResult
 * @property {string} category       Human-readable name ("News", "SaaS", ...).
 * @property {string} categoryId     InCompass-style numeric ID, optional.
 * @property {number} confidence     0..1, optional (only on ethos path).
 * @property {string} source         "polaris" | "ethos" | "fallback".
 * @property {string} tier           Ring-1 tier from ethos, optional.
 * @property {string} modelVersion   Optional model version stamp.
 */

/**
 * @param {string} url
 * @param {object|null} content - {text, headings} captured by content-inspect.
 * @param {object|null} meta    - Structured page metadata.
 * @returns {Promise<CategorizeResult|null>}
 */
export async function categorize(url, content, meta) {
  try {
    const body = {
      url,
      title: meta?.title || "",
      lang: meta?.lang || "",
      text: content?.text || "",
      headings: content?.headings || [],
      meta: meta
        ? {
            og_type: meta.ogType || "",
            og_site_name: meta.ogSiteName || "",
            twitter_card: meta.twitterCard || "",
            description: meta.description || "",
            schema_types: meta.schemaTypes || [],
          }
        : undefined,
    };

    const resp = await authedFetch("/api/v1/scout/categorize", {
      method: "POST",
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      // 403 here usually means CF Access service token is missing or wrong.
      // We don't surface that as a hard error — the popup keeps working
      // with the client-side metadata category until the token is set.
      return null;
    }
    const data = await resp.json();
    if (!data || typeof data.category !== "string") return null;
    return {
      category: data.category,
      categoryId: data.category_id || "",
      confidence: typeof data.confidence === "number" ? data.confidence : 0,
      source: data.source || "unknown",
      tier: data.tier || "",
      modelVersion: data.model_version || "",
    };
  } catch (e) {
    // Network error, abort, etc. Silent — Scout falls back to client side.
    return null;
  }
}
