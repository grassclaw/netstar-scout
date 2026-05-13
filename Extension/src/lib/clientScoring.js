/**
 * Client-side risk scoring + categorization for NetSTAR Scout.
 *
 * Pure functions. No network, no DOM access. Take a URL + (optional) cached
 * page signals from content-inspect.js + (optional) page metadata, return a
 * SecurityData object shaped to satisfy the popup UI:
 *
 *   { safetyScore, category, indicators: [{id, name, score, status}, ...],
 *     narrative, signalsSummary, source }
 *
 * The seven indicator IDs are fixed by the popup design:
 *   connection, cert, dns, domain, credentials, ip, whois
 *
 * Some of those (dns, ip, whois) are not derivable from page context. They
 * default to a neutral score and are upgraded only when backend enrichment
 * (threat-mcp /scan/lite) returns real values.
 */

const INDICATOR_NAMES = {
  connection: "Connection Security",
  cert: "Certificate Health",
  dns: "DNS Record Health",
  domain: "Domain Reputation",
  credentials: "Credential Safety",
  ip: "IP Reputation",
  whois: "WHOIS Pattern",
};

const NEUTRAL_SCORE = 80;

// Map Schema.org @type and Open Graph og:type to a coarse category label.
// Structural lookups only — no keyword matching against page text.
const SCHEMA_CATEGORY = {
  newsarticle: "News",
  article: "News & Articles",
  blogposting: "Blog",
  videoobject: "Video",
  movie: "Video",
  tvepisode: "Video",
  musicalbum: "Music",
  musicrecording: "Music",
  product: "Shopping",
  offer: "Shopping",
  store: "Shopping",
  recipe: "Food & Recipes",
  jobposting: "Careers",
  course: "Education",
  educationevent: "Education",
  socialmediaposting: "Social",
  discussionforumposting: "Forums",
  realestate: "Real Estate",
  apartment: "Real Estate",
  medicalwebpage: "Health",
  game: "Games",
  videogame: "Games",
  sportsevent: "Sports",
  financialproduct: "Finance",
  bankoraccount: "Finance",
  webapplication: "Web App",
};

const OG_TYPE_CATEGORY = {
  article: "News & Articles",
  "video.movie": "Video",
  "video.tv_show": "Video",
  "video.episode": "Video",
  "video.other": "Video",
  "music.song": "Music",
  "music.album": "Music",
  "music.playlist": "Music",
  "music.radio_station": "Music",
  profile: "Social",
  book: "Books",
};

const TWITTER_CARD_CATEGORY = {
  player: "Video",
  app: "App",
};

/**
 * Derive a category label from page metadata. Returns null when no structured
 * signal is present — we never guess from keywords in body text.
 *
 * @param {{ogType?: string, schemaTypes?: string[], twitterCard?: string, lang?: string}} meta
 * @returns {string|null}
 */
export function categorizeFromMeta(meta) {
  if (!meta) return null;

  const schemaTypes = Array.isArray(meta.schemaTypes) ? meta.schemaTypes : [];
  for (const t of schemaTypes) {
    const cat = SCHEMA_CATEGORY[String(t).toLowerCase()];
    if (cat) return cat;
  }

  if (meta.ogType) {
    const cat = OG_TYPE_CATEGORY[String(meta.ogType).toLowerCase()];
    if (cat) return cat;
  }

  if (meta.twitterCard) {
    const cat = TWITTER_CARD_CATEGORY[String(meta.twitterCard).toLowerCase()];
    if (cat) return cat;
  }

  return null;
}

/**
 * Structural hostname features. No TLD allowlists/blocklists — only structural
 * properties: punycode, IP-as-host, length, suspicious-char ratio.
 *
 * @param {string} hostname
 * @returns {{punycode: boolean, ipHost: boolean, length: number, dashCount: number, digitRatio: number, deepSubdomain: boolean}}
 */
export function hostnameFeatures(hostname) {
  const h = String(hostname || "").toLowerCase();
  const punycode = /(^|\.)xn--/.test(h);
  const ipHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || /^\[?[a-f0-9:]+\]?$/.test(h);
  const length = h.length;
  const dashCount = (h.match(/-/g) || []).length;
  const digits = (h.match(/\d/g) || []).length;
  const digitRatio = length > 0 ? digits / length : 0;
  const labelCount = h.split(".").length;
  const deepSubdomain = labelCount >= 5;
  return { punycode, ipHost, length, dashCount, digitRatio, deepSubdomain };
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function scoreToStatus(score) {
  if (score >= 90) return "excellent";
  if (score >= 75) return "good";
  if (score >= 60) return "moderate";
  return "poor";
}

/**
 * Score the connection indicator from URL + signals.
 * HTTPS=100 baseline, HTTP=30. Mixed-content downgrades.
 */
function scoreConnection(urlInfo, signals, redirectSummary) {
  if (!urlInfo.https) return 30;
  let score = 100;
  // Mixed content: if page is https but data-uri or http resources are linked,
  // shave points. We don't have explicit mixed-content counts; data_uri_links
  // is the closest proxy from current extraction.
  if (signals?.data_uri_links > 0) score -= Math.min(20, signals.data_uri_links * 5);
  // Protocol downgrade in the redirect chain (https -> http) is a serious flag.
  if (redirectSummary?.protocolDowngrade) score -= 30;
  return clamp(score, 0, 100);
}

/**
 * Score the certificate indicator. We can't actually inspect the cert from a
 * content script, but HTTPS being present is a necessary condition. Backend
 * enrichment will override this.
 */
function scoreCert(urlInfo) {
  if (!urlInfo.https) return 25;
  return 88; // "good", not "excellent" — we haven't actually verified the cert
}

/**
 * Score domain indicator from hostname features only. Structural, no TLD
 * allowlists.
 */
function scoreDomain(urlInfo) {
  const f = hostnameFeatures(urlInfo.hostname);
  let score = 95;
  if (f.ipHost) score -= 40; // IP-as-host is unusual for legit sites
  if (f.punycode) score -= 25; // IDN/punycode can hide homoglyphs
  if (f.length > 40) score -= 15;
  if (f.length > 60) score -= 10;
  if (f.dashCount >= 4) score -= 10;
  if (f.digitRatio > 0.4) score -= 10;
  if (f.deepSubdomain) score -= 8;
  return clamp(score, 0, 100);
}

/**
 * Score credentials indicator from form/password signals.
 */
function scoreCredentials(urlInfo, signals) {
  if (!signals) {
    // Without signals we can't say much. Slight penalty if HTTP.
    return urlInfo.https ? NEUTRAL_SCORE : 50;
  }
  let score = 100;
  const hasPwd = signals.password_fields > 0;
  if (hasPwd && !urlInfo.https) score -= 40;
  if (hasPwd && signals.form_action_external) score -= 35;
  if (hasPwd && signals.autocomplete_off) score -= 10;
  if (signals.hidden_fields > 5) score -= 5;
  // Pure no-form pages: nothing to credential-risk against.
  if (!hasPwd && signals.form_count === 0) score = Math.max(score, 92);
  return clamp(score, 0, 100);
}

/**
 * Compute a "page integrity" deduction from behavioral signals — applied to
 * the aggregate score, not to a single indicator (these signals don't map
 * cleanly onto cert/dns/ip/whois).
 */
function pageIntegrityDeduction(signals) {
  if (!signals) return { deduction: 0, flags: [] };
  let d = 0;
  const flags = [];

  // eval() in production JS is uncommon — most sites bundle with esbuild/
  // webpack-prod which avoids it. When present it's a real signal.
  if (signals.eval_calls > 0) {
    d += Math.min(15, signals.eval_calls * 5);
    flags.push(`${signals.eval_calls} eval() call${signals.eval_calls > 1 ? "s" : ""}`);
  }

  // Obfuscation score is noisy: atob + fromCharCode + base64 blobs all
  // appear in legit minified bundles. Only flag when eval ALSO present
  // (compound evidence) — that combo is what actually distinguishes
  // malicious obfuscation from normal minification.
  if (signals.obfuscation_score >= 70 && signals.eval_calls > 0) {
    d += 10;
    flags.push(`obfuscation patterns + eval (score ${signals.obfuscation_score})`);
  }

  // Tracking pixels are typically 1-2 hidden iframes. Three or more starts
  // looking like a kit drop / ad-injection. Linear above that.
  if (signals.hidden_iframes >= 3) {
    d += Math.min(10, (signals.hidden_iframes - 2) * 4);
    flags.push(`${signals.hidden_iframes} hidden iframes`);
  }

  // Invisible characters in body text are a strong phishing signal but
  // single occurrences happen in legit (e.g. ZWNJ in CJK). Threshold at 3.
  if (signals.invisible_chars >= 3) {
    d += Math.min(10, (signals.invisible_chars - 2) * 2);
    flags.push(`${signals.invisible_chars} invisible characters`);
  }

  // RTL overrides in body text are basically always a homograph attack.
  if (signals.rtl_overrides > 0) {
    d += 15;
    flags.push("RTL override character present");
  }

  // The display-text-domain-mismatch heuristic false-positives on news
  // articles that contain phrases like "youtube.com" in headlines while
  // linking elsewhere. Raise threshold + cap deduction.
  if (signals.mismatched_links >= 5) {
    d += 5;
    flags.push(`${signals.mismatched_links} mismatched links`);
  }

  // document.write still used in some ad networks but is uncommon in
  // first-party code. Modest penalty.
  if (signals.document_write > 0) {
    d += Math.min(5, signals.document_write * 2);
    flags.push("document.write() in inline script");
  }

  // High-confidence phishing signal — keep severity.
  if (signals.password_fields > 0 && signals.form_action_external) {
    d += 30;
    flags.push("password form posts to external domain");
  }

  return { deduction: clamp(d, 0, 55), flags };
}

/**
 * Deduction from the redirect chain Scout saw the real user traverse. Long
 * chains, lots of cross-origin hops, and JS-driven redirects are all valid
 * patterns for ad networks and link shorteners, so the penalties are modest.
 * The hard flags (protocol downgrade) are folded into scoreConnection too.
 */
function redirectDeduction(rs) {
  if (!rs || rs.hopCount === 0) return { deduction: 0, flags: [] };
  let d = 0;
  const flags = [];
  // Long chains alone aren't suspicious — ad networks + SSO bounce a lot.
  // Only deduct when the chain is genuinely deep.
  if (rs.hopCount >= 5) {
    d += Math.min(8, (rs.hopCount - 4) * 3);
    flags.push(`${rs.hopCount}-hop redirect chain`);
  }
  if (rs.crossOrigin >= 3) {
    d += 5;
    flags.push(`${rs.crossOrigin} cross-origin redirect hops`);
  }
  if (rs.protocolDowngrade) {
    flags.push("HTTPS-to-HTTP downgrade in redirect chain");
    // deduction already handled in scoreConnection; no double-count here.
  }
  if (rs.clientDriven >= 3) {
    d += 3;
    flags.push(`${rs.clientDriven} JS / meta-refresh redirects`);
  }
  return { deduction: clamp(d, 0, 15), flags };
}

/**
 * Top-level scorer. All inputs optional except url.
 *
 * @param {string} url - The URL being scored.
 * @param {object|null} signals - Cached signals from content-inspect.js.
 * @param {object|null} meta - Cached page metadata.
 * @param {{content?: object|null, redirectSummary?: object|null}} extra
 * @returns {object} SecurityData shape consumed by HomeTab.
 */
export function scoreFromContext(url, signals, meta, extra = {}) {
  const urlInfo = parseUrl(url);
  const redirectSummary = extra.redirectSummary || null;
  const content = extra.content || null;

  const indicators = [
    { id: "connection", name: INDICATOR_NAMES.connection, score: scoreConnection(urlInfo, signals, redirectSummary) },
    { id: "cert",       name: INDICATOR_NAMES.cert,       score: scoreCert(urlInfo) },
    { id: "dns",        name: INDICATOR_NAMES.dns,        score: NEUTRAL_SCORE, pending: true },
    { id: "domain",     name: INDICATOR_NAMES.domain,     score: scoreDomain(urlInfo) },
    { id: "credentials",name: INDICATOR_NAMES.credentials,score: scoreCredentials(urlInfo, signals) },
    { id: "ip",         name: INDICATOR_NAMES.ip,         score: NEUTRAL_SCORE, pending: true },
    { id: "whois",      name: INDICATOR_NAMES.whois,      score: NEUTRAL_SCORE, pending: true },
  ].map((ind) => ({ ...ind, status: scoreToStatus(ind.score) }));

  const integrity = pageIntegrityDeduction(signals);
  const redirect = redirectDeduction(redirectSummary);
  const deduction = clamp(integrity.deduction + redirect.deduction, 0, 80);
  const flags = [...integrity.flags, ...redirect.flags];

  // Aggregate: weighted average of derivable indicators minus page-integrity penalty.
  // Pending indicators (dns/ip/whois) don't dominate the aggregate when no backend.
  const weights = { connection: 1.5, cert: 1.0, domain: 1.5, credentials: 1.5, dns: 0.5, ip: 0.5, whois: 0.5 };
  let weightedSum = 0;
  let weightTotal = 0;
  for (const ind of indicators) {
    const w = weights[ind.id] || 1;
    weightedSum += ind.score * w;
    weightTotal += w;
  }
  let safetyScore = Math.round(weightedSum / weightTotal) - deduction;
  safetyScore = clamp(safetyScore, 0, 100);

  const category = categorizeFromMeta(meta) || (urlInfo.https ? "Unrated" : "Unrated (Insecure)");

  return {
    safetyScore,
    category,
    indicators,
    narrative: flags,
    signalsSummary: signals ? summarizeSignals(signals) : null,
    redirectSummary: redirectSummary
      ? {
          hopCount: redirectSummary.hopCount,
          crossOrigin: redirectSummary.crossOrigin,
          protocolDowngrade: redirectSummary.protocolDowngrade,
          clientDriven: redirectSummary.clientDriven,
        }
      : null,
    contentBytes: content?.text ? content.text.length : 0,
    source: signals ? "client" : "url-only",
    pendingIndicators: ["dns", "ip", "whois"],
    domain: urlInfo.hostname,
    placeholder: false,
    timestamp: Date.now(),
  };
}

function parseUrl(url) {
  try {
    const u = new URL(url.includes("://") ? url : `https://${url}`);
    return {
      https: u.protocol === "https:",
      hostname: u.hostname.replace(/^www\./, "").toLowerCase(),
      protocol: u.protocol,
    };
  } catch {
    return { https: false, hostname: String(url || "").toLowerCase(), protocol: "" };
  }
}

function summarizeSignals(s) {
  return {
    forms: s.form_count || 0,
    passwordFields: s.password_fields || 0,
    inlineScripts: s.inline_scripts || 0,
    hiddenIframes: s.hidden_iframes || 0,
    externalLinks: s.external_links || 0,
    mismatchedLinks: s.mismatched_links || 0,
    cookies: s.cookie_count || 0,
    localStorageKeys: s.localstorage_keys || 0,
    sessionStorageKeys: s.sessionstorage_keys || 0,
    crossOriginHosts: s.perf_cross_origin_hosts || 0,
    failedRequests: s.perf_failed_requests || 0,
  };
}

/**
 * Merge a backend-enriched result into a client-side result. Backend wins for
 * fields it provides; client fills the rest. Used when threat-mcp /scan/lite
 * succeeds asynchronously.
 *
 * @param {object} clientResult - From scoreFromContext().
 * @param {object} backendResult - Lite endpoint payload.
 * @returns {object} Merged SecurityData.
 */
export function mergeBackendEnrichment(clientResult, backendResult) {
  if (!backendResult || backendResult.error) return clientResult;

  const merged = { ...clientResult };
  if (typeof backendResult.safetyScore === "number") merged.safetyScore = backendResult.safetyScore;
  if (backendResult.category) merged.category = backendResult.category;

  if (Array.isArray(backendResult.indicators) && backendResult.indicators.length) {
    const byId = new Map(merged.indicators.map((i) => [i.id, i]));
    for (const b of backendResult.indicators) {
      if (typeof b.score === "number" && byId.has(b.id)) {
        byId.set(b.id, {
          ...byId.get(b.id),
          score: b.score,
          status: scoreToStatus(b.score),
          pending: false,
        });
      }
    }
    merged.indicators = Array.from(byId.values());
  }
  merged.source = "client+backend";
  merged.timestamp = Date.now();
  return merged;
}
