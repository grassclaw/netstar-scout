/**
 * Per-tab redirect chain capture.
 *
 * Scout's advantage over the pipeline scraper is that it sees the chain a real
 * user's browser actually walked through — cookies, geo, A/B tests, JS-driven
 * navigation, meta refresh. The pipeline tracker (project_redirect_chain_architecture)
 * sees server-side redirects from a headless vantage; Scout sees user-session
 * redirects. They're complementary.
 *
 * Captures HTTP redirects via chrome.webRequest.onBeforeRedirect (status codes,
 * exact hops) and JS / meta-refresh redirects via chrome.webNavigation
 * onBeforeNavigate -> onCommitted (transitionType signals client-driven nav).
 */

const chains = new Map(); // tabId -> Array<RedirectHop>

const MAX_HOPS_PER_TAB = 40; // pathological loops cap
const MAX_TAB_RETENTION_MS = 30 * 60 * 1000;

/**
 * @typedef {Object} RedirectHop
 * @property {string} from
 * @property {string} to
 * @property {number} statusCode      0 for client-driven (JS / meta-refresh).
 * @property {"server"|"client"} kind
 * @property {number} t               Date.now() at observation.
 */

function pushHop(tabId, hop) {
  if (tabId == null || tabId < 0) return;
  let chain = chains.get(tabId);
  if (!chain) {
    chain = [];
    chains.set(tabId, chain);
  }
  // De-dupe: webRequest.onBeforeRedirect and webNavigation.onCommitted can both
  // fire for the same hop. Treat same from->to within 1.5s as a duplicate.
  const last = chain[chain.length - 1];
  if (last && last.from === hop.from && last.to === hop.to && hop.t - last.t < 1500) {
    return;
  }
  chain.push(hop);
  if (chain.length > MAX_HOPS_PER_TAB) chain.shift();
}

function resetTab(tabId) {
  if (tabId == null || tabId < 0) return;
  chains.set(tabId, []);
}

function purgeStale() {
  const cutoff = Date.now() - MAX_TAB_RETENTION_MS;
  for (const [tabId, chain] of chains.entries()) {
    if (chain.length === 0 || chain[chain.length - 1].t < cutoff) {
      chains.delete(tabId);
    }
  }
}

export function registerRedirectTracker() {
  if (!chrome.webRequest || !chrome.webNavigation) return;

  // Server-side HTTP redirects: 301/302/303/307/308.
  chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
      if (details.type !== "main_frame") return;
      pushHop(details.tabId, {
        from: details.url,
        to: details.redirectUrl,
        statusCode: details.statusCode || 0,
        kind: "server",
        t: Date.now(),
      });
    },
    { urls: ["<all_urls>"] }
  );

  // Client-side navigations (JS, meta refresh, link click). For the chain
  // we only count navigations that occur within the same tab and have a
  // qualifying transition reason.
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return; // main frame only
    const qualifiers = details.transitionQualifiers || [];
    const type = details.transitionType || "";
    // "client_redirect" covers meta-refresh + JS location.href changes that
    // Chrome classifies as a redirect (not a user-initiated link).
    if (!qualifiers.includes("client_redirect") && type !== "client_redirect") {
      return;
    }
    const chain = chains.get(details.tabId);
    const last = chain && chain[chain.length - 1];
    const from = last ? last.to : "";
    if (!from || from === details.url) return;
    pushHop(details.tabId, {
      from,
      to: details.url,
      statusCode: 0,
      kind: "client",
      t: details.timeStamp || Date.now(),
    });
  });

  // Reset on a fresh user-initiated navigation (typed URL, bookmark, etc).
  // This keeps each "trip" independent rather than accumulating forever.
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    // If parentFrameId is -1 it's the top-level frame. Only reset when this
    // is the start of a fresh navigation chain, not an in-flight redirect
    // hop. We detect "fresh" by checking that the most recent chain entry's
    // 'to' does not equal this navigation's URL.
    const chain = chains.get(details.tabId);
    const last = chain && chain[chain.length - 1];
    if (!last) {
      resetTab(details.tabId);
      return;
    }
    if (last.to !== details.url) {
      // Different starting URL — user navigated somewhere new. Reset.
      resetTab(details.tabId);
    }
  });

  chrome.tabs.onRemoved.addListener((tabId) => {
    chains.delete(tabId);
  });

  // Periodic GC. Service workers idle out, but while alive this trims stale
  // chains. On wake-up purgeStale runs anyway via getRedirectSummary().
  setInterval(purgeStale, 5 * 60 * 1000);
}

/**
 * Return a summary of the current chain for a tab. The full chain is also
 * included so the popup can render hop-by-hop if desired.
 *
 * @param {number} tabId
 * @returns {{hops: RedirectHop[], hopCount: number, crossOrigin: number, protocolDowngrade: boolean, clientDriven: number} | null}
 */
export function getRedirectSummary(tabId) {
  purgeStale();
  const chain = chains.get(tabId);
  if (!chain || chain.length === 0) {
    return { hops: [], hopCount: 0, crossOrigin: 0, protocolDowngrade: false, clientDriven: 0 };
  }
  let crossOrigin = 0;
  let protocolDowngrade = false;
  let clientDriven = 0;
  for (const hop of chain) {
    try {
      const fromU = new URL(hop.from);
      const toU = new URL(hop.to);
      if (fromU.hostname.replace(/^www\./, "") !== toU.hostname.replace(/^www\./, "")) {
        crossOrigin++;
      }
      if (fromU.protocol === "https:" && toU.protocol === "http:") {
        protocolDowngrade = true;
      }
    } catch {
      // ignore malformed
    }
    if (hop.kind === "client") clientDriven++;
  }
  return {
    hops: chain.slice(),
    hopCount: chain.length,
    crossOrigin,
    protocolDowngrade,
    clientDriven,
  };
}
