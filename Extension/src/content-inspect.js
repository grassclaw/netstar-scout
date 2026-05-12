/**
 * Content script for live DOM signal extraction.
 * Runs once at document_idle, extracts page security signals,
 * and sends them to the background service worker.
 *
 * Separate from content.js (alert overlay) to keep concerns clean.
 */

(function () {
  "use strict";

  // Only run on http/https pages
  if (!/^https?:/.test(location.protocol)) return;

  /**
   * Extracts security-relevant signals from the live DOM.
   * Lightweight: uses querySelectorAll and TreeWalker, never serializes the DOM.
   * @returns {Object} InspectSignals-compatible object
   */
  function extractPageSignals() {
    const pageDomain = location.hostname.replace(/^www\./, "").toLowerCase();

    const signals = {
      invisible_chars: 0,
      rtl_overrides: 0,
      homoglyph_score: 0,
      unicode_details: [],
      form_count: 0,
      password_fields: 0,
      hidden_fields: 0,
      form_action_external: false,
      autocomplete_off: false,
      inline_scripts: 0,
      eval_calls: 0,
      base64_blobs: 0,
      document_write: 0,
      obfuscation_score: 0,
      hidden_iframes: 0,
      offscreen_elements: 0,
      zero_size_elements: 0,
      mismatched_links: 0,
      external_links: 0,
      data_uri_links: 0,
      cookie_count: 0,
      cookie_bytes: 0,
      localstorage_keys: 0,
      sessionstorage_keys: 0,
      perf_failed_requests: 0,
      perf_slow_requests: 0,
      perf_cross_origin_hosts: 0,
      mode: "live",
    };

    // --- Unicode analysis via TreeWalker over text nodes ---
    try {
      const walker = document.createTreeWalker(
        document.body || document.documentElement,
        NodeFilter.SHOW_TEXT,
        null
      );
      // Invisible char ranges: U+200B-U+200F, U+FEFF
      // RTL overrides: U+202A-U+202E
      // Cyrillic range for homoglyph detection (basic)
      const INVISIBLE_RE = /[\u200B-\u200F\uFEFF]/g;
      const RTL_RE = /[\u202A-\u202E]/g;
      const CYRILLIC_RE = /[\u0400-\u04FF]/g;

      let node;
      let textNodesChecked = 0;
      while ((node = walker.nextNode()) && textNodesChecked < 5000) {
        textNodesChecked++;
        const text = node.textContent;
        if (!text || text.length < 2) continue;

        const invisibles = text.match(INVISIBLE_RE);
        if (invisibles) {
          signals.invisible_chars += invisibles.length;
          if (signals.unicode_details.length < 10) {
            signals.unicode_details.push(
              `${invisibles.length} invisible char(s) in text node`
            );
          }
        }

        const rtls = text.match(RTL_RE);
        if (rtls) signals.rtl_overrides += rtls.length;

        const cyrillics = text.match(CYRILLIC_RE);
        if (cyrillics) signals.homoglyph_score += cyrillics.length * 5;
      }
      if (signals.homoglyph_score > 100) signals.homoglyph_score = 100;
    } catch (e) {
      // Silently ignore walker errors
    }

    // --- Form analysis ---
    try {
      const forms = document.querySelectorAll("form");
      signals.form_count = forms.length;
      forms.forEach((form) => {
        const action = form.getAttribute("action") || "";
        if (action) {
          const actionDomain = extractDomain(action);
          if (actionDomain && !sameDomain(actionDomain, pageDomain)) {
            signals.form_action_external = true;
          }
        }
        if (
          form.getAttribute("autocomplete") &&
          form.getAttribute("autocomplete").toLowerCase() === "off"
        ) {
          signals.autocomplete_off = true;
        }
      });

      signals.password_fields = document.querySelectorAll(
        'input[type="password"]'
      ).length;
      signals.hidden_fields = document.querySelectorAll(
        'input[type="hidden"]'
      ).length;

      // Check password fields for autocomplete=off
      if (signals.password_fields > 0) {
        document
          .querySelectorAll('input[type="password"]')
          .forEach((input) => {
            if (
              input.getAttribute("autocomplete") &&
              input.getAttribute("autocomplete").toLowerCase() === "off"
            ) {
              signals.autocomplete_off = true;
            }
          });
      }
    } catch (e) {
      // Silently ignore
    }

    // --- Script analysis ---
    try {
      const scripts = document.querySelectorAll("script:not([src])");
      signals.inline_scripts = scripts.length;

      const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;

      scripts.forEach((script) => {
        const content = script.textContent || "";
        if (!content) return;

        // Count suspicious patterns
        const evalMatches = content.match(/\beval\s*\(/g);
        if (evalMatches) signals.eval_calls += evalMatches.length;

        const docWriteMatches = content.match(/\bdocument\.write\s*\(/g);
        if (docWriteMatches)
          signals.document_write += docWriteMatches.length;

        const base64Matches = content.match(BASE64_RE);
        if (base64Matches) signals.base64_blobs += base64Matches.length;

        // Obfuscation heuristics
        const hasAtob = /\batob\s*\(/.test(content);
        const hasFromCharCode = /String\.fromCharCode/.test(content);

        let obfScore = 0;
        if (signals.eval_calls > 0) obfScore += 30;
        if (hasAtob) obfScore += 20;
        if (hasFromCharCode) obfScore += 25;
        if (signals.base64_blobs > 2) obfScore += 25;
        if (obfScore > signals.obfuscation_score)
          signals.obfuscation_score = Math.min(obfScore, 100);
      });
    } catch (e) {
      // Silently ignore
    }

    // --- Iframe analysis ---
    try {
      const iframes = document.querySelectorAll("iframe");
      iframes.forEach((iframe) => {
        const style = (iframe.getAttribute("style") || "").toLowerCase();
        const w = iframe.getAttribute("width");
        const h = iframe.getAttribute("height");
        const rect = iframe.getBoundingClientRect();

        if (
          w === "0" ||
          h === "0" ||
          style.includes("display:none") ||
          style.includes("display: none") ||
          style.includes("visibility:hidden") ||
          style.includes("visibility: hidden") ||
          (rect.width === 0 && rect.height === 0)
        ) {
          signals.hidden_iframes++;
        }

        if (rect.width === 0 || rect.height === 0) {
          signals.zero_size_elements++;
        }
      });
    } catch (e) {
      // Silently ignore
    }

    // --- Link analysis ---
    try {
      const links = document.querySelectorAll("a[href]");
      links.forEach((link) => {
        const href = link.getAttribute("href") || "";

        // Data URI links
        if (href.toLowerCase().startsWith("data:")) {
          signals.data_uri_links++;
          return;
        }

        const hrefDomain = extractDomain(href);
        if (!hrefDomain) return;

        // External links
        if (!sameDomain(hrefDomain, pageDomain)) {
          signals.external_links++;

          // Check for display text that looks like a different domain
          const displayText = (link.textContent || "").trim();
          const displayDomain = extractDomainFromText(displayText);
          if (
            displayDomain &&
            displayDomain !== hrefDomain &&
            !sameDomain(displayDomain, hrefDomain)
          ) {
            signals.mismatched_links++;
          }
        }
      });
    } catch (e) {
      // Silently ignore
    }

    // --- Off-screen / zero-size elements ---
    try {
      const allElements = document.querySelectorAll(
        "div[style], span[style], p[style]"
      );
      allElements.forEach((el) => {
        const style = (el.getAttribute("style") || "").toLowerCase();
        if (
          style.includes("position:absolute") ||
          style.includes("position: absolute")
        ) {
          if (
            style.match(/left\s*:\s*-\d/) ||
            style.match(/top\s*:\s*-\d/)
          ) {
            signals.offscreen_elements++;
          }
        }
      });
    } catch (e) {
      // Silently ignore
    }

    // --- Cookie / storage shape ---
    try {
      const shape = extractStorageShape();
      signals.cookie_count = shape.cookieCount;
      signals.cookie_bytes = shape.cookieBytes;
      signals.localstorage_keys = shape.localStorageKeys;
      signals.sessionstorage_keys = shape.sessionStorageKeys;
    } catch (e) {
      // localStorage access can throw on sandboxed iframes / blocked origins
    }

    // --- Performance anomalies ---
    try {
      const perf = extractPerfAnomalies();
      signals.perf_failed_requests = perf.failedRequests;
      signals.perf_slow_requests = perf.slowRequests;
      signals.perf_cross_origin_hosts = perf.crossOriginHosts;
    } catch (e) {
      // performance.getEntriesByType isn't available in all contexts
    }

    return signals;
  }

  /**
   * Returns counts only — no values, no keys. We do not exfiltrate user data.
   */
  function extractStorageShape() {
    let cookieCount = 0;
    let cookieBytes = 0;
    try {
      const raw = document.cookie || "";
      cookieBytes = raw.length;
      if (raw) cookieCount = raw.split(/;\s*/).filter(Boolean).length;
    } catch (e) {
      // ignore
    }
    let localStorageKeys = 0;
    let sessionStorageKeys = 0;
    try {
      localStorageKeys = window.localStorage ? window.localStorage.length : 0;
    } catch (e) {
      // SecurityError on cross-origin / sandboxed
    }
    try {
      sessionStorageKeys = window.sessionStorage ? window.sessionStorage.length : 0;
    } catch (e) {
      // ignore
    }
    return { cookieCount, cookieBytes, localStorageKeys, sessionStorageKeys };
  }

  /**
   * Summarize fetch/resource activity via the Performance API. Lightweight —
   * the browser already collected this data; we just count it.
   */
  function extractPerfAnomalies() {
    let failedRequests = 0;
    let slowRequests = 0;
    const hosts = new Set();
    try {
      const pageHost = location.hostname.replace(/^www\./, "");
      const entries = performance.getEntriesByType("resource") || [];
      for (const e of entries) {
        // Failure heuristic: completed entry but transferSize=0 and
        // duration=0 for a cross-origin URL == likely network failure / blocked.
        // (Won't catch CORS-blocked responses cleanly, but flags many failures.)
        if (
          e.transferSize === 0 &&
          e.duration === 0 &&
          !e.name.startsWith("data:") &&
          !e.name.startsWith("blob:")
        ) {
          failedRequests++;
        }
        if (e.duration > 5000) slowRequests++;
        try {
          const u = new URL(e.name);
          const h = u.hostname.replace(/^www\./, "");
          if (h && h !== pageHost) hosts.add(h);
        } catch {
          // skip non-URL entries (e.g., blob:)
        }
      }
    } catch (e) {
      // ignore
    }
    return {
      failedRequests,
      slowRequests,
      crossOriginHosts: hosts.size,
    };
  }

  /**
   * Capture body text up to a byte cap + heading list. This is what the
   * backend categorizer (Polaris miss path) will consume. innerText not
   * textContent so we get visible text only, no hidden CSS-display:none stuff.
   */
  function extractPageContent() {
    const cap = 8 * 1024;
    let text = "";
    try {
      const body = document.body;
      if (body) {
        // innerText is slow on huge pages — slice via the underlying string.
        const raw = (body.innerText || "").replace(/\s+/g, " ").trim();
        text = raw.length > cap ? raw.slice(0, cap) : raw;
      }
    } catch (e) {
      // ignore
    }
    const headings = [];
    try {
      const nodes = document.querySelectorAll("h1, h2, h3");
      for (let i = 0; i < nodes.length && headings.length < 20; i++) {
        const t = (nodes[i].textContent || "").trim();
        if (t && t.length <= 200) headings.push(t);
      }
    } catch (e) {
      // ignore
    }
    return { text, headings };
  }

  /**
   * Extract domain from a URL string
   */
  function extractDomain(rawURL) {
    if (
      !rawURL ||
      rawURL.startsWith("#") ||
      rawURL.startsWith("javascript:")
    )
      return "";
    try {
      // Handle protocol-relative
      if (rawURL.startsWith("//")) rawURL = "https:" + rawURL;
      // Handle relative URLs
      if (!rawURL.includes("://")) return "";
      const u = new URL(rawURL);
      return u.hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return "";
    }
  }

  /**
   * Try to extract a domain from display text (e.g. "Click here to visit google.com")
   */
  function extractDomainFromText(text) {
    if (!text) return "";
    const match = text.match(
      /\b([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/i
    );
    if (match) {
      return match[0].toLowerCase().replace(/^www\./, "");
    }
    return "";
  }

  /**
   * Check if two domains are the same or subdomain-related
   */
  function sameDomain(a, b) {
    a = a.replace(/^www\./, "").toLowerCase();
    b = b.replace(/^www\./, "").toLowerCase();
    if (a === b) return true;
    if (a.endsWith("." + b) || b.endsWith("." + a)) return true;
    return false;
  }

  /**
   * Extract structural page metadata for client-side categorization.
   * Reads og:* + twitter:* meta tags and any JSON-LD @type values. We do not
   * read body keywords — only structured metadata authors declared.
   */
  function extractPageMeta() {
    const meta = {
      title: (document.title || "").slice(0, 200),
      lang: document.documentElement.getAttribute("lang") || "",
      ogType: "",
      ogSiteName: "",
      twitterCard: "",
      description: "",
      schemaTypes: [],
    };

    try {
      const og = document.querySelector('meta[property="og:type"]');
      if (og) meta.ogType = (og.getAttribute("content") || "").trim();
      const ogSite = document.querySelector('meta[property="og:site_name"]');
      if (ogSite) meta.ogSiteName = (ogSite.getAttribute("content") || "").trim().slice(0, 100);
      const tw = document.querySelector('meta[name="twitter:card"]');
      if (tw) meta.twitterCard = (tw.getAttribute("content") || "").trim();
      const desc = document.querySelector('meta[name="description"]');
      if (desc) meta.description = (desc.getAttribute("content") || "").trim().slice(0, 300);
    } catch (e) {
      // ignore
    }

    try {
      const lds = document.querySelectorAll('script[type="application/ld+json"]');
      const types = new Set();
      lds.forEach((node, idx) => {
        if (idx > 8) return; // cap parsing cost
        const txt = node.textContent || "";
        if (!txt || txt.length > 100_000) return;
        let parsed;
        try {
          parsed = JSON.parse(txt);
        } catch {
          return;
        }
        collectTypes(parsed, types);
      });
      meta.schemaTypes = Array.from(types).slice(0, 12);
    } catch (e) {
      // ignore
    }

    return meta;
  }

  function collectTypes(node, out, depth = 0) {
    if (!node || depth > 4) return;
    if (Array.isArray(node)) {
      node.forEach((n) => collectTypes(n, out, depth + 1));
      return;
    }
    if (typeof node !== "object") return;
    const t = node["@type"];
    if (typeof t === "string") out.add(t);
    else if (Array.isArray(t)) t.forEach((x) => typeof x === "string" && out.add(x));
    if (node["@graph"]) collectTypes(node["@graph"], out, depth + 1);
  }

  // --- Run extraction and send to background ---
  try {
    const signals = extractPageSignals();
    const meta = extractPageMeta();
    const content = extractPageContent();
    chrome.runtime.sendMessage({
      action: "pageSignals",
      signals: signals,
      meta: meta,
      content: content,
      url: location.href,
    });
  } catch (e) {
    // Extension context may have been invalidated; silently fail
  }
})();
