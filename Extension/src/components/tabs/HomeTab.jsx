import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Lock,
  GlobeLock,
  KeyRound,
  Network,
  CheckCircle2,
  AlertCircle,
  ZoomIn,
  ScrollText,
  FileUser,
  NotebookText,
  RefreshCw,
} from "lucide-react";
import { getStatusFromScore, getStatusMessage, getDetailedStatusMessage } from "@/lib/securityUtils";
import { getColorClasses } from "@/lib/themeUtils";
import { DEFAULT_INDICATOR_DATA } from "@/lib/constants";


/**
 * Mapping of indicator IDs to their corresponding icon components from lucide-react
 * @type {Object<string, React.ComponentType>}
 * @constant
 * @memberof module:Front End
 */
const INDICATOR_ICONS = {
  cert: ScrollText,
  connection: Lock,
  domain: GlobeLock,
  credentials: KeyRound,
  ip: Network,
  dns: NotebookText,
  whois: FileUser,
};

/**
 * localStorage key used to persist the expanded/collapsed state of the "What We Checked" section
 * @type {string}
 * @constant
 * @memberof module:Front End
 */
const INDICATORS_OPEN_KEY = "indicatorsOpen";

/**
 * HomeTab component - Main tab displaying security score and indicators for the current website
 * 
 * @component
 * @memberof module:Front End
 * @param {Object} props - Component props
 * @param {string} props.mode - Current theme mode: "light" or "dark"
 * @param {Function} props.onNavigate - Callback function to navigate to other tabs/pages
 * @param {Function} props.onNavigate.details - Navigate to details tab with indicator data
 * @param {boolean|undefined} props.forceShowIndicators - Force indicators to be shown (used by tour/guided experiences). 
 *   When provided, overrides user's saved preference
 * @returns {JSX.Element} The rendered HomeTab component
 * 
 * @example
 * ```jsx
 * <HomeTab 
 *   mode="dark" 
 *   onNavigate={(tab, data) => setActiveTab(tab)} 
 *   forceShowIndicators={true} 
 * />
 * ```
 */
function categorySourceLabel(src) {
  switch (src) {
    case "polaris": return "via Polaris";
    case "ethos":   return "via Ethos";
    case "llm":     return "via AI Engine";
    case "pending": return "resolving…";
    case "fallback":return "from page";
    default:        return "";
  }
}

function categorySourceTooltip(src) {
  switch (src) {
    case "polaris": return "Category resolved from NetSTAR's Polaris classification table";
    case "ethos":   return "Category predicted by Ethos (NetSTAR ML model)";
    case "llm":     return "Category determined live by NetSTAR's AI Engine on this page's content";
    case "pending": return "NetSTAR is categorizing this page — usually takes a few seconds";
    case "fallback":return "Category derived from page metadata — backend unavailable";
    default:        return "";
  }
}

function hostnameFromUrl(urlString) {
  try {
    const u = new URL(urlString.includes("://") ? urlString : `https://${urlString}`);
    return u.hostname;
  } catch {
    return "this site";
  }
}

export function HomeTab({ mode, onNavigate, forceShowIndicators, overrideUrl, overrideSecurityData }) {
  /** Current website URL hostname. Initialize from override when landing after a manual scan. */
  const [currentUrl, setCurrentUrl] = useState(() => (overrideUrl ? hostnameFromUrl(overrideUrl) : ""));

  /** Security safety score (0-100). Initialize from override when landing after a manual scan so the score shows immediately. */
  const [safetyScore, setSafetyScore] = useState(() =>
    overrideSecurityData?.safetyScore !== undefined ? overrideSecurityData.safetyScore : 0
  );

  /** Complete security scan data including indicators and metadata. Initialize from override so we don't show loading after a manual scan. */
  const [securityData, setSecurityData] = useState(() => overrideSecurityData ?? null);
  const [scanState, setScanState] = useState("loading"); // "loading" | "success" | "error"
  const [scanError, setScanError] = useState(null);

  /**
   * State for whether the "What We Checked" indicators section is expanded
   * Initialized from localStorage to persist user's preference across sessions
   * @type {boolean}
   */
  const [showIndicators, setShowIndicators] = useState(() => {
    try {
      if (typeof window === "undefined") return false;
      const saved = window.localStorage.getItem(INDICATORS_OPEN_KEY);
      return saved ? saved === "1" : false;
    } catch {
      return false;
    }
  });

  /**
   * Computed indicator visibility state - allows external control (tour) to override user preference
   * @type {boolean}
   * @memberof module:Front End~HomeTab
   */
  const computedShowIndicators =
    forceShowIndicators ?? showIndicators;

  /**
   * Effect to persist user's indicator toggle preference to localStorage
   * Runs whenever showIndicators changes, but does not persist forced overrides
   * @memberof module:Front End~HomeTab
   */
  useEffect(() => {
    try {
      if (typeof window !== "undefined") {
        window.localStorage.setItem(
          INDICATORS_OPEN_KEY,
          showIndicators ? "1" : "0"
        );
      }
    } catch {
      /* ignore write errors */
    }
  }, [showIndicators]);

  /**
   * Effect to fetch current tab URL and security data from background script
   * Runs once on component mount to populate initial security information
   * @memberof module:Front End~HomeTab
   */
  // Listen for backend category resolution. Background fires
  // "categoryResolved" once the Polaris/Ethos/LLM call finishes (could be
  // ~18s after popup open for LLM cold). Update the category in place so
  // the threat score doesn't have to re-render.
  useEffect(() => {
    if (typeof chrome === "undefined" || !chrome.runtime?.onMessage) return;
    const listener = (msg) => {
      if (msg?.action === "categoryResolved" && msg.securityData) {
        setSecurityData((prev) => {
          // Only swap if this resolution is for the URL we're currently showing
          if (!prev || prev.error) return prev;
          if (prev.domain && msg.securityData.domain && prev.domain !== msg.securityData.domain) {
            return prev;
          }
          return { ...prev, ...msg.securityData };
        });
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  useEffect(() => {
    let isMounted = true;

    const run = async () => {
      setSecurityData(null); // forces loading UI every time a fetch starts
      setScanState("loading");
      setScanError(null);

      // If the popup is showing a manual scan target, prefer that over "current tab".
      if (overrideUrl) {
        setCurrentUrl(hostnameFromUrl(overrideUrl));

        if (overrideSecurityData?.safetyScore !== undefined) {
          setSafetyScore(overrideSecurityData.safetyScore);
          setSecurityData(overrideSecurityData);
          setScanState("success")
          return;
        }

        // Fallback: ask background for cached/scan result for the override URL.
        if (typeof chrome !== "undefined" && chrome.runtime) {
          try {
            const result = await new Promise((resolve) => {
              chrome.runtime.sendMessage({ action: "scanUrl", url: overrideUrl }, (resp) => resolve(resp));
            });

            if (!isMounted) return;
            if (result && !result.error && result.safetyScore !== undefined) {
              setSafetyScore(result.safetyScore);
              setSecurityData(result);
              setScanError(null);
              setScanState("success");
            } else {
              const msg = result?.message || result?.error || "Scan failed";
              setSecurityData({ error: true, message: msg });
              setScanError(msg);
              setScanState("error");
            }
          } catch (error) {
            console.error("Error getting manual scan data:", error);
            const msg = error?.message || "Scan failed";

            setSecurityData({ error: true, message: msg });
            setScanError(msg);
            setScanState("error");
          }
        }

        return;
      }

      // Default behavior: Get current tab URL and security data.
      if (typeof chrome !== "undefined" && chrome.runtime) {
        try {
          const t0 = Date.now();
          const TIMEOUT_MS = 12_000;
          const response = await new Promise((resolve) => {
            const timer = setTimeout(() => resolve(null), TIMEOUT_MS);

            chrome.runtime.sendMessage({ action: "getCurrentTab" }, (resp) => {
              clearTimeout(timer);
              if (chrome.runtime.lastError) {
                console.error("[NetSTAR] getCurrentTab error:", chrome.runtime.lastError.message);
                resolve(null);
                return;
              }
              resolve(resp ?? null);
            });
          });

          if (!isMounted || !response) return;

          if (response.error) {
            const msg = typeof response.error === "string"
              ? response.error
              : (response.message || "Scan failed");
            setSecurityData({ error: true, message: msg });
            setScanError(msg);
            setScanState("error");
            return;
          }

          if (response.url) {
            const elapsedMs = Date.now() - t0;
            console.log("[NetSTAR][timing] popup: getCurrentTab end-to-end", elapsedMs, "ms");

            setCurrentUrl(hostnameFromUrl(response.url));

            // Background can return { error: true, message: ... } for non-
            // scannable tabs (chrome://, settings, new tab). Render that
            // as a friendly empty state instead of the loading spinner.
            if (response.securityData?.error) {
              const msg = response.securityData.message || "This page can't be scanned";
              setSecurityData({ error: true, message: msg });
              setScanError(msg);
              setScanState("error");
              return;
            }

            if (response.securityData?.safetyScore !== undefined) {
              setSafetyScore(response.securityData.safetyScore);
              setSecurityData(response.securityData);
            }
            setScanError(null);
            setScanState("success");
            return;
          }

          // No scannable active tab (browser is on chrome://, settings, etc.).
          // Show a friendly prompt instead of an error spinner.
          const msg = "Open a webpage tab to scan it";
          setSecurityData({ error: true, message: msg });
          setScanError(msg);
          setScanState("error");
        } catch (error) {
          const msg = error?.message || "Scan failed";
          setSecurityData({ error: true, message: msg });
          setScanError(msg);
          setScanState("error");
        }
      } else {
        setCurrentUrl("example.com");
      }
    };

    run();

    return () => {
      isMounted = false;
    };
  }, [overrideUrl, overrideSecurityData]);

  // Build indicators with icons + score (merge live score if provided), then sort by score asc
  // Convert indicators array to object for easier lookup by id
  const indicatorsLookup = securityData?.indicators?.reduce((acc, indicator) => {
    acc[indicator.id] = indicator;
    return acc;
  }, {}) || {};

  const indicators = DEFAULT_INDICATOR_DATA
    .map((data) => {
      const liveIndicator = indicatorsLookup[data.id];
      return {
        ...data,
        score: liveIndicator?.score ?? data.score ?? 0,
        status: liveIndicator?.status ?? getStatusFromScore(data.score ?? 0),
        icon: INDICATOR_ICONS[data.id],
      };
    })
    .sort((a, b) => a.score - b.score);

  /**
   * Handler function to toggle the visibility of the "What We Checked" indicators section
   * Prevents toggling when a forced override is active (e.g., during a tour)
   * @memberof module:Front End~HomeTab
   * @function handleToggleIndicators
   */
  const handleToggleIndicators = () => {
    // If a forced value is provided (tour/demo), don't toggle the persisted state
    if (forceShowIndicators != null) return;
    setShowIndicators((openState) => !openState);
  };

  const [isRescanning, setIsRescanning] = useState(false);

  /**
   * Force a fresh scan of the current URL — clears cached signals + scan
   * result, re-injects content-inspect, re-runs scoring + backend categorize.
   */
  const handleRescan = async () => {
    if (isRescanning) return;
    const target = overrideUrl || (currentUrl && `https://${currentUrl}`);
    if (!target || typeof chrome === "undefined" || !chrome.runtime) return;

    setIsRescanning(true);
    setSecurityData(null);
    setScanState("loading");
    setScanError(null);

    try {
      const result = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: "rescan", url: target }, (resp) => resolve(resp));
      });
      if (result && !result.error && result.safetyScore !== undefined) {
        setSafetyScore(result.safetyScore);
        setSecurityData(result);
        setScanState("success");
      } else {
        const msg = result?.message || result?.error || "Rescan failed";
        setSecurityData({ error: true, message: msg });
        setScanError(msg);
        setScanState("error");
      }
    } catch (e) {
      const msg = e?.message || "Rescan failed";
      setSecurityData({ error: true, message: msg });
      setScanError(msg);
      setScanState("error");
    } finally {
      setIsRescanning(false);
    }
  };

  const isLoading = securityData == null;
  const isError = securityData?.error === true;

  const SafetyScoreStatus = safetyScore === 0 ? "unknown" : getStatusFromScore(safetyScore);
  const SafetyScoreColor = getColorClasses(SafetyScoreStatus);

  // Header text
  const headerTitle = isLoading
    ? "Loading URL Score"
    : isError
    ? "Scan failed"
    : getDetailedStatusMessage(String(SafetyScoreStatus).toLowerCase());

  const headerLine = isLoading
    ? "Scanning"
    : isError
    ? (securityData.message || "We couldn't scan this site.")
    : "Scanned";

  // Live affordance — visible only when we actually consumed page signals,
  // so the user can tell scoring used THIS page, not a generic lookup.
  const summary = securityData?.signalsSummary;
  const redirect = securityData?.redirectSummary;
  const liveAffordance = summary
    ? [
        `${summary.forms} form${summary.forms === 1 ? "" : "s"}`,
        `${summary.inlineScripts} script${summary.inlineScripts === 1 ? "" : "s"}`,
        `${summary.crossOriginHosts} 3rd-party host${summary.crossOriginHosts === 1 ? "" : "s"}`,
      ].join(" · ")
    : null;
  const redirectAffordance = redirect && redirect.hopCount > 0
    ? `${redirect.hopCount} redirect hop${redirect.hopCount === 1 ? "" : "s"}${
        redirect.crossOrigin > 0 ? `, ${redirect.crossOrigin} cross-origin` : ""
      }${redirect.protocolDowngrade ? " · ⚠ HTTPS→HTTP" : ""}`
    : null;


  return (
    <div className="p-6">
      {/* Header with friendly greeting */}
      <div className="text-center mb-6">
        <h2
          className={`font-bold text-xl mb-1 ${
            mode === "dark" ? "text-white" : "text-slate-900"
          }`}
        >
          {headerTitle}
        </h2>
        <p
          className={`text-sm ${
            mode === "dark" ? "text-slate-200" : "text-brand-900"
          }`}
        >
          {headerLine} <span className="break-all">{currentUrl}</span>
          {!isLoading && !isError && currentUrl && (
            <button
              type="button"
              onClick={handleRescan}
              disabled={isRescanning}
              title="Rescan this page"
              className={`ml-2 inline-flex items-center justify-center rounded-full p-1 align-middle transition ${
                mode === "dark"
                  ? "text-brand-300 hover:bg-brand-900/40"
                  : "text-brand-600 hover:bg-brand-100"
              } ${isRescanning ? "opacity-60 cursor-wait" : "cursor-pointer"}`}
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isRescanning ? "animate-spin" : ""}`} />
            </button>
          )}
        </p>
        {liveAffordance && (
          <p
            className={`text-[11px] mt-0.5 ${
              mode === "dark" ? "text-slate-400" : "text-brand-500"
            }`}
            title="Computed live from this page"
          >
            Live: {liveAffordance}
          </p>
        )}
        {redirectAffordance && (
          <p
            className={`text-[11px] ${
              redirect?.protocolDowngrade
                ? "text-red-500"
                : mode === "dark" ? "text-slate-400" : "text-brand-500"
            }`}
            title="Redirect chain observed by Scout in this tab"
          >
            Path: {redirectAffordance}
          </p>
        )}
      </div>

      {/* Friendly Score Display */}
      <div
        id="security-score"
        className={`rounded-2xl p-6 mb-6 ${
          mode === "dark"
            ? "bg-gradient-to-br from-brand-900/50 to-brand-accent-500/30"
            : "bg-gradient-to-br from-brand-100 to-brand-accent-400/20"
        }`}
      >
        <div className="text-center">
          <div className="inline-flex items-baseline gap-2 mb-2">
            <div className="inline-flex items-baseline gap-2 mb-2">

            {scanState === "loading" ? (
              <span
                className={`inline-flex items-center justify-center w-[4.25rem] h-[4.25rem] ${
                  mode === "dark" ? "text-slate-100" : "text-brand-600"
                }`}
                aria-label="Loading safety score"
                role="status"
              >
                <span className="w-10 h-10 border-4 border-current border-t-transparent rounded-full animate-spin" />
              </span>
            ) : scanState === "error" ? (
              <div className="text-sm">
                {scanError}
              </div>
            ) : (
              <span
                className={`text-6xl font-bold bg-gradient-to-r ${SafetyScoreColor.gradient} bg-clip-text text-transparent`}
              >
                {Number.isFinite(safetyScore) ? safetyScore : "—"}
              </span>
            )}

            </div>

            <span
              className={`text-2xl font-medium ${
                mode === "dark" ? "text-slate-100" : "text-brand-600"
              }`}
            >
              /100
            </span>
          </div>
          <div
            className={`text-sm font-medium ${
              mode === "dark" ? "text-slate-100" : "text-brand-700"
            }`}
          >
            Safety Score
          </div>
          {securityData?.category && (
            <div
              className={`text-xs mt-1 ${
                mode === "dark" ? "text-slate-400" : "text-brand-500"
              }`}
            >
              Category: {securityData.category}
              {securityData.categorySecondary && (
                <span
                  className={mode === "dark" ? "text-slate-500" : "text-brand-400"}
                  title="Secondary category suggestion"
                >
                  {" / "}{securityData.categorySecondary}
                </span>
              )}
              {securityData.categorySource && (
                <span
                  className={`ml-1 text-[10px] uppercase tracking-wide ${
                    mode === "dark" ? "text-brand-400" : "text-brand-600"
                  }`}
                  title={categorySourceTooltip(securityData.categorySource)}
                >
                  · {categorySourceLabel(securityData.categorySource)}
                </span>
              )}
            </div>
          )}
          <div className="flex items-center justify-center gap-1 mt-3">
            {[...Array(5)].map((_, i) => {
              const segmentFill = Math.min(
                Math.max((safetyScore - i * 20) / 20, 0),
                1
              );

              return (
                <div
                  key={i}
                  className={`relative w-8 h-1.5 rounded-full overflow-hidden ${
                    mode === "dark" ? "bg-slate-700" : "bg-brand-200"
                  }`}
                >
                  <div
                    className={`absolute inset-y-0 left-0 transition-all ${
                      segmentFill > 0 ? `bg-gradient-to-r ${SafetyScoreColor.gradient}` : ""
                    }`}
                    style={{ width: `${segmentFill * 100}%` }}
                  />
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Friendly Indicators */}
      <div id="security-indicators" className="space-y-3">
        <button
          onClick={handleToggleIndicators}
          className={`text-sm font-semibold mb-3 flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity ${
            mode === "dark" ? "text-white" : "text-brand-800"
          }`}
        >
          <ZoomIn className="h-4 w-4" />
          What We Checked
          <span className="text-xs ml-auto">
            {computedShowIndicators ? "▼" : "▶"}
          </span>
        </button>

        {computedShowIndicators &&
          indicators.map((indicator) => {
            const Icon = indicator.icon;
            const status = getStatusFromScore(indicator.score);
            const colors = getColorClasses(status);

            return (
              <button
                key={indicator.id}
                onClick={() => onNavigate("details", { ...indicator, status })}
                className={`w-full flex items-center gap-3 p-4 rounded-xl transition-all hover:scale-[1.02] ${
                  mode === "dark"
                    ? "bg-slate-800/50 hover:bg-slate-800"
                    : "bg-white hover:shadow-md"
                }`}
              >
                <div className={`p-2 rounded-lg ${colors.bg}`}>
                  <Icon className={`h-4 w-4 ${colors.text}`} />
                </div>
                <div className="flex-1 text-left">
                  <div
                    className={`text-sm font-medium ${
                      mode === "dark" ? "text-white" : "text-slate-900"
                    }`}
                  >
                    {indicator.name}
                  </div>
                  <div
                    className={`text-xs ${
                      mode === "dark" ? "text-slate-300" : "text-slate-600"
                    }`}
                  >
                    {getStatusMessage(status)}
                  </div>
                </div>
                {status === "excellent" || status === "good" ? (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                ) : status === "moderate" ? (
                  <AlertCircle className="h-5 w-5 text-amber-500" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-red-500" />
                )}
              </button>
            );
          })}
      </div>
    </div>
  );
}
