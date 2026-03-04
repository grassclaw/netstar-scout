import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Search, Shield, Sparkles, AlertCircle, X } from "lucide-react"

/**
 * ScanTab component - Allows users to manually scan a website for security analysis
 * 
 * @component
 * @memberof module:Front End
 * @param {Object} props - Component props
 * @param {string} props.mode - Current theme mode: "light" or "dark"
 * @param {Function} props.onScanComplete - Callback function called when a scan completes successfully
 * @param {string} props.onScanComplete.url - The URL that was scanned
 * @returns {JSX.Element} The rendered ScanTab component
 * 
 * @example
 * ```jsx
 * <ScanTab 
 *   mode="dark" 
 *   onScanComplete={(url) => {
 *     setActiveTab("home");
 *     console.log("Scanned:", url);
 *   }}
 * />
 * ```
 */
export function ScanTab({ mode, onScanComplete }) {
  /** URL input value for the scan */
  const [scanUrl, setScanUrl] = useState("")
  
  /** Whether a scan is currently in progress */
  const [isScanning, setIsScanning] = useState(false)
  
  /** Array of recently scanned sites from Chrome storage */
  const [recentScans, setRecentScans] = useState([]);
  
  /** Error message to display if scan fails */
  const [errorMessage, setErrorMessage] = useState(null);

  /**
   * Effect to load recent scans from Chrome storage and listen for updates
   * Updates the recent scans list when storage changes
   * @memberof module:Front End~ScanTab
   */
  useEffect(() => {
    chrome.storage.local.get("recentScans", (data) => {
      if (data.recentScans) {
        setRecentScans(data.recentScans);
      }
    });

    const handleStorageChange = (changes, area) => {
      if (area === "local" && changes.recentScans) {
        setRecentScans(changes.recentScans.newValue || []);
      }
    };

    chrome.storage.onChanged.addListener(handleStorageChange);

    return () => {
      chrome.storage.onChanged.removeListener(handleStorageChange);
    };
  }, []);
  
  /**
   * Handler function to initiate a security scan for the entered URL
   * Sends a message to the background script to perform the scan
   * Handles error responses and navigates on successful scan
   * @memberof module:Front End~ScanTab
   * @function handleScan
   */
  const handleScan = () => {
    if (!scanUrl || isScanning) return
    setIsScanning(true)
    setErrorMessage(null) // Clear any previous error

    chrome.runtime.sendMessage(
      { action: "scanUrl", url: scanUrl },
      (result) => {
        setIsScanning(false);

        // Check if there's an error response
        if (result && result.error) {
          setErrorMessage(result.message || "Invalid URL. Please enter a valid website address.");
          return; // Don't navigate away, stay on scan tab
        }

        // Only navigate to home if scan was successful
        if (onScanComplete && result && !result.error) {
          // Pass both the URL and the scan results so Home can display the manual scan.
          onScanComplete(scanUrl, result);
        }
      }
    );
  };

  /**
   * Handler function for keyboard events on the URL input
   * Triggers scan when Enter key is pressed
   * @memberof module:Front End~ScanTab
   * @function handleKeyDown
   * @param {KeyboardEvent} e - Keyboard event object
   */
  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      handleScan()
    }
  }

  return (
    <div className="p-6">
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-brand-400 to-brand-accent-400 mb-3">
          <Search className="h-8 w-8 text-white" />
        </div>
        <h2 className={`font-bold text-xl mb-1 ${mode === "dark" ? "text-white" : "text-slate-900"}`}>
          Let's Check a Website
        </h2>
        <p className={`text-sm ${mode === "dark" ? "text-slate-200" : "text-brand-600"}`}>
          We'll help you stay safe online
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label
            className={`text-sm font-medium mb-2 block ${mode === "dark" ? "text-white" : "text-brand-800"}`}
          >
            Website address
          </label>
          <Input
            type="text"
            placeholder="example.com"
            value={scanUrl}
            onChange={(e) => {
              setScanUrl(e.target.value)
              setErrorMessage(null) // Clear error when user types
            }}
            onKeyDown={handleKeyDown}
            className={`rounded-xl ${mode === "dark" ? "bg-slate-800 border-slate-700 text-white" : "border-brand-200 text-slate-900"}`}
          />
          <p className={`text-xs mt-2 ${mode === "dark" ? "text-slate-300" : "text-slate-600"}`}>
            Tip: You can paste any URL or IP address
          </p>
        </div>

        {/* Error Warning Message */}
        {errorMessage && (
          <div
            className={`p-4 rounded-xl border-2 ${
              mode === "dark"
                ? "bg-amber-900/20 border-amber-500/50"
                : "bg-amber-50 border-amber-300"
            }`}
          >
            <div className="flex items-start gap-3">
              <AlertCircle className={`h-5 w-5 mt-0.5 flex-shrink-0 ${
                mode === "dark" ? "text-amber-400" : "text-amber-600"
              }`} />
              <div className="flex-1">
                <p className={`text-sm font-medium ${
                  mode === "dark" ? "text-amber-300" : "text-amber-800"
                }`}>
                  Invalid URL
                </p>
                <p className={`text-xs mt-1 ${
                  mode === "dark" ? "text-amber-200" : "text-amber-700"
                }`}>
                  {errorMessage}
                </p>
              </div>
              <button
                onClick={() => setErrorMessage(null)}
                className={`flex-shrink-0 p-1 rounded-full hover:bg-opacity-20 ${
                  mode === "dark"
                    ? "text-amber-300 hover:bg-amber-500"
                    : "text-amber-600 hover:bg-amber-200"
                }`}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {!isScanning ? (
          <Button
            className="w-full bg-gradient-to-r from-brand-500 to-brand-accent-500 hover:from-brand-600 hover:to-brand-accent-500 text-white rounded-xl"
            onClick={handleScan}
            disabled={!scanUrl}
          >
            <Shield className="h-4 w-4 mr-2" />
            Check This Site
          </Button>
        ) : (
          <div
            className={`p-8 rounded-2xl ${mode === "dark" ? "bg-gradient-to-br from-brand-900/30 to-brand-accent-500/20" : "bg-gradient-to-br from-brand-100 to-brand-accent-400/20"}`}
          >
            <div className="flex flex-col items-center gap-4">
              <div className="relative w-20 h-20">
                <div className="absolute inset-0 bg-gradient-to-r from-brand-500 to-brand-accent-500 rounded-full opacity-20 animate-ping"></div>
                <div className="absolute inset-0 bg-gradient-to-r from-brand-500 to-brand-accent-500 rounded-full opacity-75 animate-pulse"></div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <Sparkles className="h-8 w-8 text-white" />
                </div>
              </div>
              <div className="text-center">
                <div className={`font-medium ${mode === "dark" ? "text-white" : "text-slate-900"}`}>
                  Checking security...
                </div>
                <div className={`text-sm ${mode === "dark" ? "text-slate-200" : "text-brand-600"}`}>
                  This will just take a moment
                </div>
              </div>
            </div>
          </div>
        )}

{/* Recently checked sites dynamically from storage */}
<div className="mt-6">
  <h3
    className={`text-sm font-semibold mb-3 ${
      mode === "dark" ? "text-white" : "text-brand-800"
    }`}
  >
    Recently Checked
  </h3>

  {recentScans.length === 0 ? (
    <p
      className={`text-sm italic ${
        mode === "dark" ? "text-slate-400" : "text-slate-600"
      }`}
    >
      No sites checked yet
    </p>
  ) : (
    <div className="space-y-2">
      {[...recentScans].reverse().map((site) => (
        <button
          key={site.url}
          className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all hover:scale-[1.02] ${
            mode === "dark"
              ? "bg-slate-800/50 hover:bg-slate-800"
              : "bg-white hover:shadow-md"
          }`}
          onClick={() => setScanUrl(site.url.startsWith("http") ? site.url : `https://${site.url}`)}
        >
          {/* URL area scrolls, badge stays put */}
          <div
            className={`flex-1 min-w-0 overflow-x-auto whitespace-nowrap url-scroll ${
              mode === "dark" ? "text-white" : "text-slate-900"
            }`}
            title={site.url.match(/^(?:https?:\/\/)?([^/]+)/)?.[1] || site.url}
          >
            <span className="text-sm">
              {site.url.match(/^(?:https?:\/\/)?([^/]+)/)?.[1] || site.url}
            </span>
          </div>

          <Badge
            className={`text-xs font-medium px-2 py-1 rounded-full flex-shrink-0 ${
              site.safe === "safe"
                ? "bg-green-100 text-green-800 border-green-300"
                : site.safe === "warning"
                ? "bg-yellow-100 text-yellow-800 border-yellow-300"
                : "bg-red-100 text-red-800 border-red-300"
            }`}
          >
            {site.safe === "safe" ? "Safe" : site.safe === "warning" ? "Warning" : "Danger"}
          </Badge>
        </button>
      ))}
    </div>
  )}
</div>

      </div>
    </div>
  )
}

