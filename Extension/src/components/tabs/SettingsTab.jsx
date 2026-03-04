/* global chrome */
import { useEffect, useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import * as Switch from "@radix-ui/react-switch";

/**
 * TextSizeRow (General → Text Size)
 *
 * Requirements implemented during this session:
 * - The "Text Size" label acts as the visible test text for scaling.
 * - The slider UI (track/thumb and the A indicators) MUST NOT resize when text scaling changes.
 *
 * Approach:
 * - The slider UI is wrapped in a container (`.textsize-ui`) that is locked to a fixed px font-size
 *   and fixed px layout in CSS.
 * - The `value` is discrete (0..4) to keep 5 stable accessibility options.
 *
 * Note:
 * - We removed tick marks to avoid alignment/length issues across browsers and font scales.
 * - The slider remains discrete via step=1, so users still get 5 fixed positions.
 */
function TextSizeRow({ mode, value, onChange }) {
  const labels = ["Smallest", "Small", "Default", "Large", "Largest"];
  const clampStep = (v) => Math.max(0, Math.min(4, v));
  const safeValue = clampStep(Number.isFinite(value) ? value : 2);
  // While dragging, we update this local value only (no global font-size change).
  const [previewValue, setPreviewValue] = useState(safeValue);

  useEffect(() => {
    // Keep preview synced when the saved value changes (initial load, etc.)
    setPreviewValue(safeValue);
    latestValueRef.current = safeValue;
  }, [safeValue]);

  /**
   * Endpoint indicator sizing.
   *
   * We render small and large "A" at fixed px sizes so they visually represent the extremes
   * without being affected by the global text scaling setting.
   */
  const minPx = 14;
  const maxPx = 18;

  const track =
    mode === "dark" ? "rgba(148, 163, 184, 0.35)" : "rgba(148, 163, 184, 0.6)";
  const thumb = mode === "dark" ? "#ffffff" : "#0f172a";
  const thumbBorder =
    mode === "dark"
      ? "rgba(255,255,255,0.25)"
      : "rgba(15,23,42,0.15)";

  // Used to pin slider position during click+drag while the UI reflows.
  const sliderRef = useRef(null);
  const draggingRef = useRef(false);
  const latestValueRef = useRef(safeValue);


  return (
    <div className="mt-4">
      <div className="flex items-center gap-4">
        <div
          className={`text-sm font-medium ${
            mode === "dark" ? "text-white" : "text-slate-900"
          } min-w-[88px]`}
        >
          Text Size
        </div>

        {/**
         * IMPORTANT: The `.textsize-ui` container is intentionally fixed-size in CSS so that:
         * - slider track/thumb
         * - "A" endpoint indicators
         * - spacing/width
         * do NOT change when the popup's root font-size changes.
         *
         * This ensures the control remains stable while the surrounding UI text scales.
         */}
        <div className="textsize-ui">
          {/* Small A (fixed size) */}
          <span
            style={{ fontSize: `${minPx}px`, lineHeight: "1" }}
            className={mode === "dark" ? "text-slate-300" : "text-slate-700"}
            aria-hidden="true"
          >
            A
          </span>

          {/**
           * Discrete 5-step range input (0..4).
           *
           * - step=1 ensures only 5 positions.
           * - `aria-valuetext` provides accessible labels ("Smallest"..."Largest").
           *
           * Tick marks were removed to keep layout stable and avoid browser inconsistencies.
           *
           * Additional behavior added:
           * - While click+dragging, compensate scroll so the slider stays pinned in the viewport
           *   even as font size changes cause surrounding layout to reflow.
           */}

          <div
            className="textsize-trackwrap"
            style={{
              "--ts-track": track,
              "--ts-thumb": thumb,
              "--ts-thumb-border": thumbBorder,
            }}
          >
            <input
              ref={sliderRef}
              type="range"
              min={0}
              max={4}
              step={1}
              value={previewValue}
              onPointerDown={() => {
                draggingRef.current = true;

                const stop = () => {
                  draggingRef.current = false;

                  // Commit the final selection only when the user releases click/touch
                  onChange(clampStep(latestValueRef.current));

                  window.removeEventListener("pointerup", stop);
                  window.removeEventListener("pointercancel", stop);
                };

                window.addEventListener("pointerup", stop);
                window.addEventListener("pointercancel", stop);
              }}
              onChange={(e) => {
                const next = clampStep(Number(e.target.value));
                latestValueRef.current = next;   // <-- immediate, no React timing issues
                setPreviewValue(next);
              }}

              className="textsize-range"
              aria-label="Text size"
              aria-valuetext={labels[previewValue] ?? "Default"}
            />
          </div>

          {/* Big A (fixed size) */}
          <span
            style={{ fontSize: `${maxPx}px`, lineHeight: "1" }}
            className={mode === "dark" ? "text-slate-200" : "text-slate-900"}
            aria-hidden="true"
          >
            A
          </span>
        </div>
      </div>
    </div>
  );
}

/**
 * SettingsTab component - Displays application settings and preferences.
 *
 * Notifications model:
 *  - Soft toggle saved in chrome.storage.local as `notificationsEnabledSoft`.
 *  - Chrome optional permission "notifications".
 *  - We only send alerts when both soft toggle and permission are true.
 *  - When turning ON, request permission if missing, then show one test notification.
 *  - Turning OFF keeps the browser permission intact (soft disable only).
 *  - A separate button fully revokes the browser permission.
 *
 * @component
 * @memberof module:Front End
 * @param {Object} props
 * @param {"light"|"dark"} props.mode - Current theme mode
 * @param {Function} props.onBack - Navigate back to previous tab
 * @param {Function} props.onStartTour - Start guided tour
 * @returns {JSX.Element}
 *
 * @example
 * <SettingsTab
 *   mode="dark"
 *   onBack={() => setActiveTab("home")}
 *   onStartTour={() => setIsTourActive(true)}
 * />
 */

/** Read soft toggle from storage. */
function readSoftToggle() {
  return new Promise((resolve) => {
    chrome.storage.local.get("notificationsEnabledSoft", (res) => {
      resolve(Boolean(res && res.notificationsEnabledSoft));
    });
  });
}

/** Write soft toggle to storage. */
function writeSoftToggle(value) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ notificationsEnabledSoft: Boolean(value) }, () =>
      resolve()
    );
  });
}

/** Check Chrome notifications permission. */
function hasNotificationsPermission() {
  return new Promise((resolve) => {
    if (!chrome || !chrome.permissions) return resolve(false);
    chrome.permissions.contains(
      { permissions: ["notifications"] },
      (has) => resolve(Boolean(has))
    );
  });
}

/** Request Chrome notifications permission (must be from a user gesture). */
function requestNotificationsPermission() {
  return new Promise((resolve) => {
    if (!chrome || !chrome.permissions || !chrome.permissions.request)
      return resolve(false);
    chrome.permissions.request(
      { permissions: ["notifications"] },
      (granted) => resolve(Boolean(granted))
    );
  });
}

/** Revoke Chrome notifications permission. */
function revokeNotificationsPermission() {
  return new Promise((resolve) => {
    if (!chrome || !chrome.permissions || !chrome.permissions.remove)
      return resolve(false);
    chrome.permissions.remove(
      { permissions: ["notifications"] },
      (removed) => resolve(Boolean(removed))
    );
  });
}

/** Build a packaged icon URL for notifications. */
function resolveIconUrl() {
  const manifest = chrome.runtime.getManifest();
  const iconPath =
    (manifest.icons &&
      (manifest.icons["128"] ||
        manifest.icons["48"] ||
        manifest.icons["16"])) ||
    "src/icons/icon-safe-128.png";
  return chrome.runtime.getURL(iconPath);
}

/** Verify a chrome-extension URL exists. */
async function checkUrlExists(url) {
  try {
    const res = await fetch(url, { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

/** Fire a single test notification. Assumes permission is already granted. */
async function showTestNotification() {
  if (!(chrome && chrome.notifications)) return;
  const iconUrl = resolveIconUrl();
  if (!(await checkUrlExists(iconUrl))) return;

  chrome.notifications.create(
    {
      type: "basic",
      iconUrl,
      title: "Notifications enabled",
      message: "You will see alerts when a site looks risky.",
      priority: 2,
    },
    () => {
      if (chrome.runtime && chrome.runtime.lastError) {
        console.warn(
          "notifications.create error:",
          chrome.runtime.lastError.message
        );
      }
    }
  );
}

export function SettingsTab({
  mode,
  themeMode = "system",
  onThemeModeChange,
  onBack,
  onStartTour,
  textSizeStep,
  onTextSizeStepChange,
}) {
  const [softEnabled, setSoftEnabled] = useState(false);
  const [hasPermission, setHasPermission] = useState(false);
  const [isChecking, setIsChecking] = useState(true);

  // Initial load
  useEffect(() => {
    let mounted = true;
    (async () => {
      const [soft, perm] = await Promise.all([
        readSoftToggle(),
        hasNotificationsPermission(),
      ]);
      if (!mounted) return;
      setSoftEnabled(soft);
      setHasPermission(perm);
      setIsChecking(false);
    })();
    return () => {
      mounted = false;
    };
  }, []);

  /**
   * Toggle notifications (soft). When turning ON, request permission if needed,
   * persist the soft toggle, and show one test notification.
   */
  const handleToggleSoft = async (nextChecked) => {
    if (isChecking) return;
    setIsChecking(true);

    if (nextChecked) {
      // Turning ON
      let perm = await hasNotificationsPermission();
      if (!perm) {
        const granted = await requestNotificationsPermission();
        if (!granted) {
          await writeSoftToggle(false);
          setSoftEnabled(false);
          setHasPermission(false);
          setIsChecking(false);
          return;
        }
        perm = true;
      }

      await writeSoftToggle(true);
      setSoftEnabled(true);
      setHasPermission(true);
      setIsChecking(false);

      await showTestNotification();
      return;
    }

    // Turning OFF (soft only)
    await writeSoftToggle(false);
    setSoftEnabled(false);
    setHasPermission(await hasNotificationsPermission());
    setIsChecking(false);
  };

  /** Fully revoke browser permission and clear soft toggle. */
  const handleRevokePermission = async () => {
    setIsChecking(true);
    await revokeNotificationsPermission();
    await writeSoftToggle(false);
    setSoftEnabled(false);
    setHasPermission(false);
    setIsChecking(false);
  };

  return (
    <div className="p-6 space-y-4">
      {/* <Button
        variant="ghost"
        size="sm"
        onClick={onBack}
        className={`mb-4 ${mode === "dark" ? "text-slate-200 hover:text-white" : "text-slate-700 hover:text-slate-900"}`}
      >
        ← Back
      </Button> */}

      <h2
        className={`font-bold text-lg mb-4 ${
          mode === "dark" ? "text-white" : "text-slate-900"
        }`}
      >
        Settings
      </h2>

      <div className="space-y-4">
        {/* Help & Tutorial */}
        <div
          className={`border-2 rounded-2xl p-5 ${
            mode === "dark"
              ? "border-brand-700 bg-gradient-to-br from-brand-900/30 to-slate-800/30"
              : "border-brand-300 bg-gradient-to-br from-brand-50 to-white"
          }`}
        >
          <div className="flex items-start gap-3">
            <div className="flex-1">
              <h3
                className={`font-medium mb-2 ${
                  mode === "dark" ? "text-white" : "text-slate-900"
                }`}
              >
                Help & Tutorial
              </h3>
              <p
                className={`text-sm mb-3 ${
                  mode === "dark" ? "text-slate-300" : "text-slate-600"
                }`}
              >
                New to NetSTAR? Take a guided tour to learn how to use all the
                features and keep yourself safe online.
              </p>
              <Button
                size="sm"
                onClick={onStartTour}
                className="bg-gradient-to-r from-brand-500 to-brand-600 text-white hover:from-brand-600 hover:to-brand-700"
              >
                Start Guided Tour
              </Button>
            </div>
          </div>
        </div>

        {/* General */}
        <div
          className={`border rounded-2xl p-5 ${
            mode === "dark"
              ? "border-slate-700 bg-slate-800/30"
              : "border-slate-200 bg-slate-50"
          }`}
        >
          <h3
            className={`font-medium mb-2 ${
              mode === "dark" ? "text-white" : "text-slate-900"
            }`}
          >
            General
          </h3>
          <p
            className={`text-sm ${
              mode === "dark" ? "text-slate-300" : "text-slate-600"
            }`}
          >
            Configure general settings for NetSTAR
          </p>
          {/* Theme */}
          <div className="flex items-center gap-4 mb-4">
            <div
              className={`text-sm font-medium ${
                mode === "dark" ? "text-white" : "text-slate-900"
              } min-w-[88px]`}
            >
              Theme
            </div>
            <select
              value={themeMode}
              onChange={(e) => onThemeModeChange?.(e.target.value)}
              className={`text-sm rounded-lg border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-500 ${
                mode === "dark"
                  ? "border-slate-600 bg-slate-800 text-white"
                  : "border-slate-300 bg-white text-slate-900"
              }`}
              aria-label="Theme"
            >
              <option value="system">System (match OS)</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </div>
          <TextSizeRow
            mode={mode}
            value={textSizeStep ?? 2}
            onChange={onTextSizeStepChange}
          />
        </div>

        {/* Notifications */}
        <div
          className={`border rounded-2xl p-5 ${
            mode === "dark"
              ? "border-slate-700 bg-slate-800/30"
              : "border-slate-200 bg-slate-50"
          }`}
        >
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3
                className={`font-medium mb-2 ${
                  mode === "dark" ? "text-white" : "text-slate-900"
                }`}
              >
                Notifications
              </h3>
              <p
                className={`text-sm ${
                  mode === "dark" ? "text-slate-300" : "text-slate-600"
                }`}
              >
                Turn desktop alerts on or off for risky sites. When enabled, we
                will notify you if a page looks unsafe.
              </p>
            </div>

            {/* Radix Switch for notifications soft toggle */}
            <div className="flex items-center gap-2">
              <label htmlFor="notif-switch" className="sr-only">
                Notifications
              </label>
              <Switch.Root
                id="notif-switch"
                checked={softEnabled}
                disabled={isChecking}
                onCheckedChange={handleToggleSoft}
                className={`
                  group inline-flex h-6 w-11 items-center rounded-full p-1 outline-none transition
                  ${softEnabled ? "bg-brand-500" : "bg-slate-400/60"}
                  ${isChecking ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
                  data-[state=checked]:bg-brand-500
                  data-[state=unchecked]:bg-slate-400/60
                `}
                aria-label="Toggle notifications"
              >
                <Switch.Thumb
                  className={`
                    block h-4 w-4 rounded-full bg-white shadow transition-transform
                    data-[state=checked]:translate-x-5
                    data-[state=unchecked]:translate-x-0
                  `}
                />
              </Switch.Root>
            </div>
          </div>

          {/* Revoke permission */}
          <div className="mt-4 border-t pt-3">
            <h4
              className={`text-sm font-medium mb-1 ${
                mode === "dark" ? "text-white" : "text-slate-900"
              }`}
            >
              Revoke browser permission
            </h4>
            <p
              className={`text-xs mb-2 ${
                mode === "dark" ? "text-slate-400" : "text-slate-500"
              }`}
            >
              This turns off all desktop notifications from this extension at
              the browser level. You can re-enable notifications later, but
              Chrome will ask you to grant permission again.
            </p>
            <Button
              size="sm"
              className="bg-gradient-to-r from-brand-500 to-brand-600 text-white hover:from-brand-600 hover:to-brand-700"
              onClick={handleRevokePermission}
            >
              Revoke permission
            </Button>
          </div>
        </div>

        {/* Privacy */}
        {/* <div className={`border rounded-2xl p-5 ${mode === "dark" ? "border-slate-700 bg-slate-800/30" : "border-slate-200 bg-slate-50"}`}>
          <h3 className={`font-medium mb-2 ${mode === "dark" ? "text-white" : "text-slate-900"}`}>Privacy</h3>
          <p className={`text-sm ${mode === "dark" ? "text-slate-300" : "text-slate-600"}`}>Control your privacy and data settings</p>
        </div> */}
      </div>
    </div>
  );
}
