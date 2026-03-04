import { Moon, Sun } from "lucide-react"

/**
 * Theme toggle icon: shows the icon for the current look (light or dark).
 * Always matches effective mode so there is no separate "system" icon—
 * e.g. when system is dark, show Sun (click to switch to light).
 * @param {"light"|"dark"} [effectiveMode] - Current effective theme (from mode or themeMode when system)
 * @param {"light"|"dark"} [mode] - Legacy: same as effectiveMode
 * @param {string} className - Additional CSS classes
 */
export function ThemeToggleIcon({ effectiveMode: effectiveModeProp, mode: modeProp, themeMode, className = "" }) {
  const effectiveMode = effectiveModeProp ?? modeProp ?? "light"
  if (effectiveMode === "dark") {
    return <Moon className={`h-4 w-4 text-slate-300 ${className}`} aria-hidden />
  }
  return <Sun className={`h-4 w-4 text-amber-500 ${className}`} aria-hidden />
}

