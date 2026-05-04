# Store Listing Copy — NetSTAR Scout

Source-controlled copy for Chrome Web Store, Mozilla AMO, and (later) Apple App Store listings. Edit here, copy/paste into store consoles. Keep in sync with the public announcement at https://netstar.ai/netstar-scout-browser-extension-web-risk-intelligence/.

---

## Title (75 char max)

```
NetSTAR Scout
```

## Short name (used in some surfaces)

```
Scout
```

---

## Summary (132 char max — Chrome Web Store)

```
Real-time web risk intelligence in your browser. See how safe a site is before you click — powered by NetSTAR threat data.
```

(124 characters)

---

## Single Purpose Description (Chrome Web Store, since 2024 — one sentence)

```
Show users a real-time safety score and category for the website they're currently viewing, using NetSTAR's threat intelligence platform.
```

---

## Description (long-form, plain text, ~16K char max)

```
NetSTAR Scout brings the threat intelligence behind NetSTAR's enterprise web protection to your personal browser — for free.

For every site you visit, Scout shows you:
  • A safety score from 0 to 100
  • A category (so you know what kind of site you're on)
  • A clear visual indicator: safe, warning, or risky
  • Quick guidance when something looks dangerous

Scout is built on the same threat intelligence platform that powers NetSTAR's enterprise customers — phishing detection, malware reputation, certificate health, DNS posture, and more.

PRIVACY-FIRST DESIGN
  • Scout sends only the URL of the site you're viewing to NetSTAR's scoring service.
  • Page content is never uploaded as a whole. Lightweight signals (form structure, script obfuscation, hidden iframes) are summarized in your browser before being sent.
  • No browsing history is stored on NetSTAR servers beyond what's needed to score the request.
  • No tracking, no ads, no profile building.

WHAT'S NEW IN BETA
Scout is currently in BETA — the threat scoring engine is finishing calibration. The interface and category tagging are live; the live scoring backend activates in an update shortly after launch. The BETA badge in the popup will go away once full scoring is online.

ABOUT NETSTAR
NetSTAR is a global threat intelligence and web filtering provider. NetSTAR's classification and reputation feeds protect hundreds of millions of users through enterprise security partners worldwide. Scout brings that same intelligence to individual browsers.

Learn more: https://netstar.ai
Privacy policy: https://netstar.ai/scout/privacy

Questions or feedback: scout@netstar.ai
```

---

## Category

**Chrome Web Store**: `Productivity` (primary), `Communication` (secondary if available)

**Mozilla AMO**: `Privacy & Security` → `Security`

---

## Permission Justifications

Required by both CWS and AMO at submission time. One short paragraph per permission explaining why it's needed and what it's used for.

### `activeTab`
> Scout needs read access to the URL of the tab you're actively viewing in order to look up its safety score and category. Without this permission Scout can't tell you anything about the site you're on.

### `storage`
> Scout caches scan results in your browser (5-minute TTL) to avoid re-scoring the same site repeatedly as you navigate. Stored data: scan results keyed by domain, your theme preference, your tour-completion flag. Nothing is ever uploaded.

### `tabs`
> Scout needs to know when you switch tabs or load a new page so it can update the safety indicator and badge icon for the current site. We do not enumerate or read content of tabs you aren't viewing.

### `scripting`
> Required to inject Scout's overlay (a small in-page warning banner) when a high-risk site is detected. The overlay is read-only and has a one-click dismiss.

### `host_permissions: <all_urls>`
> Scout scores every website you visit, so it must be able to operate on any URL. We do not pre-fetch, crawl, or index sites in the background — we only act on the tab you're currently viewing.

### `optional_permissions: notifications`
> Optional. If granted, Scout shows a system notification when you visit a site scored below the warning threshold (default: 60/100). You can revoke this permission anytime in your browser settings; Scout still works without it.

---

## Privacy Policy URL

**Status**: TODO — needs hosted URL before submission.

**Recommended path**: `https://netstar.ai/scout/privacy`

**Required content** (Mozilla AMO + Chrome Web Store both check):
- What data is collected (URLs of visited tabs, lightweight DOM signals, telemetry)
- How it's transmitted (HTTPS to scan.wildcatdashboard.com once threat-mcp wires in; nothing currently while in BETA placeholder mode)
- How long it's retained (URL → 24h cache; aggregated telemetry per data retention policy)
- Third-party data flow (none beyond NetSTAR infrastructure)
- User rights (revoke optional permissions, uninstall to delete all local cache)
- Contact: privacy@netstar.ai

Draft template lives in `docs/privacy-policy.md` (TODO).

---

## Screenshots (1280×800, 4-5 shots)

### Shot 1 — Popup on a safe site
- Open popup on https://example.com
- Show: SCOUT badge, BETA badge, score 95/100 (green), Category: GenAI: Chat, "What We Checked" expanded with all green indicators

### Shot 2 — Tour walkthrough
- First-install tour mid-step (the score-explanation step works well)

### Shot 3 — Settings tab
- Theme toggle visible, light/dark/system options

### Shot 4 — Recent scans (if implemented) or popup detail view
- Drill-down view of one indicator (e.g. Certificate Health detail)

### Shot 5 — Header/branding shot
- Just the popup header showing NetSTAR + SCOUT + BETA badges + Web Risk Intelligence subtitle

**TODO**: Capture once we agree on placeholder UX framing (#11 BETA badge ships now; tour copy still capstone-era per #4).

---

## Promotional Images (Chrome Web Store)

| Asset | Size | Required? |
|---|---|---|
| Small promo tile | 440×280 | Required |
| Large promo tile | 920×680 | Optional but recommended |
| Marquee | 1400×560 | Optional, used in featured slots |

**Design direction**: Use the same blue + amber palette as the BETA badge in the popup. NetSTAR brand wordmark + Scout pill + "Web Risk Intelligence" tagline.

**TODO**: Hand off to design (or generate in Figma).

---

## Developer Notes (review-only, not user-visible)

Field for explaining edge cases to store reviewers. Both CWS and AMO have one.

```
Scout currently ships in BETA mode while the full threat-scoring backend
finishes calibration. The popup displays a BETA badge in the header to
make this status visible to users. During BETA, the scoring response is
generated locally and shows a placeholder safe verdict for every URL —
no data is transmitted to remote servers.

Once the scoring backend goes live in a follow-up release, the URL of
the active tab will be sent to scan.wildcatdashboard.com (Cloudflare-
protected) and lightweight DOM signals (form structure summary, script
obfuscation indicators) will be sent in the request body. We pre-declare
both data flows in the Firefox manifest's data_collection_permissions
field (websiteContent, browsingActivity).

Source code is available on request to reviewers.
```

---

## Trade Compliance (CWS)

**Export classification**: Self-classified as encryption item using publicly available standard cryptography only (HTTPS to fetch scan results). No additional ECCN registration required.

---

## Reference Links

- Public announcement: https://netstar.ai/netstar-scout-browser-extension-web-risk-intelligence/
- Privacy policy: https://netstar.ai/scout/privacy *(pending publication)*
- Support email: scout@netstar.ai
- Source repo (private): https://github.com/grassclaw/netstar-scout
