# NetSTAR Scout — Privacy Policy

**Effective date:** 2026-05-10 (Scout v1.0.4 launch)
**Last updated:** 2026-05-04
**Applies to:** NetSTAR Scout browser extension for Chrome, Firefox, Edge, and (forthcoming) Safari.

> **For legal review before publication.** This draft was prepared by the Scout product team and must be reviewed by NetSTAR counsel against jurisdiction-specific obligations (GDPR, CCPA/CPRA, PIPEDA, Quebec Law 25, LGPD, COPPA) before being published at https://netstar.ai/scout/privacy.

---

## At a glance

NetSTAR Scout helps you make safer browsing decisions. To do that, it sends the URL of the website you're currently viewing to NetSTAR's threat-intelligence service and receives a safety score and category back.

**We collect:** the URL of your active tab, and a small structural summary of the current page (form layout, script characteristics, hidden elements) — only when Scout is actively scoring that page.

**We don't collect:** browsing history beyond the active tab, page contents, your identity, your IP address as a tracking identifier, anything for advertising purposes.

**We don't sell your data.** We don't share it with advertisers. We don't use it to build a profile of you.

You control what's transmitted: uninstall Scout to stop all data collection immediately, revoke the optional notifications permission anytime, or block specific sites by adjusting browser-level extension permissions.

---

## 1. Who we are

NetSTAR, Inc. ("NetSTAR", "we", "us") publishes the NetSTAR Scout browser extension. NetSTAR is a global threat-intelligence and web-categorization provider whose enterprise classification feeds protect hundreds of millions of users through security partners worldwide. Scout brings that intelligence to individual browsers as a free consumer tool.

Contact: scout@netstar.ai
Support: https://netstar.ai/scout/support
Privacy contact: privacy@netstar.ai

---

## 2. What data Scout collects

Scout collects only what's needed to score the website you're currently viewing.

### 2.1 Sent to NetSTAR's scoring service

| Data | When | Why |
|---|---|---|
| URL of your active tab (`https://example.com/page`) | When you load or switch to a tab over HTTP/HTTPS | To look up the site's safety score and category |
| Page structure summary — form count, password-field count, script obfuscation indicators, hidden iframe count, Unicode-obfuscation flags | When Scout scans the active tab | To detect phishing patterns, malware-staging behavior, and credential harvesters |
| Extension version | With every scoring request | To support backward compatibility and debugging |

We do **not** transmit:
- Page text, page screenshots, page HTML, or any document the page renders
- Form field values (passwords, usernames, anything you type)
- Cookies or session tokens
- Other open tabs' URLs
- Browsing history
- Bookmarks
- Files on your device
- Your name, email, or any account identifier (Scout has no user accounts)

### 2.2 Stored locally in your browser (`chrome.storage.local` / `browser.storage.local`)

| Data | Retention | Why |
|---|---|---|
| Cached scan results, keyed by domain | 5 minutes per domain (TTL) | Avoids re-scoring the same site as you navigate within it |
| Theme preference (light / dark / system) | Until uninstall | Honor your visual preference |
| Tour-completion flag | Until uninstall | Don't re-show the onboarding tour after first use |
| Recent scans list (URLs + scores from your current session) | Capped, rolling history | Powers the "recent scans" display in the popup |
| Page-signal cache, keyed by domain | Up to 5 minutes per domain | Reduces redundant DOM extraction during a session |

This data never leaves your device. NetSTAR cannot read your local browser storage.

### 2.3 Server-side telemetry

When the scoring backend processes your request, our servers log:
- Timestamp of the request
- The URL that was scored
- The score and category we returned
- Aggregate response-time metrics

These logs are kept in a NetSTAR-controlled environment with restricted access, used for service operation, abuse prevention, and quality monitoring. We do not link them to any user identity (Scout has no user accounts and does not transmit a stable client identifier).

---

## 3. What data Scout does NOT collect

To make the boundary clear:

- **No user accounts.** Scout has no sign-in, no profile, no NetSTAR ID associated with you.
- **No cross-site tracking.** Scout does not set tracking cookies, fingerprint your browser, or track behavior across sites for advertising or analytics.
- **No advertising data.** Scout does not participate in any advertising network, RTB exchange, or audience-segmentation product.
- **No third-party SDKs.** Scout does not embed Google Analytics, Mixpanel, Sentry, Segment, Amplitude, or any other third-party telemetry SDK in the extension.
- **No biometric, location, financial, or health data.**
- **No data from inactive tabs.** Scout reads only the URL of the tab you're actively viewing.

---

## 4. How we use the data

We use the data described in §2 for these purposes only:

1. **Provide the safety scoring service** — score and categorize the site you're viewing
2. **Operate the service** — capacity planning, performance monitoring, error debugging
3. **Detect and prevent abuse** — automated bot traffic, scrape attempts, denial-of-service patterns
4. **Improve the threat-intelligence feeds** — aggregate scoring data informs which sites get prioritized for deeper analysis. Aggregation is non-attributable; no individual-user behavior is reconstructed.

We do **not** use the data for:
- Advertising or marketing to you
- Building a profile of you, your interests, or your identity
- Selling or licensing to third parties
- Cross-device tracking
- Any purpose disclosed only to a partner, employer, or other third party

---

## 5. Who we share data with

NetSTAR does not sell or rent your data. We share data only as follows:

| Recipient | What | Why |
|---|---|---|
| Cloudflare | URL + page signals in transit | Cloudflare fronts our scoring service for DDoS protection and TLS termination. Cloudflare does not retain content of requests. See [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/). |
| Amazon Web Services (US-East-1) | URL + page signals at rest in service logs | Underlying cloud infrastructure for the scoring backend. Logs are encrypted at rest and access-controlled. |
| Law enforcement | Only when legally compelled | We will only respond to valid legal process and will challenge overbroad requests. |

We do not share data with advertisers, data brokers, social-media networks, or analytics vendors.

---

## 6. Data retention

| Data | Retention period |
|---|---|
| Local browser cache (scan results, signals) | 5 minutes per domain (auto-expires); cleared on uninstall |
| Local browser preferences (theme, tour flag) | Until you uninstall the extension |
| Server-side scoring logs | 90 days, then aggregated and the per-request rows deleted |
| Aggregated scoring statistics | Indefinite, non-attributable to individual users |
| Abuse-detection / rate-limit data | 30 days |

You can delete all local data at any time by uninstalling Scout from your browser's extension manager.

---

## 7. Security

We protect data in transit and at rest:

- **In transit**: All scoring requests use HTTPS (TLS 1.2+). Our service endpoints reject non-encrypted requests.
- **At rest**: Server logs are encrypted using AWS-managed keys (AES-256). Access to production data is restricted to a small group of NetSTAR engineers under access-logged controls.
- **No long-term identifiers**: Scout transmits no stable client identifier, so server-side data cannot be linked to a recurring user across sessions.

No system is perfectly secure. If a breach occurs that affects your data, we will notify users in accordance with applicable law and the timelines required by GDPR Article 33 (EU users) and equivalent statutes.

---

## 8. Your rights and choices

### Everyone

- **Stop all data collection**: uninstall Scout. All local data is cleared by your browser; no further requests are made.
- **Revoke the optional notifications permission** at any time via your browser's extension settings.
- **Disable Scout temporarily** via your browser's extension toggle.

### EU / UK / EEA residents (GDPR / UK GDPR)

You have the right to:
- **Access** the data we hold about you (note: because Scout has no user identifier, we typically have no way to identify your data among server logs; we can confirm this in writing)
- **Rectification** of inaccurate data
- **Erasure** ("right to be forgotten")
- **Restriction** of processing
- **Objection** to processing based on legitimate interests
- **Data portability** in a machine-readable format
- **Withdraw consent** for any processing based on consent
- **Lodge a complaint** with your supervisory authority

Lawful basis for processing: **legitimate interests** (Article 6(1)(f)) — providing a security tool that protects users from malicious websites — balanced against the minimal data collected and the absence of profiling.

To exercise any of these rights: privacy@netstar.ai. We will respond within 30 days.

### California residents (CCPA / CPRA)

You have the right to:
- **Know** what personal information we collect, use, and disclose
- **Delete** personal information we hold about you
- **Correct** inaccurate personal information
- **Opt out of "sale" or "sharing"** — we do neither, but the right exists
- **Limit use of sensitive personal information** — we collect none
- **Non-discrimination** for exercising your rights

We do not sell or share personal information for cross-context behavioral advertising. Scout collects no "sensitive personal information" as defined by CPRA.

To exercise these rights: privacy@netstar.ai or our designated agent (TBD).

### Other jurisdictions

PIPEDA (Canada), Quebec Law 25, LGPD (Brazil), POPIA (South Africa), PIPL (China), APPI (Japan), and similar statutes provide rights generally analogous to those above. Contact privacy@netstar.ai for jurisdiction-specific requests.

---

## 9. Children's privacy

Scout is a general-audience security tool. We do not knowingly collect personal information from children under 13 (or under 16 in the EU). If you believe a child has installed Scout and we have inadvertently collected their data, contact privacy@netstar.ai and we will take appropriate steps under COPPA and equivalent laws.

---

## 10. International data transfers

NetSTAR's scoring infrastructure operates primarily in AWS US-East-1 (Northern Virginia, USA). If you use Scout from outside the United States, your data is transferred to the US for processing.

For EU/UK users, this transfer is governed by the **Standard Contractual Clauses** approved by the European Commission (2021/914/EU). NetSTAR has signed SCCs with all sub-processors listed in §5.

---

## 11. Beta-period note

Scout v1.0.4 (the May 10, 2026 launch build) ships with the threat-scoring backend in a **calibration / BETA state**. During this period, Scout displays a placeholder safety score and category locally — **no scan requests are transmitted to NetSTAR servers** while the BETA badge is shown in the popup header.

When the live scoring backend goes online in a subsequent update, Scout will begin sending the data described in §2.1 above. We will publish a release note when this transition happens. Users who install during the BETA period and who do not want their data transmitted once full scoring activates can uninstall the extension at that time.

---

## 12. Changes to this policy

We will post material changes to this policy at https://netstar.ai/scout/privacy at least 14 days before they take effect. The "Last updated" date at the top of this policy reflects the most recent revision. Substantive changes (new data categories collected, new third parties, new uses) will also be communicated via an in-extension notice in the popup.

---

## 13. Contact

| For | Email |
|---|---|
| General privacy questions | privacy@netstar.ai |
| Exercise of GDPR / CCPA / CPRA rights | privacy@netstar.ai |
| Security vulnerability disclosure | security@netstar.ai |
| Scout product support | scout@netstar.ai |

NetSTAR, Inc.
[Mailing address — TBD by NetSTAR legal]
[EU representative under GDPR Art. 27 — TBD]
[California Privacy Agent — TBD]

---

## Appendix A — Manifest data-collection declarations

For transparency, the formal data-collection declarations Scout makes to browser-extension stores:

**Mozilla AMO** (`browser_specific_settings.gecko.data_collection_permissions`):
- `required: ["websiteContent", "browsingActivity"]`

**Chrome Web Store** (developer console disclosures):
- Personal communications: **No**
- Authentication information: **No**
- Personally identifiable info: **No**
- Financial / payment info: **No**
- Health info: **No**
- Location: **No**
- Web history: **No** (we read only the active tab's URL, not history)
- User activity: **Yes** — URL of active tab transmitted for scoring
- Website content: **Yes** — page structure summary transmitted with scoring request

**Apple App Store** (App Privacy "Nutrition Label"):
- Browsing history: linked to scoring request, not linked to user identity
- Identifiers: none collected
- Diagnostics: aggregate performance metrics, not linked to user

These declarations match this policy. Discrepancies should be reported to privacy@netstar.ai.

---

## Appendix B — Open-source components

Scout includes the following third-party libraries. Each has its own license terms; none collect user data on NetSTAR's behalf.

- React 19 (MIT)
- Tailwind CSS 4 (MIT)
- Radix UI primitives (MIT)
- Lucide icons (ISC)
- wxt build framework (MIT)
- @vitejs/plugin-react (MIT)

Full attribution and license texts are available in the extension package's `LICENSES.txt` (TODO: generate at build time).
