# NetSTAR Shield Browser Extension

A friendly and intuitive browser extension that helps users stay safe online by providing real-time security insights about websites they visit.

![NetSTAR Extension](https://img.shields.io/badge/Browser-Extension-purple?style=for-the-badge)
![React](https://img.shields.io/badge/React-19-blue?style=for-the-badge)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=for-the-badge)

## Features

### Home Tab
- Real-time safety score (0-100) for the current website
- Visual gradient display showing overall security status
- Expandable security indicators section with 7 detailed metrics:
  - Certificate Health
  - Connection Security
  - Domain Reputation
  - Credential Safety
  - IP Reputation
  - DNS Record Health
  - WHOIS Pattern
- Click any indicator to view detailed explanations

### Scan Tab
- Manually scan any URL before visiting
- Input field with URL validation
- Animated scanning progress indicator
- Recent scan history tracking
- Quick access to previously scanned sites

### Alerts Tab
- High-priority security alert display
- Friendly "Hold On!" warning with actionable buttons
- Clear messaging about potential threats
- Simple interface for security awareness

### Details View
- Deep dive into individual security indicators
- Color-coded status badges (Excellent/Good/Moderate/Poor)
- Educational insights explaining security concepts
- User-friendly explanations with emojis and icons
- Back navigation to return to home

### Settings Tab
- Help & Tutorial section with guided tour button
- General settings placeholder
- Notifications preferences placeholder
- Privacy settings placeholder
- Accessible via gear icon in header

### Guided Tour
- Interactive 7-step walkthrough for new users
- Step-by-step navigation through all features
- Highlights specific UI elements with pulsing glow effect
- Auto-expands sections when relevant
- Skip or close tour at any time
- Positioned tooltip that doesn't obscure content

### Theme Support
- Light and dark mode toggle
- Sun/Moon icon indicator with enhanced contrast
- Consistent theming across all tabs
- Smooth gradient backgrounds

## Quick Start

### Prerequisites
- Node.js 16 or higher
- npm or yarn
- Chrome, Edge, or any Chromium-based browser

### Installation

1. Clone and Install
   ```bash
   git clone https://github.com/YOUR_USERNAME/netstar-shield-prototype-1.git
   cd netstar-shield-prototype-1
   npm install
   ```

2. Start Development Server
   ```bash
   npm run dev
   ```

3. Load in Browser
   - Open `chrome://extensions/` (Chrome) or `edge://extensions/` (Edge)
   - Enable "Developer mode" (toggle in top-right)
   - Click "Load unpacked"
   - Select the `dist` folder

## Development

### Development Mode with Hot Reload
```bash
npm run dev
```

This starts the development server with hot module reloading. Any changes you make to the code will automatically update in the extension without manual reloading.

### Building for Production
```bash
npm run build
```

This command builds an optimized production version of the extension in the `dist` folder.

### Project Structure
```
├── src/
│   ├── manifest.json           # Chrome Extension manifest (Manifest V3)
│   ├── background.js           # Background service worker
│   ├── index.html              # Extension popup HTML
│   ├── popup.jsx               # Main popup with tab navigation & tour
│   ├── index.css               # Tailwind CSS styles with custom brand colors
│   ├── icons/                  # Extension icons (16px, 48px, 128px)
│   │   ├── icon*.png           # Standard extension icons
│   │   ├── icon-safe-*.png     # Dynamic green safety icons
│   │   ├── icon-warning-*.png  # Dynamic yellow warning icons
│   │   └── icon-danger-*.png   # Dynamic red danger icons
│   ├── components/
│   │   ├── Tour.jsx            # Guided tour component
│   │   ├── tabs/               # Tab components
│   │   │   ├── HomeTab.jsx     # Home view with safety score
│   │   │   ├── ScanTab.jsx     # Manual URL scanner
│   │   │   ├── AlertsTab.jsx   # Security alerts
│   │   │   ├── DetailsTab.jsx  # Detailed indicator view
│   │   │   └── SettingsTab.jsx # Settings and help
│   │   └── ui/                 # Reusable UI components (shadcn/ui)
│   │       ├── badge.jsx
│   │       ├── button.jsx
│   │       ├── card.jsx
│   │       ├── input.jsx
│   │       └── progress.jsx
│   └── lib/
│       └── utils.js            # Utility functions (cn helper)
├── dist/                       # Build output (auto-generated)
├── vite.config.js              # Vite configuration
├── components.json             # shadcn/ui configuration
├── THEME_GUIDE.md              # Color scheme documentation
└── DYNAMIC_ICONS_GUIDE.md      # Icon generation documentation
```

## Tech Stack

- **React 19** - UI framework with hooks
- **Vite 5** - Lightning-fast build tool and dev server
- **@crxjs/vite-plugin** - Hot module reloading for Chrome extensions
- **Tailwind CSS 4** - Utility-first styling
- **shadcn/ui** - High-quality accessible components
- **Radix UI** - Unstyled accessible component primitives
- **Lucide React** - Beautiful icon set
- **Chrome Extension API (Manifest V3)** - Extension functionality

## Extension Permissions

The extension requires the following permissions:

- `activeTab` - Access current tab information for security analysis
- `storage` - Save recent scans, preferences, and tour progress
- `tabs` - Query tab information for auto-scanning
- `<all_urls>` - Scan any website (host permissions)

## Documentation

In-depth guides live in the [docs/](docs/) folder:

| Document | Description |
|----------|-------------|
| [DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md) | How the extension works, file interactions, component architecture, data flow, and development workflow. |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System diagrams and design patterns (mermaid sequence/flow diagrams). |
| [THEME_GUIDE.md](docs/THEME_GUIDE.md) | How to change the color theme — brand and accent color scales in `index.css`. |
| [CACHING_AND_MESSAGING.md](docs/CACHING_AND_MESSAGING.md) | Evolution of the caching system and `chrome.runtime` message passing. |
| [CONTENT_STRATEGY.md](docs/CONTENT_STRATEGY.md) | Hybrid client/server content management strategy for security text. |
| [CODE_QUALITY_ASSESSMENT.md](docs/CODE_QUALITY_ASSESSMENT.md) | Code quality review and grading. |
| [TOUR_REVIEW.md](docs/TOUR_REVIEW.md) | Tour component implementation review and improvement notes. |

For cross-cutting project docs (testing, deployment, URL sanitization policy), see [Docs/](../Docs/).

## Current Status

The extension is fully integrated with the Node server and Python scoring engine:

- Real-time security scoring via the `/scan` API (certificate, DNS, HVAL, RDAP, domain reputation, credential safety, IP reputation, WHOIS)
- Background service worker monitors tab navigation and triggers scans automatically
- Results are cached per-domain with a configurable TTL
- Dynamic extension icon reflects site safety (safe / warning / danger)
- Manual URL scanning with scan history persisted in `chrome.storage`
- Light/dark/system theme with persistent preference
- Interactive guided tour for onboarding
- In-page content script for security alerts

## License

This project is licensed under the MIT License.

## Acknowledgments

- Built with [shadcn/ui](https://ui.shadcn.com/) components
- Icons by [Lucide](https://lucide.dev/)
- Color system inspired by modern security practices
- UI/UX designed for accessibility and user-friendliness

