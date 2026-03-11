# Bill of Materials

| Field | Value |
|-------|-------|
| Artifact ID | ART-021 |
| Artifact Title | Project Management |
| Revision | 01 |
| Revision Date | 25 FEB 2026 |
| Prepared by | Tate McCauley |
| Checked by | Cam Gedris |
| Purpose | Preview of future work plans from our Jira instance |

---

## Bill of Materials

### Deliverables

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 1 | Chrome Extension (netstar-extension) | 1 | React 19, MV3; popup, background, content script |
| 2 | Node.js Server (Express API) | 1 | `/scan` endpoint; validates targets, spawns scoring engine |
| 3 | Python Scoring Engine | 1 | scoring_main.py, score_engine.py, data_fetch.py, scoring_logic.py |

### Runtime / Prerequisites

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 4 | Node.js | 1 | v18+ required (Extension + Server) |
| 5 | Python | 1 | 3.x required (Scoring Engine) |
| 6 | Chrome / Chromium browser | 1 | Edge, Brave, etc. for Extension |

### Extension — Production Dependencies

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 7 | react | 19.1.0 | UI framework |
| 8 | react-dom | 19.1.0 | React DOM renderer |
| 9 | @radix-ui/react-progress, react-slot, react-switch | 3 | Accessible UI primitives |
| 10 | lucide-react | ^0.552.0 | Icons |
| 11 | tailwind-merge, tailwind-scrollbar, tailwindcss-animate | 3 | Styling utilities |
| 12 | class-variance-authority, clsx | 2 | Component styling (cva/clsx) |

### Extension — Build / Dev Dependencies

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 13 | Vite | ^5.4.21 | Build tool |
| 14 | @crxjs/vite-plugin | ^2.2.0 | Chrome extension build |
| 15 | @vitejs/plugin-react | ^4.3.1 | React HMR/build |
| 16 | Tailwind CSS, PostCSS, Autoprefixer | 3 | Styles (Tailwind ^4.1.17) |
| 17 | Jest | ^30.2.0 | Unit tests |
| 18 | JSDoc | ^4.0.5 | Documentation |

### Server — Dependencies

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 19 | express | ^5.1.0 | HTTP API |
| 20 | jest, supertest | 2 | Testing (dev) |

### Scoring Engine — Dependencies

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 21 | Python standard library + curl | — | Telemetry (cert, DNS, RDAP, etc.) via curl |
| 22 | pytest, pytest-cov, pytest-mock | 3 | Testing (requirements.txt) |

### Documentation

| Item # | Part / Description | Quantity | Notes |
|--------|--------------------|----------|-------|
| 23 | Docs (deployment, testing, url-sanitization-policy, extension-server-flow) | 4+ | NetSTAR-Shield/Docs |
| 24 | Extension docs (architecture, development, theme, content, caching) | 5+ | Extension/docs |
| 25 | READMEs (project, Extension, Server, Scoring Engine) | 4 | Top-level and per-component |
