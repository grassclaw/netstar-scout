# NetSTAR Shield — Documentation

This folder contains architecture guides, shared policies, and cross-cutting documentation for the NetSTAR Shield project.

For a full project overview and quick start, see the [root README](../../README.md).

---

## Contents

| Document | Description |
|----------|-------------|
| [extension-server-flow.md](extension-server-flow.md) | How the Chrome extension, Node server, and Python scoring engine work together — data flow, response schema, flavor text, caching guidance. |
| [url-sanitization-policy.md](url-sanitization-policy.md) | Single source of truth for how scan targets are normalized and validated across the Extension, Server, and Scoring Engine. |
| [testing.md](testing.md) | Unified testing guide — how to run tests for every layer and what CI covers. |
| [deployment.md](deployment.md) | Running the server in production — PM2, health checks, environment variables. |

---

## System-Specific Documentation

Each subsystem has its own docs alongside its code:

- **Extension** — [Extension/README.md](../Extension/README.md) (overview and quick start) and [Extension/docs/](../Extension/docs/) (development guide, architecture, theme, caching, content strategy).
- **Server** — [Server/readme.md](../Server/readme.md) (URL sanitization details, test structure).
- **Scoring Engine** — [Scoring Engine/readme.md](../Scoring%20Engine/readme.md) (usage and scoring categories) and [Scoring Engine/TESTING.md](../Scoring%20Engine/TESTING.md) (pytest guide).
