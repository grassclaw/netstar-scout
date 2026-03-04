# Deployment

This document covers running the NetSTAR Shield server in a production or staging environment.

---

## Production Server

The main application server lives in `Server/server.js`. It is a standard Node/Express app.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port the Express server listens on. |
| `USE_SCORING_TEST_DATA` | *(unset)* | When set to `"1"`, the scoring engine uses built-in test data instead of calling external APIs. Used in CI. |

### Starting the Server

```bash
cd Server
npm install
node server.js
```

For persistent production use, run with a process manager like **PM2** so the server restarts automatically on crashes or reboots.

---

## Remote / Test Server

A standalone deployment configuration (with PM2 recipes, health-check URLs, and Nginx notes) is documented in the test server folder:

**[test server/SERVER_MANAGEMENT.md](../test%20server/SERVER_MANAGEMENT.md)**

That guide covers:

- Health-check endpoints (`/health`, `/`)
- Starting with PM2 (`pm2 start`, `pm2 save`, `pm2 startup`)
- Viewing logs and restarting
- Remote server IP and access

---

## Extension Distribution

The Chrome extension is built locally and loaded as an unpacked extension during development. For Chrome Web Store distribution:

```bash
cd Extension
npm run pack
```

This runs `vite build` and zips the `dist/` folder into `netstar-shield-webstore.zip`.

---

## Scoring Engine

The scoring engine does not run as a standalone service. The Node server spawns `scoring_main.py` as a subprocess on each `/scan` request. Ensure Python 3 and the scoring engine dependencies are installed on the same machine as the server:

```bash
cd "Scoring Engine"
pip install -r requirements.txt
```

The server resolves the path to `scoring_main.py` relative to its own directory.
