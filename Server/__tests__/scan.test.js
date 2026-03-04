const request = require("supertest");

// ─── Mock child_process.spawn ──────────────────────────────────────────
// We mock spawn so the Python scoring engine is never actually executed.
// Each test configures `mockSpawnBehavior` to control what the mock child
// process emits. The mock child is created *inside* spawn() so that
// event scheduling happens after the handler attaches listeners.

let mockSpawnBehavior = { stdout: "{}", stderr: "", exitCode: 0 };

jest.mock("child_process", () => ({
  spawn: jest.fn(() => {
    // Must require inside factory — Jest forbids out-of-scope references.
    const { EventEmitter } = require("events");
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = jest.fn();

    const { stdout, stderr, exitCode } = mockSpawnBehavior;

    // Schedule events after the caller has attached listeners.
    // spawn() → caller attaches .once("spawn") → setImmediate fires.
    setImmediate(() => {
      child.emit("spawn");
      setImmediate(() => {
        if (stdout) child.stdout.emit("data", Buffer.from(stdout));
        if (stderr) child.stderr.emit("data", Buffer.from(stderr));
        setImmediate(() => {
          child.emit("close", exitCode);
        });
      });
    });

    return child;
  }),
}));

// Also mock fs.existsSync so resolvePythonScript() finds a "script"
jest.mock("fs", () => {
  const originalFs = jest.requireActual("fs");
  return {
    ...originalFs,
    existsSync: jest.fn((p) => {
      // Return true for any scoring_main.py path so the handler proceeds
      if (typeof p === "string" && p.includes("scoring_main.py")) return true;
      return originalFs.existsSync(p);
    }),
  };
});

const { app } = require("../server");

// ─── Tests ─────────────────────────────────────────────────────────────

describe("GET /scan", () => {
  // ── 400 responses: blocked by normalizeScanTarget ──────────────────

  describe("returns 400 for blocked inputs", () => {
    it("rejects when no domain/url is provided", async () => {
      const res = await request(app).get("/scan").expect(400);
      expect(res.body.error).toBe(true);
      expect(res.body.message).toMatch(/no domain/i);
    });

    it("rejects localhost", async () => {
      const res = await request(app).get("/scan?domain=localhost").expect(400);
      expect(res.body.error).toBe(true);
      expect(res.body.message).toMatch(/localhost|loopback/i);
    });

    it("rejects 127.0.0.1", async () => {
      const res = await request(app).get("/scan?domain=127.0.0.1").expect(400);
      expect(res.body.error).toBe(true);
    });

    it("rejects a plain IPv4 address", async () => {
      const res = await request(app).get("/scan?domain=192.168.1.1").expect(400);
      expect(res.body.error).toBe(true);
      expect(res.body.message).toMatch(/ip address/i);
    });

    it("rejects input without a TLD", async () => {
      const res = await request(app).get("/scan?domain=notadomain").expect(400);
      expect(res.body.error).toBe(true);
      expect(res.body.message).toMatch(/top-level domain/i);
    });

    it("rejects http://localhost/path via ?url=", async () => {
      const res = await request(app)
        .get("/scan?url=" + encodeURIComponent("http://localhost/path"))
        .expect(400);
      expect(res.body.error).toBe(true);
    });

    it("returns the expected JSON shape on 400", async () => {
      const res = await request(app).get("/scan?domain=localhost").expect(400);
      expect(res.body).toHaveProperty("error", true);
      expect(res.body).toHaveProperty("message");
      expect(res.body).toHaveProperty("safetyScore", 0);
      expect(res.body).toHaveProperty("aggregatedScore", 0);
      expect(res.body).toHaveProperty("indicators");
      expect(res.body).toHaveProperty("timestamp");
    });
  });

  // ── 200 response: valid domain with mocked scoring engine ──────────

  describe("returns 200 for valid domains (mocked scoring engine)", () => {
    const MOCK_SCORING_OUTPUT = JSON.stringify({
      Connection_Security: 85,
      Certificate_Health: 90,
      DNS_Record_Health: 80,
      Domain_Reputation: 75,
      Credential_Safety: 70,
      aggregatedScore: 80,
    });

    beforeEach(() => {
      mockSpawnBehavior = { stdout: MOCK_SCORING_OUTPUT, stderr: "", exitCode: 0 };
    });

    it("returns 200 with safetyScore for a valid domain", async () => {
      const res = await request(app)
        .get("/scan?domain=example.com")
        .expect(200);

      expect(res.body).toHaveProperty("safetyScore");
      expect(typeof res.body.safetyScore).toBe("number");
      expect(res.body).toHaveProperty("aggregatedScore");
      expect(res.body).toHaveProperty("indicators");
      expect(Array.isArray(res.body.indicators)).toBe(true);
      expect(res.body).toHaveProperty("timestamp");
    });

    it("returns 200 with correct aggregated score", async () => {
      const res = await request(app)
        .get("/scan?domain=example.com")
        .expect(200);

      expect(res.body.safetyScore).toBe(80);
      expect(res.body.aggregatedScore).toBe(80);
    });

    it("returns indicators array with expected structure", async () => {
      const res = await request(app)
        .get("/scan?domain=example.com")
        .expect(200);

      for (const indicator of res.body.indicators) {
        expect(indicator).toHaveProperty("id");
        expect(indicator).toHaveProperty("name");
        expect(indicator).toHaveProperty("score");
        expect(indicator).toHaveProperty("status");
      }
    });

    it("handles ?url= with a full URL that resolves to a valid domain", async () => {
      const res = await request(app)
        .get("/scan?url=" + encodeURIComponent("https://www.example.com/page"))
        .expect(200);

      expect(res.body.safetyScore).toBe(80);
    });
  });

  // ── Scoring engine failure paths ───────────────────────────────────

  describe("handles scoring engine failures gracefully", () => {
    it("returns 500 when scoring engine exits with non-zero code", async () => {
      mockSpawnBehavior = { stdout: "", stderr: "Traceback: some error", exitCode: 1 };
      const res = await request(app)
        .get("/scan?domain=example.com")
        .expect(500);

      expect(res.body.error).toBe(true);
      expect(res.body.safetyScore).toBe(0);
    });

    it("returns 500 when scoring engine outputs invalid JSON", async () => {
      mockSpawnBehavior = { stdout: "not valid json at all", stderr: "", exitCode: 0 };
      const res = await request(app)
        .get("/scan?domain=example.com")
        .expect(500);

      expect(res.body.error).toBe(true);
      expect(res.body.message).toMatch(/parse|json/i);
    });
  });
});
