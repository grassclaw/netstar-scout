import { jest, describe, it, expect, beforeEach, afterEach } from "@jest/globals";

// ─── Mocks ─────────────────────────────────────────────────────────────
// We use jest.unstable_mockModule for ESM. Constants are mocked with a
// short timeout so the abort test completes quickly.

const TEST_TIMEOUT_MS = 200;

jest.unstable_mockModule("../src/background/constants.js", () => ({
  SCAN_API_BASE: "http://test-server:3000",
  CACHE_DURATION_MS: 300_000,
  SCAN_FETCH_TIMEOUT_MS: TEST_TIMEOUT_MS,
}));

// The urlNormalize module is real (no mock needed).

// Global chrome mock — getCachedOrScan uses chrome.storage.local
const storageBacking = {};
globalThis.chrome = {
  storage: {
    local: {
      get: jest.fn((key) => {
        const k = typeof key === "string" ? key : Object.keys(key)[0];
        return Promise.resolve(k in storageBacking ? { [k]: storageBacking[k] } : {});
      }),
      set: jest.fn((obj) => {
        Object.assign(storageBacking, obj);
        return Promise.resolve();
      }),
      remove: jest.fn((key) => {
        delete storageBacking[key];
        return Promise.resolve();
      }),
    },
  },
};

// Import after mocks are registered
const { performSecurityScan, getCachedOrScan } = await import(
  "../src/background/scan.js"
);

// ─── Helpers ───────────────────────────────────────────────────────────

function mockFetchResponse(body, { ok = true, status = 200 } = {}) {
  globalThis.fetch = jest.fn(() =>
    Promise.resolve({
      ok,
      status,
      json: () => Promise.resolve(body),
    })
  );
}

function clearStorageBacking() {
  for (const key of Object.keys(storageBacking)) delete storageBacking[key];
}

// ─── Tests ─────────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  clearStorageBacking();
});

// ═══ performSecurityScan ═══════════════════════════════════════════════

describe("performSecurityScan", () => {
  it("returns { safetyScore, indicators, timestamp } on success", async () => {
    mockFetchResponse({ safetyScore: 85, indicators: [{ id: "cert" }] });

    const result = await performSecurityScan("https://www.example.com/path");

    expect(result).toEqual(
      expect.objectContaining({
        safetyScore: 85,
        indicators: [{ id: "cert" }],
      })
    );
    expect(typeof result.timestamp).toBe("number");
  });

  it("uses the normalized domain in the fetch URL", async () => {
    mockFetchResponse({ safetyScore: 90, indicators: [] });

    await performSecurityScan("https://www.Example.COM/page?q=1");

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const url = globalThis.fetch.mock.calls[0][0];
    expect(url).toContain("domain=example.com");
    expect(url).not.toContain("www.");
  });

  it("falls back to aggregatedScore when safetyScore is missing", async () => {
    mockFetchResponse({ aggregatedScore: 70, indicators: [] });

    const result = await performSecurityScan("example.com");

    expect(result.safetyScore).toBe(70);
  });

  it("rejects with a timeout error when fetch never resolves", async () => {
    globalThis.fetch = jest.fn(
      () => new Promise((_, reject) => {
        // Listen for the abort signal to reject, like a real fetch would.
        const opts = globalThis.fetch.mock.calls[0]?.[1];
        if (opts?.signal) {
          opts.signal.addEventListener("abort", () =>
            reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }))
          );
        }
      })
    );

    await expect(performSecurityScan("example.com")).rejects.toThrow(
      /timed out/i
    );
  }, TEST_TIMEOUT_MS + 5000);

  it("rejects with the original error on network failure", async () => {
    globalThis.fetch = jest.fn(() => Promise.reject(new Error("Network down")));

    await expect(performSecurityScan("example.com")).rejects.toThrow(
      "Network down"
    );
  });

  it("passes an AbortSignal to fetch", async () => {
    mockFetchResponse({ safetyScore: 50, indicators: [] });

    await performSecurityScan("example.com");

    const opts = globalThis.fetch.mock.calls[0][1];
    expect(opts).toBeDefined();
    expect(opts.signal).toBeInstanceOf(AbortSignal);
  });
});

// ═══ getCachedOrScan ═══════════════════════════════════════════════════

describe("getCachedOrScan", () => {
  it("returns cached data on cache hit (no fetch)", async () => {
    const cached = {
      safetyScore: 92,
      indicators: [],
      timestamp: Date.now(),
    };
    const cacheKey = "scan_example.com";
    storageBacking[cacheKey] = cached;

    globalThis.fetch = jest.fn();

    const result = await getCachedOrScan("https://www.example.com");

    expect(result).toEqual(cached);
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(chrome.storage.local.set).not.toHaveBeenCalled();
  });

  it("fetches and caches on cache miss", async () => {
    mockFetchResponse({ safetyScore: 77, indicators: [{ id: "dns" }] });

    const result = await getCachedOrScan("https://example.com");

    expect(result.safetyScore).toBe(77);
    expect(result.indicators).toEqual([{ id: "dns" }]);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(chrome.storage.local.set).toHaveBeenCalledTimes(1);

    const setArg = chrome.storage.local.set.mock.calls[0][0];
    expect(Object.keys(setArg)[0]).toBe("scan_example.com");
  });

  it("removes expired cache and fetches fresh data", async () => {
    const expired = {
      safetyScore: 50,
      indicators: [],
      timestamp: Date.now() - 600_000, // 10 min ago, well past 5 min TTL
    };
    storageBacking["scan_example.com"] = expired;

    mockFetchResponse({ safetyScore: 88, indicators: [] });

    const result = await getCachedOrScan("https://example.com");

    expect(chrome.storage.local.remove).toHaveBeenCalledWith("scan_example.com");
    expect(result.safetyScore).toBe(88);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("deduplicates concurrent in-flight requests", async () => {
    let resolveFetch;
    globalThis.fetch = jest.fn(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve;
        })
    );

    // Launch both before awaiting either — storage.get is async so we need
    // to let microtasks drain so both calls reach the in-flight check.
    const p1 = getCachedOrScan("https://example.com");
    const p2 = getCachedOrScan("https://example.com");

    // Wait a tick so the async storage calls resolve and fetch is invoked
    await new Promise((r) => setTimeout(r, 50));

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    resolveFetch({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ safetyScore: 60, indicators: [] }),
    });

    const [r1, r2] = await Promise.all([p1, p2]);

    expect(r1.safetyScore).toBe(60);
    expect(r2.safetyScore).toBe(60);
    expect(r1).toBe(r2);
  });
});
