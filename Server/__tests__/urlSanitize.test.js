const { normalizeScanTarget } = require("../lib/urlSanitize");

// ─── Unit tests for normalizeScanTarget ─────────────────────────────────
// Covers the normalization pipeline and validation rules documented in
// Docs/url-sanitization-policy.md and lib/urlSanitize.js.

describe("normalizeScanTarget", () => {
  // ── Normalization (valid inputs) ────────────────────────────────────

  describe("normalization — valid inputs return { ok: true, domain }", () => {
    it("extracts hostname from a full https URL and lowercases", () => {
      const result = normalizeScanTarget("https://www.Example.COM/path?q=1");
      expect(result).toEqual({ ok: true, domain: "example.com" });
    });

    it("extracts hostname from an http URL", () => {
      const result = normalizeScanTarget("http://Sub.Example.CO.UK/page");
      expect(result).toEqual({ ok: true, domain: "sub.example.co.uk" });
    });

    it("handles a bare domain (no scheme)", () => {
      const result = normalizeScanTarget("example.com");
      expect(result).toEqual({ ok: true, domain: "example.com" });
    });

    it("trims leading and trailing whitespace", () => {
      const result = normalizeScanTarget("  sub.example.co.uk  ");
      expect(result).toEqual({ ok: true, domain: "sub.example.co.uk" });
    });

    it("strips a leading www.", () => {
      const result = normalizeScanTarget("www.example.com");
      expect(result).toEqual({ ok: true, domain: "example.com" });
    });

    it("strips trailing dots", () => {
      const result = normalizeScanTarget("example.com.");
      expect(result).toEqual({ ok: true, domain: "example.com" });
    });

    it("strips trailing dots and www. together", () => {
      const result = normalizeScanTarget("www.example.org.");
      expect(result).toEqual({ ok: true, domain: "example.org" });
    });

    it("lowercases mixed-case bare domains", () => {
      const result = normalizeScanTarget("MyDomain.NET");
      expect(result).toEqual({ ok: true, domain: "mydomain.net" });
    });

    it("handles subdomains", () => {
      const result = normalizeScanTarget("api.v2.example.com");
      expect(result).toEqual({ ok: true, domain: "api.v2.example.com" });
    });
  });

  // ── Blocked: empty / whitespace ─────────────────────────────────────

  describe("blocked — empty or whitespace-only", () => {
    it("rejects an empty string", () => {
      const result = normalizeScanTarget("");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/no domain/i);
    });

    it("rejects whitespace-only string", () => {
      const result = normalizeScanTarget("   ");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/no domain/i);
    });

    it("rejects null (coerced to empty string)", () => {
      const result = normalizeScanTarget(null);
      expect(result.ok).toBe(false);
    });

    it("rejects undefined (coerced to empty string)", () => {
      const result = normalizeScanTarget(undefined);
      expect(result.ok).toBe(false);
    });
  });

  // ── Blocked: malformed URLs ─────────────────────────────────────────

  describe("blocked — malformed URL", () => {
    it("rejects a scheme with no host (https://)", () => {
      const result = normalizeScanTarget("https://");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/malformed|hostname|empty/i);
    });

    it("rejects a completely invalid URL with ://", () => {
      const result = normalizeScanTarget("not://[invalid");
      expect(result.ok).toBe(false);
    });
  });

  // ── Blocked: localhost / loopback ───────────────────────────────────

  describe("blocked — localhost and loopback addresses", () => {
    it.each(["localhost", "127.0.0.1", "::1", "0.0.0.0"])(
      "rejects %s",
      (input) => {
        const result = normalizeScanTarget(input);
        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/localhost|loopback/i);
      }
    );

    it("rejects http://localhost/path", () => {
      const result = normalizeScanTarget("http://localhost/path");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/localhost|loopback/i);
    });

    it("rejects https://127.0.0.1:8080", () => {
      const result = normalizeScanTarget("https://127.0.0.1:8080");
      expect(result.ok).toBe(false);
    });
  });

  // ── Blocked: plain IP addresses ─────────────────────────────────────

  describe("blocked — plain IP addresses", () => {
    it("rejects a private IPv4 address", () => {
      const result = normalizeScanTarget("192.168.1.1");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/ip address/i);
    });

    it("rejects a public IPv4 address", () => {
      const result = normalizeScanTarget("8.8.8.8");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/ip address/i);
    });

    it("rejects 10.0.0.1", () => {
      const result = normalizeScanTarget("10.0.0.1");
      expect(result.ok).toBe(false);
    });

    it("rejects an IPv6-like string", () => {
      const result = normalizeScanTarget("2001:db8::1");
      expect(result.ok).toBe(false);
    });
  });

  // ── Blocked: no letter-based TLD ────────────────────────────────────

  describe("blocked — no recognizable TLD", () => {
    it("rejects a single word with no dot", () => {
      const result = normalizeScanTarget("example");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain/i);
    });

    it("rejects 'notadomain'", () => {
      const result = normalizeScanTarget("notadomain");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain/i);
    });

    it("rejects a domain with only a single-letter TLD", () => {
      const result = normalizeScanTarget("example.x");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain/i);
    });
  });

  // ── Security: dangerous schemes and injection ───────────────────────
  // Verifies that scheme-based injection, host confusion, and payloads
  // in path/fragment do not result in accepting a malicious target.

  describe("security — dangerous schemes and content injection", () => {
    it("rejects javascript: scheme (script injection)", () => {
      const result = normalizeScanTarget("javascript:alert(1)");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain|empty|malformed/i);
    });

    it("rejects data: scheme (data URL / inline content)", () => {
      const result = normalizeScanTarget(
        "data:text/html,<script>alert(1)</script>"
      );
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain|empty|malformed/i);
    });

    it("rejects vbscript: scheme", () => {
      const result = normalizeScanTarget("vbscript:msgbox(1)");
      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/top-level domain|empty|malformed/i);
    });

    it("uses authority host not userinfo (evil.com@good.com → good.com)", () => {
      // URL parsing: part before @ is userinfo, so hostname is good.com.
      // Ensures we scan the real host, not attacker-controlled userinfo.
      const result = normalizeScanTarget("https://evil.com@good.com");
      expect(result).toEqual({ ok: true, domain: "good.com" });
    });

    it("ignores fragment so #@evil.com does not override host", () => {
      const result = normalizeScanTarget("https://good.com#@evil.com");
      expect(result).toEqual({ ok: true, domain: "good.com" });
    });

    it("extracts only hostname — path with script payload is discarded", () => {
      const result = normalizeScanTarget(
        "https://example.com/<script>alert(1)</script>"
      );
      expect(result).toEqual({ ok: true, domain: "example.com" });
    });
  });
});
