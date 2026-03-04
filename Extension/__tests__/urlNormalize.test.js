import { jest } from "@jest/globals";
import { normalizeScanDomain } from "../src/background/urlNormalize.js";

// ─── Unit tests for the Extension's normalizeScanDomain ─────────────────
// This function normalizes URLs/domains for cache keys and API requests.
// It does NOT validate or reject — it always returns a best-effort hostname
// (or ""). Validation is handled by messages.js (TLD check) and the server.
// See Docs/url-sanitization-policy.md for the full policy.

describe("normalizeScanDomain", () => {
  // ── Basic normalization ─────────────────────────────────────────────

  describe("returns a normalized hostname", () => {
    it("extracts hostname from a full https URL", () => {
      expect(normalizeScanDomain("https://www.Example.COM/path?q=1"))
        .toBe("example.com");
    });

    it("extracts hostname from an http URL", () => {
      expect(normalizeScanDomain("http://Sub.Example.CO.UK/page"))
        .toBe("sub.example.co.uk");
    });

    it("handles a bare domain (no scheme)", () => {
      expect(normalizeScanDomain("capitalone.com")).toBe("capitalone.com");
    });

    it("prepends https:// to parse bare domains", () => {
      expect(normalizeScanDomain("example.org")).toBe("example.org");
    });

    it("trims whitespace", () => {
      expect(normalizeScanDomain("  example.com  ")).toBe("example.com");
    });

    it("strips leading www.", () => {
      expect(normalizeScanDomain("www.example.com")).toBe("example.com");
    });

    it("strips trailing dots", () => {
      expect(normalizeScanDomain("example.com.")).toBe("example.com");
    });

    it("lowercases the result", () => {
      expect(normalizeScanDomain("MyDomain.NET")).toBe("mydomain.net");
    });

    it("handles subdomains", () => {
      expect(normalizeScanDomain("api.v2.example.com"))
        .toBe("api.v2.example.com");
    });

    it("strips www. from a full URL", () => {
      expect(normalizeScanDomain("https://www.example.org/page"))
        .toBe("example.org");
    });
  });

  // ── Empty / null / undefined ────────────────────────────────────────

  describe("returns empty string for empty-ish input", () => {
    it("returns '' for empty string", () => {
      expect(normalizeScanDomain("")).toBe("");
    });

    it("returns '' for whitespace-only", () => {
      expect(normalizeScanDomain("   ")).toBe("");
    });

    it("returns '' for null", () => {
      expect(normalizeScanDomain(null)).toBe("");
    });

    it("returns '' for undefined", () => {
      expect(normalizeScanDomain(undefined)).toBe("");
    });
  });

  // ── Fallback behavior (does not reject) ─────────────────────────────

  describe("falls back gracefully for unparseable input", () => {
    it("returns best-effort for a single word (no dot)", () => {
      // URL("https://hello") may succeed or fail depending on runtime;
      // either way the function returns something (not throws).
      const result = normalizeScanDomain("hello");
      expect(typeof result).toBe("string");
    });

    it("does not throw for unusual input", () => {
      expect(() => normalizeScanDomain("://bad")).not.toThrow();
    });
  });

  // ── Parity with server normalization ────────────────────────────────

  describe("produces the same hostname the server would", () => {
    const cases = [
      ["https://www.Example.COM/path", "example.com"],
      ["http://sub.example.co.uk/page", "sub.example.co.uk"],
      ["  example.com  ", "example.com"],
      ["www.example.com", "example.com"],
      ["example.com.", "example.com"],
      ["MyDomain.NET", "mydomain.net"],
    ];

    it.each(cases)("normalizeScanDomain(%s) === %s", (input, expected) => {
      expect(normalizeScanDomain(input)).toBe(expected);
    });
  });
});
