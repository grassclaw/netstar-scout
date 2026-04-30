// Live DOM signal extraction content script (Phase 7).
// Implementation lives in `../content-inspect.js` — runs as an IIFE on import.

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_idle',
  async main() {
    await import('../content-inspect.js');
  },
});
