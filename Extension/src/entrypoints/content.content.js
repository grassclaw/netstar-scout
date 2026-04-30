// Alert overlay content script. Implementation lives in `../content.js`.

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_idle',
  async main() {
    await import('../content.js');
  },
});
