import { defineConfig } from 'wxt';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  srcDir: 'src',
  entrypointsDir: 'entrypoints',
  outDir: '.output',

  manifest: ({ browser }) => ({
    name: 'NetSTAR Scout',
    description:
      'Real-time web risk intelligence from NetSTAR — see how safe a site is before you click.',
    version: '1.0.4',

    permissions: ['activeTab', 'storage', 'tabs', 'scripting'],
    host_permissions: ['<all_urls>'],
    optional_permissions: ['notifications'],

    action: {
      default_icon: {
        16: 'icons/icon-safe-16.png',
        48: 'icons/icon-safe-48.png',
        128: 'icons/icon-safe-128.png',
      },
    },
    icons: {
      16: 'icons/icon-safe-16.png',
      48: 'icons/icon-safe-48.png',
      128: 'icons/icon-safe-128.png',
    },
    web_accessible_resources: [
      {
        resources: [
          'icons/icon-safe-16.png',
          'icons/icon-safe-48.png',
          'icons/icon-safe-128.png',
          'icons/icon-warning-16.png',
          'icons/icon-warning-48.png',
          'icons/icon-warning-128.png',
          'icons/icon-danger-16.png',
          'icons/icon-danger-48.png',
          'icons/icon-danger-128.png',
        ],
        matches: ['<all_urls>'],
      },
    ],

    // Firefox needs a browser_specific_settings.gecko.id for AMO signing.
    // TODO(AMO submission, issue #9): add `data_collection_permissions` once
    // the exact wxt schema is confirmed — Mozilla started requiring this field
    // 2025-11-03 for new listings. Scout will declare websiteContent + URL
    // collection (we send page URLs to the scoring backend).
    ...(browser === 'firefox' && {
      browser_specific_settings: {
        gecko: {
          id: 'scout@netstar.ai',
          strict_min_version: '121.0',
        },
      },
    }),
  }),

  vite: () => ({
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
  }),
});
