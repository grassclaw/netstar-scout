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

    // Firefox-specific manifest. AMO has required data_collection_permissions
    // for new listings since 2025-11-03.
    //
    // Scout's data flow once threat-mcp wires in (post-launch):
    //   - URL of visited tab     → sent to /api/v1/scan/lite  (browsingActivity)
    //   - DOM signals from page  → sent in scan request body  (websiteContent)
    //
    // Currently in placeholder mode we transmit nothing, but AMO listings
    // describe what the extension *can* do across versions, not what the
    // current build does — so declare both upfront to avoid a re-review when
    // the real backend lands.
    ...(browser === 'firefox' && {
      browser_specific_settings: {
        gecko: {
          id: 'scout@netstar.ai',
          strict_min_version: '121.0',
          // wxt's manifest type doesn't yet know about this field; cast loose.
          data_collection_permissions: {
            required: ['websiteContent', 'browsingActivity'],
          } as any,
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
