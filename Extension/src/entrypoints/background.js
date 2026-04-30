// Background service worker entry point for NetSTAR Scout (MV3).
// Implementation lives in `src/background/*`. wxt picks this up automatically.

import { registerInstallListener } from "../background/install.js";
import { registerTabListeners } from "../background/tabs.js";
import { registerMessageListeners } from "../background/messages.js";

export default defineBackground(() => {
  registerInstallListener();
  registerTabListeners();
  registerMessageListeners();
});
