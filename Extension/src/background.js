// Background service worker entrypoint for NetSTAR extension (MV3).
//
// This file intentionally stays small. Implementation lives in `src/background/*`.

import { registerInstallListener } from "./background/install.js";
import { registerTabListeners } from "./background/tabs.js";
import { registerMessageListeners } from "./background/messages.js";

registerInstallListener();
registerTabListeners();
registerMessageListeners();
