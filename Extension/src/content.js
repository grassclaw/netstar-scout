// Content script for injecting security alerts into web pages

const ALERT_ID = 'netstar-security-alert';
const ALERT_DISMISSED_KEY = 'netstar-alert-dismissed';
const DEBUG = false;

// Function to create the alert overlay
function createAlertOverlay(safetyScore, url) {
  // Remove any existing alert
  removeAlert();
  
  // Check if user has dismissed this alert for this URL
  const dismissedKey = `${ALERT_DISMISSED_KEY}-${url}`;
  const dismissed = sessionStorage.getItem(dismissedKey);
  if (DEBUG) {
    console.log('[NetSTAR] Checking dismissal for URL:', url);
    console.log('[NetSTAR] Dismissal key:', dismissedKey);
    console.log('[NetSTAR] Dismissed status:', dismissed);
  }
  if (dismissed === 'true') {
    if (DEBUG) console.log('[NetSTAR] Alert already dismissed, not showing');
    return; // Don't show if dismissed
  }

  // Determine alert level and styling
  let alertLevel = 'danger';
  let gradientFrom = '#ef4444'; // red-500
  let gradientTo = '#ec4899'; // pink-500
  let emoji = '⚠️';
  let alertTitle = 'Hold On!';
  let alertSubtitle = 'This website might not be safe';
  let alertMessage = 'We found signs of phishing and malware. We recommend leaving this site to protect your information.';
  
  if (safetyScore >= 60 && safetyScore < 75) {
    alertLevel = 'warning';
    gradientFrom = '#f59e0b'; // amber-500
    gradientTo = '#f97316'; // orange-500
    emoji = '⚠️';
    alertTitle = 'Warning';
    alertSubtitle = 'This website has some security concerns';
    alertMessage = 'We detected some security issues with this website. Proceed with caution.';
  } else if (safetyScore < 60) {
    alertLevel = 'danger';
    gradientFrom = '#ef4444'; // red-500
    gradientTo = '#ec4899'; // pink-500
    emoji = '⚠️';
    alertTitle = 'Hold On!';
    alertSubtitle = 'This website might not be safe';
    alertMessage = 'We found signs of phishing and malware. We recommend leaving this site to protect your information.';
  }

  // Create backdrop overlay (transparent, just for click handling)
  const backdrop = document.createElement('div');
  backdrop.id = `${ALERT_ID}-backdrop`;
  backdrop.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 999998;
    background: transparent;
    animation: fadeIn 0.3s ease-out;
  `;
  backdrop.onclick = () => {
    // Close alert when backdrop is clicked
    sessionStorage.setItem(dismissedKey, 'true');
    if (DEBUG) {
      console.log('[NetSTAR] Alert dismissed (backdrop click) for URL:', url);
      console.log('[NetSTAR] SessionStorage key set:', dismissedKey);
    }
    removeAlert();
  };

  // Create the alert container (top-right corner)
  const alertContainer = document.createElement('div');
  alertContainer.id = ALERT_ID;
  alertContainer.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 999999;
    background: linear-gradient(to bottom right, ${gradientFrom}, ${gradientTo});
    color: white;
    padding: 20px;
    border-radius: 16px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    animation: slideInRight 0.3s ease-out;
    max-width: 400px;
    width: calc(100% - 40px);
    max-height: calc(100vh - 40px);
    overflow-y: auto;
    margin: 0;
    box-sizing: border-box;
  `;

  // Add animation keyframes and styles (only once)
  if (!document.getElementById('netstar-alert-styles')) {
    const style = document.createElement('style');
    style.id = 'netstar-alert-styles';
    style.textContent = `
      @keyframes fadeIn {
        from {
          opacity: 0;
        }
        to {
          opacity: 1;
        }
      }
      @keyframes slideInRight {
        from {
          transform: translateX(100%);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
      #${ALERT_ID} {
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        margin: 0 !important;
      }
      #${ALERT_ID}-backdrop {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        bottom: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
      }
      @keyframes bounce {
        0%, 100% {
          transform: translateY(0);
        }
        50% {
          transform: translateY(-10px);
        }
      }
      .netstar-alert-content {
        width: 100%;
      }
      .netstar-alert-header {
        text-align: center;
        margin-bottom: 16px;
      }
      .netstar-alert-emoji {
        font-size: 3rem;
        line-height: 1;
        margin-bottom: 8px;
        animation: bounce 1s infinite;
        display: block;
      }
      .netstar-alert-title {
        font-size: 1.25rem;
        font-weight: 700;
        margin-bottom: 8px;
      }
      .netstar-alert-subtitle {
        font-size: 0.875rem;
        opacity: 0.9;
      }
      .netstar-alert-message-box {
        background: rgba(255, 255, 255, 0.2);
        backdrop-filter: blur(4px);
        border-radius: 12px;
        padding: 12px;
        margin-bottom: 16px;
      }
      .netstar-alert-message {
        font-size: 0.875rem;
      }
      .netstar-alert-actions {
        display: flex;
        gap: 8px;
      }
      .netstar-alert-button {
        flex: 1;
        padding: 8px 16px;
        border: none;
        border-radius: 6px;
        font-size: 0.875rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
        font-family: inherit;
      }
      .netstar-alert-button-primary {
        background: white;
        color: var(--netstar-alert-primary-color, #ef4444);
      }
      .netstar-alert-button-primary:hover {
        background: var(--netstar-alert-primary-hover, #fef2f2);
      }
      .netstar-alert-button-secondary {
        background: transparent;
        color: white;
        border: 1px solid rgba(255, 255, 255, 0.3);
      }
      .netstar-alert-button-secondary:hover {
        background: rgba(255, 255, 255, 0.2);
      }
      .netstar-alert-close {
        position: absolute;
        top: 16px;
        right: 16px;
        background: rgba(0, 0, 0, 0.2);
        border: none;
        color: white;
        font-size: 20px;
        line-height: 1;
        cursor: pointer;
        padding: 6px;
        width: 28px;
        height: 28px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        transition: all 0.2s;
        opacity: 0.9;
        z-index: 1;
      }
      .netstar-alert-close:hover {
        background: rgba(0, 0, 0, 0.3);
        opacity: 1;
        transform: scale(1.1);
      }
    `;
    document.head.appendChild(style);
  }

  // Set CSS custom properties for dynamic colors
  const primaryHoverColor = alertLevel === 'danger' ? '#fef2f2' : '#fffbeb';
  alertContainer.style.setProperty('--netstar-alert-primary-color', gradientFrom);
  alertContainer.style.setProperty('--netstar-alert-primary-hover', primaryHoverColor);

  // Create alert content - matching AlertsTab structure
  const content = document.createElement('div');
  content.className = 'netstar-alert-content';
  // Set position relative on the container for absolute positioning of close button
  alertContainer.style.position = 'relative';

  // Header section with emoji, title, and subtitle
  const header = document.createElement('div');
  header.className = 'netstar-alert-header';
  
  const emojiDiv = document.createElement('div');
  emojiDiv.className = 'netstar-alert-emoji';
  emojiDiv.textContent = emoji;
  
  const title = document.createElement('div');
  title.className = 'netstar-alert-title';
  title.textContent = alertTitle;
  
  const subtitle = document.createElement('div');
  subtitle.className = 'netstar-alert-subtitle';
  subtitle.textContent = alertSubtitle;
  
  header.appendChild(emojiDiv);
  header.appendChild(title);
  header.appendChild(subtitle);

  // Message box
  const messageBox = document.createElement('div');
  messageBox.className = 'netstar-alert-message-box';
  
  const message = document.createElement('div');
  message.className = 'netstar-alert-message';
  message.textContent = alertMessage;
  
  messageBox.appendChild(message);

  // Actions section
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'netstar-alert-actions';

  // Primary button (Take Me Back for danger, or View Details)
  const primaryBtn = document.createElement('button');
  primaryBtn.className = 'netstar-alert-button netstar-alert-button-primary';
  
  if (alertLevel === 'danger') {
    primaryBtn.textContent = 'Take Me Back';
    primaryBtn.onclick = () => {
      window.history.back();
      removeAlert();
    };
  } else {
    primaryBtn.textContent = 'View Details';
    primaryBtn.onclick = () => {
      chrome.runtime.sendMessage({ action: 'highlightExtension' });
      primaryBtn.textContent = 'Click extension icon ↑';
      setTimeout(() => {
        primaryBtn.textContent = 'View Details';
      }, 3000);
    };
  }

  // Secondary button (Tell Me More)
  const secondaryBtn = document.createElement('button');
  secondaryBtn.className = 'netstar-alert-button netstar-alert-button-secondary';
  secondaryBtn.textContent = 'Tell Me More';
  secondaryBtn.onclick = () => {
    chrome.runtime.sendMessage({ action: 'highlightExtension' });
    secondaryBtn.textContent = 'Click extension icon ↑';
    setTimeout(() => {
      secondaryBtn.textContent = 'Tell Me More';
    }, 3000);
  };

  actionsDiv.appendChild(primaryBtn);
  actionsDiv.appendChild(secondaryBtn);

  // Close button (positioned absolutely)
  const closeBtn = document.createElement('button');
  closeBtn.className = 'netstar-alert-close';
  closeBtn.innerHTML = '×';
  closeBtn.title = 'Dismiss alert';
  closeBtn.onclick = () => {
    sessionStorage.setItem(dismissedKey, 'true');
    if (DEBUG) {
      console.log('[NetSTAR] Alert dismissed for URL:', url);
      console.log('[NetSTAR] SessionStorage key set:', dismissedKey);
    }
    removeAlert();
  };

  // Assemble the content
  content.appendChild(header);
  content.appendChild(messageBox);
  content.appendChild(actionsDiv);
  alertContainer.appendChild(content);
  alertContainer.appendChild(closeBtn);
  
  // Prevent clicks inside the modal from closing it
  alertContainer.onclick = (e) => {
    e.stopPropagation();
  };

  // Insert backdrop and modal into body
  // Always append to body (or documentElement) to ensure proper positioning
  if (document.body) {
    document.body.appendChild(backdrop);
    document.body.appendChild(alertContainer);
    
    // Ensure modal is positioned in top-right corner
    setTimeout(() => {
      alertContainer.style.top = '20px';
      alertContainer.style.right = '20px';
    }, 0);
  } else {
    // If body doesn't exist yet, wait for it
    const observer = new MutationObserver((mutations, obs) => {
      if (document.body) {
        document.body.appendChild(backdrop);
        document.body.appendChild(alertContainer);
        
        setTimeout(() => {
          alertContainer.style.top = '20px';
          alertContainer.style.right = '20px';
        }, 0);
        
        obs.disconnect();
      }
    });
    observer.observe(document.documentElement, { childList: true });
  }
}

// Function to remove the alert
function removeAlert() {
  const existingAlert = document.getElementById(ALERT_ID);
  const existingBackdrop = document.getElementById(`${ALERT_ID}-backdrop`);
  if (existingAlert) {
    existingAlert.remove();
  }
  if (existingBackdrop) {
    existingBackdrop.remove();
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showAlert') {
    createAlertOverlay(request.safetyScore, request.url);
    sendResponse({ success: true });
  } else if (request.action === 'hideAlert') {
    removeAlert();
    sendResponse({ success: true });
  }
  return true;
});

// Clean up alert when navigating away
window.addEventListener('beforeunload', () => {
  removeAlert();
});

// Also handle SPA navigation (for single-page apps)
let lastUrl = location.href;

// Use multiple methods to detect URL changes for better reliability
function checkUrlChange() {
  const currentUrl = location.href;
  if (currentUrl !== lastUrl) {
    const previousUrl = lastUrl;
    lastUrl = currentUrl;
    
    // Only clear the dismissal for the previous URL, not all dismissals
    if (previousUrl) {
      const previousDismissedKey = `${ALERT_DISMISSED_KEY}-${previousUrl}`;
      sessionStorage.removeItem(previousDismissedKey);
    }
    removeAlert();
  }
}

// Listen for popstate (back/forward navigation)
window.addEventListener('popstate', checkUrlChange);

// Listen for hashchange
window.addEventListener('hashchange', checkUrlChange);

// Use MutationObserver as a fallback, but throttle it
let mutationTimeout;
new MutationObserver(() => {
  // Throttle checks to avoid excessive clearing
  clearTimeout(mutationTimeout);
  mutationTimeout = setTimeout(checkUrlChange, 100);
}).observe(document, { subtree: true, childList: true });

