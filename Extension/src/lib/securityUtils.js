/**
 * Security-related utility functions
 */

/**
 * Determines security status based on a numerical score
 * @param {number} score - Security score (0-100)
 * @returns {string} Status: "excellent", "good", "moderate", or "poor"
 */
export function getStatusFromScore(score) {
  if (score >= 90) return "excellent"
  if (score >= 75) return "good"
  if (score >= 60) return "moderate"
  return "poor"
}

/**
 * Gets user-friendly status message
 * @param {string} status - Status: "excellent", "good", "moderate", or "poor"
 * @returns {string} User-friendly message
 */
export function getStatusMessage(status) {
  switch (status) {
    case "excellent":
      return "Looking great!"
    case "good":
      return "All good"
    case "moderate":
      return "Could be better"
    case "poor":
      return "Needs attention"
    default:
      return "Unknown"
  }
}

/**
 * Gets detailed status message for score cards
 * @param {string} status - Status: "excellent", "good", "moderate", or "poor"
 * @returns {string} Detailed message
 */
export function getDetailedStatusMessage(status) {
  switch (status) {
    case "excellent":
      return "You\'re Safe Here!"
    case "good":
      return "You Should Be Confident!"
    case "moderate":
      return "You Should Take Some Precaution."
    case "poor":
      return "You Might Not Be Safe."
    default:
      return "Unknown status"
  }
}

