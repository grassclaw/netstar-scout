function getStatusFromScore(score) {
  if (score >= 90) return "excellent";
  if (score >= 75) return "good";
  if (score >= 60) return "moderate";
  return "poor";
}

function adjustScanOutput(raw) {
    const domain = raw.url;
    const aggregatedScore = raw.aggregatedScore;

    const scores = {
        Connection_Security: raw.Connection_Security,
        Certificate_Health: raw.Certificate_Health,
        DNS_Record_Health: raw.DNS_Record_Health,
        Domain_Reputation: raw.Domain_Reputation,
        Credential_Safety: raw.Credential_Safety,
        WHOIS_Pattern: raw.WHOIS_Pattern
    };

    const indicators = [
        { id: "cert", name: "Certificate Health", score: raw.Certificate_Health, status: null, message: null },
        { id: "connection", name: "Connection Security", score: raw.Connection_Security, status: null, message: null },
        { id: "domain", name: "Domain Reputation", score: raw.Domain_Reputation, status: null, message: null },
        { id: "credentials", name: "Credential Safety", score: raw.Credential_Safety, status: null, message: null },
        { id: "dns", name: "DNS Record Health", score: raw.DNS_Record_Health, status: null, message: null },
        { id: "whois", name: "WHOIS Pattern", score: raw.WHOIS_Pattern, status: null, message: null }
    ];

  indicators.forEach((indicator) => {
    indicator.status = getStatusFromScore(indicator.score);
  });
  
  return {
    domain,
    aggregatedScore,
    scores,
    indicators
  };
}

module.exports = adjustScanOutput;