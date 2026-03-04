"""
Unit tests for score_engine.py

This test suite provides comprehensive coverage for all scoring functions
in the NetSTAR security scoring engine.

Run tests with:
    pytest test_score_engine.py -v
    pytest test_score_engine.py --cov=score_engine --cov-report=html
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json
import subprocess

# Import the module to test
import score_engine


# ============================================================================
# FIXTURES - Reusable test data
# ============================================================================

@pytest.fixture
def valid_cert_data():
    """Valid certificate data with 60 days until expiration"""
    return {
        "certs": [{
            "not_after": "2025-12-15T20:07:01Z",
            "not_before": "2025-09-16T20:11:24Z"
        }],
        "connection": {},
        "verification": {"hostname_matches": True, "chain_verified": True}
    }


@pytest.fixture
def expired_cert_data():
    """Expired certificate data"""
    return {
        "certs": [{
            "not_after": "2020-01-01T00:00:00Z",
            "not_before": "2019-01-01T00:00:00Z"
        }],
        "connection": {},
        "verification": {"hostname_matches": True, "chain_verified": True}
    }


@pytest.fixture
def optimal_dns_data():
    """Optimal DNS configuration with redundancy"""
    return {
        "rcode": 31,
        "a": ["162.159.153.4", "162.159.152.4"],
        "aaaa": ["2606:4700:7::a29f:9804", "2606:4700:7::a29f:9904"]
    }


@pytest.fixture
def poor_dns_data():
    """Poor DNS configuration - single A record, no IPv6"""
    return {
        "rcode": 1,
        "a": ["192.168.1.1"],
        "aaaa": []
    }


@pytest.fixture
def optimal_hval_data():
    """Optimal HVAL scan - HTTPS enforced, modern TLS, all security headers"""
    return {
        "head": [
            {"status": 301, "url": "http://example.com"},
            {"status": 200, "url": "https://example.com/", "tls": "TLS_AES_128_GCM_SHA256"}
        ],
        "n": 2,
        "security": 127  # HSTS (1) + CSP (2) + XCTO (4) + ACAO (8) + COOP (16) + CORP (32) + COEP (64)
    }


@pytest.fixture
def poor_hval_data():
    """Poor HVAL scan - HTTP only, no security headers"""
    return {
        "head": [
            {"status": 200, "url": "http://example.com", "tls": "NONE"}
        ],
        "n": 1,
        "security": 0
    }


@pytest.fixture
def optimal_mail_data():
    """Optimal mail configuration - DMARC reject, SPF hardfail, MX redundancy"""
    return {
        "mx": ["mx1.example.com", "mx2.example.com", "mx3.example.com"],
        "spf": ["v=spf1 include:_spf.example.com -all"],
        "dmarc": ["v=DMARC1; p=reject; sp=reject; pct=100"]
    }


@pytest.fixture
def poor_mail_data():
    """Poor mail configuration - no DMARC, weak SPF, single MX"""
    return {
        "mx": ["mx1.example.com"],
        "spf": ["v=spf1 +all"],
        "dmarc": []
    }


@pytest.fixture
def optimal_method_data():
    """Optimal method scan - only HEAD and GET"""
    return {
        "flag": 3  # HEAD (1) + GET (2)
    }


@pytest.fixture
def dangerous_method_data():
    """Dangerous method scan - PUT, DELETE, TRACE enabled"""
    return {
        "flag": 111  # Multiple dangerous methods
    }


@pytest.fixture
def optimal_rdap_data():
    """Optimal RDAP - multiple nameservers, diverse vendors"""
    return {
        "nameserver": [
            "ns1.google.com",
            "ns2.google.com",
            "ns1.cloudflare.com",
            "ns2.cloudflare.com"
        ]
    }


@pytest.fixture
def poor_rdap_data():
    """Poor RDAP - single nameserver"""
    return {
        "nameserver": ["ns1.example.com"]
    }


@pytest.fixture
def scan_date():
    """Fixed scan date for reproducible tests"""
    return datetime(2025, 10, 15)


@pytest.fixture
def base_scores():
    """Base scores dictionary initialized to 100"""
    return {
        'Connection_Security': 100,
        'Certificate_Health': 100,
        'DNS_Record_Health': 100,
        'Domain_Reputation': 100,
        'WHOIS_Pattern': 100,
        'IP_Reputation': 100,
        'Credential_Safety': 100
    }


# ============================================================================
# CERTIFICATE SCORING TESTS
# ============================================================================

class TestCertScoring:
    """Tests for score_cert_health() function"""
    
    def test_valid_cert_good_expiration(self, valid_cert_data, scan_date, base_scores):
        """Test valid certificate with good expiration (60+ days)"""
        score_engine.score_cert_health(valid_cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] == 100, "Valid cert with 60+ days should not be deducted"
    
    def test_expired_cert(self, expired_cert_data, scan_date, base_scores):
        """Test expired certificate gets major deduction"""
        score_engine.score_cert_health(expired_cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 50, "Expired certificate should get -50 deduction"
    
    def test_cert_expiring_soon_15_days(self, scan_date, base_scores):
        """Test certificate expiring in 15 days gets appropriate deduction"""
        cert_data = {
            "certs": [{
                "not_after": (scan_date + timedelta(days=15)).isoformat() + "Z",
                "not_before": (scan_date - timedelta(days=60)).isoformat() + "Z"
            }],
            "connection": {},
            "verification": {"hostname_matches": True, "chain_verified": True}
        }
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        # 15 days should result in gradient deduction
        assert 75 <= base_scores['Certificate_Health'] <= 90, f"Cert expiring in 15 days should be ~85, got {base_scores['Certificate_Health']}"
    
    def test_cert_expiring_very_soon_5_days(self, scan_date, base_scores):
        """Test certificate expiring in 5 days gets heavy deduction"""
        cert_data = {
            "certs": [{
                "not_after": (scan_date + timedelta(days=5)).isoformat() + "Z",
                "not_before": (scan_date - timedelta(days=60)).isoformat() + "Z"
            }],
            "connection": {},
            "verification": {"hostname_matches": True, "chain_verified": True}
        }
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        # 5 days should result in heavy gradient deduction
        assert 65 <= base_scores['Certificate_Health'] <= 80, f"Cert expiring in 5 days should be ~75, got {base_scores['Certificate_Health']}"
    
    def test_missing_cert_data(self, scan_date, base_scores):
        """Test missing certificate data gets deduction"""
        score_engine.score_cert_health({"certs": [], "connection": {}, "verification": {}}, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 50, "Missing cert data should get -50 deduction"
    
    def test_malformed_cert_dates(self, scan_date, base_scores):
        """Test malformed date fields get deduction"""
        cert_data = {
            "certs": [{
                "not_after": "invalid-date",
                "not_before": "2025-01-01T00:00:00Z"
            }],
            "connection": {},
            "verification": {"hostname_matches": True, "chain_verified": True}
        }
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 92, "Malformed cert dates should get deduction"
    
    def test_cert_not_yet_valid(self, scan_date, base_scores):
        """Test certificate not yet valid gets deduction"""
        cert_data = {
            "certs": [{
                "not_after": (scan_date + timedelta(days=365)).isoformat() + "Z",
                "not_before": (scan_date + timedelta(days=1)).isoformat() + "Z"
            }],
            "connection": {},
            "verification": {"hostname_matches": True, "chain_verified": True}
        }
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 50, "Cert not yet valid should get -50 deduction"
    
    def test_hostname_mismatch(self, valid_cert_data, scan_date, base_scores):
        """Test hostname mismatch gets deduction"""
        cert_data = valid_cert_data.copy()
        cert_data["verification"] = {"hostname_matches": False, "chain_verified": True}
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 90, "Hostname mismatch should get -10 deduction"
    
    def test_chain_not_verified(self, valid_cert_data, scan_date, base_scores):
        """Test certificate chain not verified gets deduction"""
        cert_data = valid_cert_data.copy()
        cert_data["verification"] = {"hostname_matches": True, "chain_verified": False}
        score_engine.score_cert_health(cert_data, scan_date, base_scores)
        assert base_scores['Certificate_Health'] <= 90, "Chain not verified should get -10 deduction"


# ============================================================================
# DNS SCORING TESTS
# ============================================================================

class TestDNSScoring:
    """Tests for score_dns_rec_health() function"""
    
    def test_optimal_dns_config(self, optimal_dns_data, base_scores):
        """Test optimal DNS configuration has no deductions"""
        score_engine.score_dns_rec_health(optimal_dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 100, "Optimal DNS should not be deducted"
    
    def test_poor_dns_config(self, poor_dns_data, base_scores):
        """Test poor DNS configuration gets appropriate deductions"""
        score_engine.score_dns_rec_health(poor_dns_data, {}, base_scores)
        # Should have deductions for: low rcode (-15), single A (-10), no IPv6 (-5)
        assert base_scores['DNS_Record_Health'] <= 75, f"Poor DNS should be <= 75, got {base_scores['DNS_Record_Health']}"
    
    def test_no_ipv6_support(self, base_scores):
        """Test DNS without IPv6 gets minor deduction"""
        dns_data = {
            "rcode": 31,
            "a": ["1.1.1.1", "1.0.0.1"],
            "aaaa": []
        }
        score_engine.score_dns_rec_health(dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 95, "No IPv6 should result in -5 deduction"
    
    def test_single_a_record(self, base_scores):
        """Test single A record (SPOF) gets deduction"""
        dns_data = {
            "rcode": 31,
            "a": ["1.1.1.1"],
            "aaaa": ["2606:4700:4700::1111", "2606:4700:4700::1001"]
        }
        score_engine.score_dns_rec_health(dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 90, "Single A record should result in -10 deduction"
    
    def test_single_aaaa_record(self, base_scores):
        """Test single AAAA record gets minor deduction"""
        dns_data = {
            "rcode": 31,
            "a": ["1.1.1.1", "1.0.0.1"],
            "aaaa": ["2606:4700:4700::1111"]
        }
        score_engine.score_dns_rec_health(dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 95, "Single AAAA record should result in -5 deduction"
    
    def test_incomplete_rcode_mid_range(self, base_scores):
        """Test incomplete rcode in 8-30 range gets appropriate deduction"""
        dns_data = {
            "rcode": 15,  # Between 8-30
            "a": ["1.1.1.1", "1.0.0.1"],
            "aaaa": ["2606:4700:4700::1111", "2606:4700:4700::1001"]
        }
        score_engine.score_dns_rec_health(dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 90, "Incomplete rcode (8-30) should result in -10 deduction"
    
    def test_low_rcode_1_7_range(self, base_scores):
        """Test low rcode in 1-7 range gets significant deduction"""
        dns_data = {
            "rcode": 3,  # Between 1-7
            "a": ["1.1.1.1", "1.0.0.1"],
            "aaaa": ["2606:4700:4700::1111", "2606:4700:4700::1001"]
        }
        score_engine.score_dns_rec_health(dns_data, {}, base_scores)
        assert base_scores['DNS_Record_Health'] == 85, "Low rcode (1-7) should result in -15 deduction"


# ============================================================================
# HVAL SCORING TESTS
# ============================================================================

class TestHVALScoring:
    """Tests for score_conn_sec() function"""
    
    def test_optimal_hval_config(self, optimal_hval_data, base_scores):
        """Test optimal HVAL configuration has no deductions"""
        cert_data = {"connection": {"tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}, "certs": []}
        score_engine.score_conn_sec(optimal_hval_data, cert_data, base_scores)
        assert base_scores['Connection_Security'] == 100, "Optimal HVAL should not be deducted"
    
    def test_http_only_site(self, poor_hval_data, base_scores):
        """Test HTTP-only site gets major deduction"""
        cert_data = {"connection": {"tls_version": "TLS 1.1"}, "certs": []}
        score_engine.score_conn_sec(poor_hval_data, cert_data, base_scores)
        # Should have major deductions for not HTTPS and missing headers
        assert base_scores['Connection_Security'] <= 45, f"HTTP-only site should score very low, got {base_scores['Connection_Security']}"
    
    def test_missing_one_critical_header(self, base_scores):
        """Test missing one critical security header"""
        hval_data = {
            "head": [
                {"status": 200, "url": "https://example.com/", "tls": "TLS_AES_128_GCM_SHA256"}
            ],
            "security": 3  # HSTS (1) + CSP (2), missing XCTO (4)
        }
        cert_data = {"connection": {"tls_version": "TLS 1.3"}, "certs": []}
        score_engine.score_conn_sec(hval_data, cert_data, base_scores)
        assert base_scores['Connection_Security'] <= 80, "Missing one critical header should get -20 deduction"
    
    def test_weak_cipher_suite(self, base_scores):
        """Test weak cipher suite gets deduction"""
        hval_data = {
            "head": [
                {"status": 200, "url": "https://example.com/", "tls": "DES_CBC_SHA"}
            ],
            "security": 7  # All critical headers present
        }
        cert_data = {"connection": {"tls_version": "TLS 1.3"}, "certs": []}
        score_engine.score_conn_sec(hval_data, cert_data, base_scores)
        assert base_scores['Connection_Security'] <= 55, "Weak cipher should get -45 deduction"
    
    def test_outdated_tls_version(self, base_scores):
        """Test outdated TLS version gets deduction"""
        hval_data = {
            "head": [
                {"status": 200, "url": "https://example.com/", "tls": "TLS_AES_128_GCM_SHA256"}
            ],
            "security": 7
        }
        cert_data = {"connection": {"tls_version": "TLS 1.0"}, "certs": []}
        score_engine.score_conn_sec(hval_data, cert_data, base_scores)
        assert base_scores['Connection_Security'] <= 80, "Outdated TLS should get -20 deduction"


# ============================================================================
# MAIL/DOMAIN REPUTATION SCORING TESTS
# ============================================================================

class TestMailScoring:
    """Tests for score_dom_rep() function (Mail section)"""
    
    def test_optimal_mail_config(self, optimal_mail_data, base_scores):
        """Test optimal mail configuration has no deductions"""
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com", "ns3.google.com"]}
        score_engine.score_dom_rep(optimal_mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] >= 90, "Optimal config should score >= 90"
    
    def test_no_mx_records(self, base_scores):
        """Test no MX records gets critical deduction"""
        mail_data = {
            "mx": [],
            "spf": ["v=spf1 -all"],
            "dmarc": ["v=DMARC1; p=reject"]
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 80, "No MX records should get -20 deduction"
    
    def test_single_mx_record(self, base_scores):
        """Test single MX record (SPOF) gets deduction"""
        mail_data = {
            "mx": ["mx1.example.com"],
            "spf": ["v=spf1 -all"],
            "dmarc": ["v=DMARC1; p=reject"]
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 95, "Single MX record should get minor deduction"
    
    def test_no_dmarc(self, base_scores):
        """Test missing DMARC gets major deduction"""
        mail_data = {
            "mx": ["mx1.example.com", "mx2.example.com"],
            "spf": ["v=spf1 -all"],
            "dmarc": []
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 78, "Missing DMARC should get -22 deduction"
    
    def test_weak_dmarc_policy(self, base_scores):
        """Test weak DMARC policy (p=none) gets deduction"""
        mail_data = {
            "mx": ["mx1.example.com", "mx2.example.com"],
            "spf": ["v=spf1 -all"],
            "dmarc": ["v=DMARC1; p=none"]
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 93, "Weak DMARC policy should get -7 deduction"
    
    def test_no_spf(self, base_scores):
        """Test missing SPF gets major deduction"""
        mail_data = {
            "mx": ["mx1.example.com", "mx2.example.com"],
            "spf": [],
            "dmarc": ["v=DMARC1; p=reject"]
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 90, "Missing SPF should get -10 deduction"
    
    def test_spf_softfail(self, base_scores):
        """Test SPF softfail (~all) gets minor deduction"""
        mail_data = {
            "mx": ["mx1.example.com", "mx2.example.com"],
            "spf": ["v=spf1 include:_spf.example.com ~all"],
            "dmarc": ["v=DMARC1; p=reject"]
        }
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 95, "SPF softfail should get -5 deduction"


# ============================================================================
# METHOD SCORING TESTS (via Domain Reputation)
# ============================================================================

class TestMethodScoring:
    """Tests for score_dom_rep() function (Method section)"""
    
    def test_optimal_methods(self, base_scores):
        """Test optimal methods (HEAD + GET only) has no deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}  # HEAD (1) + GET (2)
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        # Should have no deduction for methods
        assert base_scores['Domain_Reputation'] >= 85, "Optimal methods should not get deduction"
    
    def test_acceptable_methods(self, base_scores):
        """Test acceptable methods (HEAD + GET + POST) has no deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 7}  # HEAD (1) + GET (2) + POST (4)
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] >= 85, "Acceptable methods should not get deduction"
    
    def test_dangerous_methods_put_delete_trace(self, base_scores):
        """Test dangerous methods (PUT, DELETE, TRACE) get major deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 104}  # PUT (8) + DELETE (32) + TRACE (64)
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 80, "PUT/DELETE/TRACE should get -20 deduction"
    
    def test_connect_patch_methods(self, base_scores):
        """Test CONNECT and PATCH methods get deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 144}  # CONNECT (128) + PATCH (16)
        rdap_data = {"nameserver": ["ns1.google.com", "ns2.google.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 93, "CONNECT/PATCH should get -7 deduction"


# ============================================================================
# RDAP SCORING TESTS (via Domain Reputation)
# ============================================================================

class TestRDAPScoring:
    """Tests for score_dom_rep() function (RDAP section)"""
    
    def test_optimal_rdap_config(self, optimal_rdap_data, base_scores):
        """Test optimal RDAP configuration has no deductions"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}
        score_engine.score_dom_rep(mail_data, method_data, optimal_rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] >= 85, "Optimal RDAP should not get deduction"
    
    def test_single_nameserver(self, base_scores):
        """Test single nameserver (SPOF) gets critical deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.example.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 85, "Single nameserver should get -15 deduction"
    
    def test_two_nameservers_same_vendor(self, base_scores):
        """Test two nameservers from same vendor gets minor deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}
        rdap_data = {"nameserver": ["ns1.cloudflare.com", "ns2.cloudflare.com"]}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        # -2 for only 2 nameservers, -2 for same vendor
        assert base_scores['Domain_Reputation'] <= 96, "Two nameservers, same vendor should get deduction"
    
    def test_three_nameservers_diverse(self, base_scores):
        """Test three nameservers with diversity has no deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}
        rdap_data = {
            "nameserver": [
                "ns1.google.com",
                "ns1.cloudflare.com",
                "ns1.amazon.com"
            ]
        }
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] >= 90, "Three diverse nameservers should not get deduction"
    
    def test_empty_nameserver_list(self, base_scores):
        """Test empty nameserver list gets critical deduction"""
        mail_data = {"mx": ["mx1.example.com"], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]}
        method_data = {"flag": 3}
        rdap_data = {"nameserver": []}
        score_engine.score_dom_rep(mail_data, method_data, rdap_data, base_scores)
        assert base_scores['Domain_Reputation'] <= 85, "Empty nameserver list should get -15 deduction"


# ============================================================================
# FINAL SCORE CALCULATION TESTS
# ============================================================================

class TestFinalScoreCalculation:
    """Tests for calculate_final_score() function"""
    
    def test_all_perfect_scores(self):
        """Test all perfect scores (100) results in 100"""
        weights = score_engine.WEIGHTS
        scores = {
            'Connection_Security': 100,
            'Certificate_Health': 100,
            'DNS_Record_Health': 100,
            'Domain_Reputation': 100,
            'Credential_Safety': 100
        }
        final = score_engine.calculate_final_score(weights, scores)
        # Use approximate comparison for floating point precision
        assert abs(final - 100.0) < 0.01, f"All perfect scores should result in ~100, got {final}"
    
    def test_mixed_scores(self):
        """Test mixed scores uses weighted harmonic mean correctly"""
        weights = score_engine.WEIGHTS
        scores = {
            'Connection_Security': 90,
            'Certificate_Health': 85,
            'DNS_Record_Health': 95,
            'Domain_Reputation': 80,
            'Credential_Safety': 90
        }
        final = score_engine.calculate_final_score(weights, scores)
        # Harmonic mean should be lower than arithmetic mean
        assert 80 <= final <= 95, f"Mixed scores should result in reasonable range, got {final}"
    
    def test_zero_score_returns_one(self):
        """Test zero score in any component returns 1"""
        weights = score_engine.WEIGHTS
        scores = {
            'Connection_Security': 100,
            'Certificate_Health': 0,  # Zero score
            'DNS_Record_Health': 100,
            'Domain_Reputation': 100,
            'Credential_Safety': 100
        }
        final = score_engine.calculate_final_score(weights, scores)
        assert final == 1, "Zero score should return 1"
    
    def test_partial_scores(self):
        """Test calculation with only some components"""
        weights = score_engine.WEIGHTS
        scores = {
            'Connection_Security': 90,
            'Certificate_Health': 85
            # Missing other components
        }
        final = score_engine.calculate_final_score(weights, scores)
        # Should calculate based only on provided scores
        assert 85 <= final <= 90, "Partial scores should calculate correctly"
    
    def test_empty_scores(self):
        """Test empty scores dict returns 0"""
        weights = score_engine.WEIGHTS
        scores = {}
        final = score_engine.calculate_final_score(weights, scores)
        assert final == 0.0, "Empty scores should return 0"


# ============================================================================
# CREDENTIAL SAFETY SCORING TESTS
# ============================================================================

class TestCredentialSafetyScoring:
    """Tests for score_cred_safety() function"""
    
    def test_good_tls_and_hsts(self, base_scores):
        """Test good TLS version with HSTS header"""
        cert_data = {"connection": {"tls_version": "TLS 1.3"}, "certs": []}
        hval_data = {"security": 1}  # HSTS present
        score_engine.score_cred_safety(cert_data, hval_data, base_scores)
        assert base_scores['Credential_Safety'] == 100, "Good TLS + HSTS should not be deducted"
    
    def test_outdated_tls_version(self, base_scores):
        """Test outdated TLS version gets critical deduction"""
        cert_data = {"connection": {"tls_version": "TLS 1.0"}, "certs": []}
        hval_data = {"security": 1}  # HSTS present
        score_engine.score_cred_safety(cert_data, hval_data, base_scores)
        assert base_scores['Credential_Safety'] <= 50, "Outdated TLS should get -50 deduction"
    
    def test_missing_hsts_header(self, base_scores):
        """Test missing HSTS header gets deduction"""
        cert_data = {"connection": {"tls_version": "TLS 1.3"}, "certs": []}
        hval_data = {"security": 0}  # HSTS missing
        score_engine.score_cred_safety(cert_data, hval_data, base_scores)
        assert base_scores['Credential_Safety'] <= 80, "Missing HSTS should get -20 deduction"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestSecurityScoreCalculation:
    """Integration tests for calculate_security_score() orchestrator"""
    
    def test_complete_scan_optimal(self, scan_date):
        """Test complete scan with all optimal data"""
        all_scans = {
            'cert_scan': {
                "certs": [{
                    "not_after": "2025-12-15T20:07:01Z",
                    "not_before": "2025-09-16T20:11:24Z"
                }],
                "connection": {"tls_version": "TLS 1.3"},
                "verification": {"hostname_matches": True, "chain_verified": True}
            },
            'dns_scan': {
                "rcode": 31,
                "a": ["1.1.1.1", "1.0.0.1"],
                "aaaa": ["2606:4700:4700::1111", "2606:4700:4700::1001"]
            },
            'hval_scan': {
                "head": [
                    {"status": 200, "url": "https://example.com/", "tls": "TLS_AES_128_GCM_SHA256"}
                ],
                "security": 7  # HSTS + CSP + XCTO
            },
            'mail_scan': {
                "mx": ["mx1.example.com", "mx2.example.com"],
                "spf": ["v=spf1 -all"],
                "dmarc": ["v=DMARC1; p=reject"]
            },
            'method_scan': {"flag": 3},
            'rdap_scan': {
                "nameserver": ["ns1.google.com", "ns2.cloudflare.com", "ns3.amazon.com"]
            }
        }
        
        results = score_engine.calculate_security_score(all_scans, scan_date)
        
        assert 'Aggregated_Score' in results
        assert results['Aggregated_Score'] > 85, "Optimal scan should score > 85"
    
    def test_poor_scan(self, scan_date):
        """Test calculation with poor security scores"""
        all_scans = {
            'cert_scan': {
                "certs": [{
                    "not_after": "2020-01-01T00:00:00Z",
                    "not_before": "2019-01-01T00:00:00Z"
                }],
                "connection": {"tls_version": "TLS 1.0"},
                "verification": {"hostname_matches": False, "chain_verified": False}
            },
            'dns_scan': {
                "rcode": 1,
                "a": ["1.1.1.1"],
                "aaaa": []
            },
            'hval_scan': {
                "head": [
                    {"status": 200, "url": "http://example.com", "tls": "NONE"}
                ],
                "security": 0
            },
            'mail_scan': {
                "mx": [],
                "spf": [],
                "dmarc": []
            },
            'method_scan': {"flag": 248},  # All dangerous methods
            'rdap_scan': {
                "nameserver": []
            }
        }
        
        results = score_engine.calculate_security_score(all_scans, scan_date)
        
        assert 'Aggregated_Score' in results
        assert results['Aggregated_Score'] <= 20, "Poor scan should score very low"


# ============================================================================
# SUBPROCESS/CURL MOCKING TESTS
# ============================================================================

class TestCurlExecution:
    """Tests for execute_curl_command() function"""
    
    @patch('subprocess.run')
    def test_successful_curl_execution(self, mock_run):
        """Test successful curl command execution"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"test": "data"}',
            stderr=''
        )
        
        result = score_engine.execute_curl_command(['curl', '-s', 'https://example.com'])
        
        assert result == '{"test": "data"}'
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_failed_curl_execution(self, mock_run):
        """Test failed curl command execution"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout='',
            stderr='Connection failed'
        )
        
        result = score_engine.execute_curl_command(['curl', '-s', 'https://example.com'])
        
        assert result is None
    
    @patch('subprocess.run')
    def test_curl_timeout(self, mock_run):
        """Test curl command timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired('curl', 15)
        
        result = score_engine.execute_curl_command(['curl', '-s', 'https://example.com'])
        
        assert result is None
    
    @patch('subprocess.run')
    def test_curl_not_found(self, mock_run):
        """Test curl command not found"""
        mock_run.side_effect = FileNotFoundError()
        
        result = score_engine.execute_curl_command(['curl', '-s', 'https://example.com'])
        
        assert result is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])