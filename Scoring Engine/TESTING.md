# NetSTAR Scoring Engine - Testing Guide

## Overview
This directory contains unit tests for the NetSTAR security scoring engine using pytest.

## Setup

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Running Tests

### Run All Tests
```bash
pytest test_score_engine.py -v
```

### Run Specific Test Class
```bash
# Test only certificate scoring
pytest test_score_engine.py::TestCertScoring -v

# Test only DNS scoring
pytest test_score_engine.py::TestDNSScoring -v

# Test only integration tests
pytest test_score_engine.py::TestSecurityScoreCalculation -v
```

### Run with Coverage Report
```bash
pytest test_score_engine.py --cov=score_engine --cov-report=html
```

This generates an HTML coverage report in `htmlcov/index.html`

### Run Specific Test
```bash
pytest test_score_engine.py::TestCertScoring::test_valid_cert_good_expiration -v
```

## Test Structure

### Test Classes
- `TestCertScoring` - Certificate validation and expiration tests
- `TestDNSScoring` - DNS configuration and redundancy tests
- `TestHVALScoring` - HTTPS, TLS, and security header tests
- `TestMailScoring` - DMARC, SPF, and MX record tests
- `TestMethodScoring` - HTTP method restriction tests
- `TestRDAPScoring` - Nameserver redundancy and diversity tests
- `TestFinalScoreCalculation` - Weighted harmonic mean calculation tests
- `TestSecurityScoreCalculation` - Integration tests for complete scans
- `TestCurlExecution` - Subprocess/curl mocking tests
- `TestFetchScanData` - Data fetching tests
- `TestEdgeCases` - Boundary conditions and error handling

### Fixtures
Reusable test data is defined as pytest fixtures:
- `valid_cert_data` - Valid certificate with good expiration
- `expired_cert_data` - Expired certificate
- `optimal_dns_data` - Optimal DNS configuration
- `poor_dns_data` - Poor DNS configuration
- And many more...

## Test Coverage

The test suite covers:
- ✅ All 6 scoring functions (cert, DNS, HVAL, mail, method, RDAP)
- ✅ Final score calculation (weighted harmonic mean)
- ✅ Integration tests for complete security scans
- ✅ Edge cases (missing data, malformed inputs, boundary conditions)
- ✅ Subprocess mocking (no external API calls during tests)
- ✅ Error handling and graceful degradation

## Expected Results

With the current implementation, you should see:
- **60+ tests** passing
- **Coverage > 80%** of score_engine.py
- All edge cases handled gracefully

## Troubleshooting

### Import Errors
If you see import errors, make sure you're running pytest from the `Scoring Engine` directory:
```bash
cd "Scoring Engine"
pytest test_score_engine.py -v
```

### Module Not Found
Ensure `score_engine.py` is in the same directory as `test_score_engine.py`

### Assertion Failures
If specific tests fail, check:
1. The scoring logic in `score_engine.py` matches expected deductions
2. Test data fixtures are correct
3. Expected score ranges account for all deductions
