import json
import sys
import argparse
import json
import time
from datetime import datetime
from typing import Dict

# 1. Import everything needed from the new files
import config as app_config
from data_fetch import fetch_scan_data_concurrent
from scoring_logic import calculate_security_score

# --- Test Data ---
test_scans = {
    'cert_scan': {
        'host': 'amazon.com',
        'port': 443,
        'timestamp': '2026-02-18T16:06:49Z',
        'connection': {
            'tls_version': 'TLS 1.3', 
            'cipher_suite': 'TLS_AES_128_GCM_SHA256'
        },
        'verification': {
            'hostname_checked': 'amazon.com',
            'hostname_matches': True,
            'chain_verified': True
        },
        'certs': [
            {
                'role': 'leaf',
                'subject_cn': 'www.amazon.com',
                'subject_dns_names': ['*.amazon.com', 'amazon.com'],
                'not_before': '2025-10-15T00:00:00',
                'not_after': '2026-10-31T04:00:00'
            }
        ]
    },
    'dns_scan': {
        'rcode': 0,
        'host': 'amazon.com',
        'a': ['98.87.170.71', '98.82.161.185', '98.87.170.74'],
        'aaaa': ['2600:9000:2549:6400:7:49a5:5fd6:da1'],
        'cname': []
    },
    'hval_scan': {
        'item': 'amazon.com',
        'n': 4,
        'head': [
            {
                'status': 301, 
                'url': 'http://amazon.com', 
                'ip': ['98.87.170.71', '98.82.161.185', '98.87.170.74']
            },
            {
                'status': 200, 
                'url': 'https://www.amazon.com/', 
                'ip': ['2600:9000:2549:6400:7:49a5:5fd6:da1', '3.171.157.232'],
                'tls': 'TLS_AES_128_GCM_SHA256'
            }
        ],
        'security': 1
    },
    'mail_scan': {
        'host': 'amazon.com',
        'mx': ['amazon-smtp.amazon.com'],
        'spf': ['v=spf1 include:spf1.amazon.com -all'],
        'dmarc': ['v=DMARC1; p=quarantine; pct=100;']
    },
    'method_scan': {
        'url': 'amazon.com',
        'flag': 7
    },
    'rdap_scan': [
        {
            'host': 'amazon.com',
            'nameserver': ['ns1.amzndns.co.uk', 'ns1.amzndns.com', 'ns1.amzndns.net'],
            'domain': {
                'objectClassName': 'domain',
                'handle': '281209_DOMAIN_COM-VRSN',
                'ldhName': 'AMAZON.COM',
                'status': ['client delete prohibited', 'server update prohibited'],
                'events': [
                    {'eventAction': 'registration', 'eventDate': '1994-11-01T05:00:00Z'},
                    {'eventAction': 'expiration', 'eventDate': '2026-10-31T04:00:00Z'}
                ],
                'entities': [
                    {
                        'objectClassName': 'entity',
                        'handle': '292',
                        'roles': ['registrar'],
                        'vcardArray': ['vcard', [['fn', {}, 'text', 'MarkMonitor Inc.']]]
                    }
                ]
            }
        }
    ],
    'firewall_scan': {
        'host': 'amazon.com',
        'ip': ['98.87.170.71'],
        'version': 1771430157,
        'Block': True
    }
}

# --- Main execution block ---
if __name__ == '__main__':
    
    # 1. Setup argument parser
    parser = argparse.ArgumentParser(
        description="Get a security and infrastructure score for a target domain."
    )
    # The -t/--target value is expected to be a pre-sanitized hostname
    # provided by the server (no scheme, no path, no "www." prefix).
    # All normalization and validation happens in server.js before this
    # script is invoked.  See Docs/url-sanitization-policy.md.
    parser.add_argument(
        '-t', '--target',
        type=str,
        default=app_config.DEFAULT_URL,
        help=f"The target hostname to scan (e.g., {app_config.DEFAULT_URL})"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose output for clarity."
    )    
    parser.add_argument(
        '--use-test-data',
        action='store_true',
        help="Run the script using the internal test_scans data instead of live API calls."
    )
    
    args = parser.parse_args()
    app_config.VERBOSE = args.verbose
    
    all_scans = {}
    scan_date = None

    # ----------------------------------------------------
    # START TIMER 
    start_time = time.time()
    # ----------------------------------------------------

    # 2. Decide whether to use test data or fetch live data
    if args.use_test_data:
        if app_config.VERBOSE:
            print(f"--- Running analysis on TEST DATA ---", file=sys.stderr)
        all_scans = test_scans
        # For reproducible results, we'll set a fixed date for the expiration checks.
        # Cert Sample Expiration: 2025-12-15.
        scan_date = datetime(2025, 10, 15)
    else:
        if app_config.VERBOSE:
            print(f"--- Running analysis on LIVE DATA for {args.target} ---", file=sys.stderr)
        # For live data, use the real date!
        scan_date = datetime.now()
        # *** CHANGED TO THE CONCURRENT FETCH FUNCTION ***
        all_scans = fetch_scan_data_concurrent(args.target)
    
    # 3. Check if we have data, then calculate and print scores
    if not all_scans:
        if app_config.VERBOSE:
            print("No scan data was retrieved. Exiting.", file=sys.stderr)
        sys.exit(1)

    final_scores = calculate_security_score(all_scans, scan_date)
    
    # ----------------------------------------------------
    # END TIMER AND CALCULATE 
    end_time = time.time()
    elapsed_time = end_time - start_time
    # ----------------------------------------------------

    # Emit a single JSON object for the server (no text parsing needed).
    output = {k: v for k, v in final_scores.items() if k != 'Aggregated_Score'}
    output['aggregatedScore'] = final_scores.get('Aggregated_Score')
    print(json.dumps(output, indent=2))

    if app_config.VERBOSE:
        print("-------------------------------------------", file=sys.stderr)
        print(f"Total execution time: {elapsed_time:.2f} seconds", file=sys.stderr)
        print("-------------------------------------------", file=sys.stderr)

