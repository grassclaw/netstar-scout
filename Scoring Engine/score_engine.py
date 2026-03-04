import json
import math
import subprocess
import sys
import argparse
from typing import Optional, List
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor

# --- Configuration and Constants ---

# Bitmasks for Method Scan (Flag)
METHOD_FLAGS = {
    'HEAD': 1, 'GET': 2, 'POST': 4,
    'PUT': 8, 'PATCH': 16, 'DELETE': 32,
    'TRACE': 64, 'CONNECT': 128
}

# Bitmasks for HVAL Scan (Security Flag)
SECURITY_FLAGS = {
    'HSTS': 1, 'CSP': 2, 'XCTO': 4,
    'ACAO': 8, 'COOP': 16, 'CORP': 32,
    'COEP': 64
}

# Weights for each component in the final score calculation
WEIGHTS = {
    'Connection_Security': 20,
    'Certificate_Health': 18,
    'DNS_Record_Health': 17,
    'Domain_Reputation': 25,    
    'WHOIS_Pattern': 0, #unused currently
    'IP Reputation': 0, #unused currently
    'Credential Safety': 20
}

# --- GLOBAL CONFIGURATION ---
BASE_URL = 'https://w4.netstar.dev/'
API_ENDPOINTS = [
    'cert', 
    'dns', 
    'hval', 
    'mail', 
    'method', 
    'rdap'
]

# Default target hostname used if no argument is provided
DEFAULT_URL = 'netstar.ai' 

# --- Data Fetching Function (Using 'curl' subprocess) ---

def execute_curl_command(command: List[str]) -> Optional[str]: #KEEP
    """
    Executes a shell command (cURL) and returns the standard output.
    Handles potential errors during execution.
    """
    print(f"Executing command: {' '.join(command)}")
    try:
        # Run the command, capture stdout, and decode as text
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=15  # Increased timeout slightly for external API calls
        )

        if result.returncode != 0:
            # Report the error code and stderr if the command failed
            print(f"Error executing command. Return code: {result.returncode}")
            print(f"Standard Error:\n{result.stderr.strip()}")
            return None

        # The output is returned as a string (JSON)
        return result.stdout.strip()

    except FileNotFoundError:
        print("Error: The 'curl' command was not found. Make sure it is installed and in your system PATH.")
        return None
    except subprocess.TimeoutExpired:
        print("Error: Command execution timed out.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during execution: {e}")
        return None

def process_single_endpoint(host: str, endpoint: str) -> tuple[str | None, dict | None]:
    """
    (Formerly fetch_scan_data's loop content) Fetches, parses, and returns 
    the data for a single endpoint using cURL subprocess.
    Returns (scan_key, data) on success or (None, None) on failure.
    """
    # 1. Key Generation
    # Map endpoint to the key used in scoring functions (e.g., 'cert' -> 'cert_scan')
    scan_key = f"{endpoint}_scan" if endpoint != 'title' else None
    if not scan_key: 
        return (None, None)

    # 2. URL Construction
    query = ''
    if endpoint == 'dns':
        query = '?A&AAAA&CNAME&DNS&MX&TXT'
    full_url = f"{BASE_URL}{endpoint}/{host}{query}"
    
    # 3. Define the cURL command
    CURL_COMMAND = ['curl', '-s', full_url]

    print(f"\n[Processing Endpoint: {endpoint.upper()}]")

    # 4. Execute the command
    output = execute_curl_command(CURL_COMMAND)
    
    if output is None:
        print(f"--> Endpoint {endpoint.upper()} failed execution. Skipping.")
        return (None, None)
    
    # 5. Parse the JSON output
    try:
        data = json.loads(output)
        # Note: Printing final success message after command execution for clarity
        return (scan_key, data)
    except json.JSONDecodeError:
        print(f"--> Endpoint {endpoint.upper()} returned invalid JSON. Skipping.")
        return (None, None)
    except Exception as e:
        print(f"--> An error occurred processing {endpoint.upper()}: {e}")
        return (None, None)

def fetch_scan_data_concurrent(host: str) -> dict: 
    """
    Coordinates concurrent fetching of scan data from all API endpoints 
    using a ThreadPoolExecutor.
    """
    all_scans = {}
    print(f"\n--- Fetching live data for {host} from NetStar API (via concurrent cURL) ---")

    # Use ThreadPoolExecutor to run tasks in parallel
    # The number of workers is set to the number of endpoints to run all simultaneously
    with ThreadPoolExecutor(max_workers=len(API_ENDPOINTS)) as executor:
        
        # 'executor.map' schedules 'process_single_endpoint' for all items in API_ENDPOINTS.
        # It requires that 'host' is repeated for each call.
        future_results = executor.map(
            process_single_endpoint, 
            [host] * len(API_ENDPOINTS), # host repeated for each worker
            API_ENDPOINTS               # endpoint is iterated over
        )
        
        # Aggregate the results as they complete
        for scan_key, data in future_results:
            if scan_key and data:
                all_scans[scan_key] = data

    print("\n--- Data fetching complete ---")
    return all_scans

# --- Scoring Functions ---

def score_cert_health(data: dict, scan_date: datetime, scores: dict): 
    """Calculates the score for the Certificate Scan (Max Score: 100).
    Focuses on validity and time to expiration.
    
    The 'data' parameter is now the certificate list itself,
    where the first element (position 0) is the leaf certificate.
    """
    try:
        # --- MODIFIED: The certificate chain is the 'data' parameter itself (a list) ---
        connection_data = data.get("connection", {})
        verification_data = data.get("verification", {})
        cert_list = data.get("certs", [])

        # Check if the list exists and is not empty
        if not cert_list or not isinstance(cert_list, list) or len(cert_list) == 0:
            print("Cert Score: CRITICAL - No certificates found in response. (CERT_HEALTH)")
            # Note: Deducting from Certificate_Health initialized at 100
            scores['Certificate_Health'] -= 50
            return # Exit the function if no certs are found
        
        # Use the first certificate in the list for scoring (the leaf/server cert)
        cert_object = cert_list[0]

        # Get the date strings first
        # These keys are present directly in the cert_object
        not_after_str = cert_object.get("not_after")
        not_before_str = cert_object.get("not_before")

        # Check if they are None or empty
        if not not_after_str or not not_before_str:
            print("Cert Score: CRITICAL - Certificate date fields missing or invalid. (CERT_HEALTH)")
            scores['Certificate_Health'] -= 9
            return

        # --- MODIFIED: Remove .split('.') since the new format ends in 'Z' (e.g., 2024-11-20T14:00:00Z) ---
        # The 'Z' indicates UTC and is handled directly by fromisoformat.
        not_after = datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
        not_before = datetime.fromisoformat(not_before_str.replace('Z', '+00:00'))
        
    except (ValueError, TypeError) as e:
        # Handles errors from fromisoformat if the string is malformed
        print(f"Cert Score: CRITICAL - Certificate date fields are malformed or missing (Error: {e}). (CERT_HEALTH)")
        scores['Certificate_Health'] -= 8
        return

    # 1. Validity Check (Major Deductions)
    if scan_date.replace(tzinfo=not_after.tzinfo) > not_after:
        # Expired
        print("Cert Score: CRITICAL - Certificate has expired. (CERT_HEALTH)")
        scores['Certificate_Health'] -= 50
    if scan_date.replace(tzinfo=not_before.tzinfo) < not_before:
        # Not yet valid
        print("Cert Score: CRITICAL - Certificate not yet valid. (CERT_HEALTH)")
        scores['Certificate_Health'] -= 50
    
    # 2. Expiration Time Check (Gradient and Buckets)
    # Ensure both datetimes are timezone-aware or naive before subtraction.
    # By default, scan_date is naive (datetime.now()), so we ensure consistency.
    days_until_expiration = (not_after.replace(tzinfo=None) - scan_date.replace(tzinfo=None)).days

    if days_until_expiration > 30:
        # No deduction for >30 days
        print(f"Cert Score: Standard Warning - Expires in {days_until_expiration} days.")
    else: # 1 <= days_until_expiration <= 30
        # High-Risk Gradient: Deduction scales from 0 at 30 days to 30 at 0 days.
        MAX_GRADIENT_DEDUCTION = 30
        days_past_30 = 30 - days_until_expiration
        
        # Calculate linear deduction
        deduction = int(MAX_GRADIENT_DEDUCTION * (days_past_30 / 30))
        
        scores['Certificate_Health'] -= deduction
        print(f"Cert Score: High Risk Gradient - Expires in {days_until_expiration} days. Deduction: -{deduction} (CERT_HEALTH)")

    # 3. Check Verification Status
    hostname_matches = verification_data.get("hostname_matches", False)
    chain_verified = verification_data.get("chain_verified", False)
    
    if not hostname_matches:
        scores['Certificate_Health'] -= 10
        print("Cert Score: Significant Deduction - Hostname does not match certificate. (CERT_HEALTH)")
    if not chain_verified:
        scores['Certificate_Health'] -= 10
        print("Cert Score: Significant Deduction - Certificate chain not verified. (CERT_HEALTH)")

def score_dns_rec_health(dns_data: dict, rdap_scan:dict, scores: dict): 
    """Calculates the score for the DNS Scan (Max Score: 100).
    Focuses on record coverage (rcode) and redundancy (A/AAAA counts).
    """
    rcode = dns_data.get("rcode", 0)
    a_count = len(dns_data.get("a", []))
    aaaa_count = len(dns_data.get("aaaa", []))
    cname = dns_data.get("cname", [])

    # --- 2. RCODE Completeness Check (New Banded Scoring) ---
    # Goal: Ensure a wide set of requested record types are returned.
    
    if rcode >= 31:
        # Optimal completeness (includes A, AAAA, CNAME, NS, MX, and/or TXT)
        pass # score += 0 (Neutral)
    elif rcode >= 8: # 8 <= rcode <= 30
        # Missing several key types (e.g., TXT/MX if NS is present)
        scores['DNS_Record_Health'] -= 10
        print(f"DNS Score: Minor Deduction - rcode {rcode} is incomplete (Missing advanced types). (DNS_REC_HEALTH)")
    elif rcode >= 1: # 1 <= rcode <= 7
        # Missing foundational types (e.g., NS)
        scores['DNS_Record_Health'] -= 15
        print(f"DNS Score: Significant Deduction - rcode {rcode} is low (Missing foundational types). (DNS_REC_HEALTH)")

    
    # 2. Redundancy Check
    # Redundancy
    if a_count < 2:
        scores['DNS_Record_Health'] -= 10
        print("DNS Score: Minor Deduction - Only one IPv4 address (SPOF). (DNS_REC_HEALTH)")

    # IPv6 Redundancy
    if aaaa_count == 0:
        scores['DNS_Record_Health'] -= 5
        print("DNS Score: Minor Deduction - No IPv6 support. (DNS_REC_HEALTH)")
    elif aaaa_count < 2:
        scores['DNS_Record_Health'] -= 5
        print("DNS Score: Minor Deduction - Only one IPv6 address (SPOF). (DNS_REC_HEALTH)")

    # TODO: look into how to check CNAME and nameserver info

def score_conn_sec(hval_data: dict, cert_data: dict, scores: dict): 
    """Calculates the score for the HVAL Scan (Max Score: 100).
    Focuses on HTTPS enforcement, TLS, and security headers (security flag).
    """
    security_flag = hval_data.get("security", 0)
    head_chain = hval_data.get("head", [])
    tls_version = cert_data.get('connection', {}).get('tls_version')
    cipher_suite = cert_data.get('connection', {}).get('cipher_suite')

    # 1. HTTPS Enforcement Check (Major Deductions)
    final_status = head_chain[-1].get("status") if head_chain else None
    final_url = head_chain[-1].get("url", "") if head_chain else ""
    tls_cipher = head_chain[-1].get("tls", "NONE") if head_chain and head_chain[-1].get("tls") else "NONE"

    # CHECK - correct functionality for desired outcome?
    if final_status == 403:
        print("HVAL Notice: Final connection returned 403 Forbidden. Skipping HTTPS enforcement check. (CONN_SEC)")
        pass
    elif final_status != 200 or not final_url.startswith("https"):
        # Fails to load or loads over HTTP
        print("HVAL Score: CRITICAL - Final connection not 200 HTTPS. (CONN_SEC)")
        scores['Connection_Security'] -= 45
        # return 1

    # 2. TLS Strength Check
    if "TLS_AES" in tls_cipher or "TLS_CHACHA20" in tls_cipher:
        pass # Strong cipher, no deduction
    elif "TLS_ECDHE-RSA" in tls_cipher:
        scores['Connection_Security'] -= 10
        print(f"HVAL Score: Minor Deduction - Moderate cipher used: {tls_cipher}. (CONN_SEC)")
    else:
        scores['Connection_Security'] -= 45
        print(f"HVAL Score: Significant Deduction - Weak/no cipher used: {tls_cipher}. (CONN_SEC)")

    # 3. Security Header Check (Bitwise Flag Analysis)
    #TODO: Create functionality if security flag is missing (skip this step?)
    # The required headers are HSTS (1), CSP (2), XCTO (4). Total = 7.
    REQUIRED_FLAGS = SECURITY_FLAGS['HSTS'] | SECURITY_FLAGS['CSP'] | SECURITY_FLAGS['XCTO']
    
    # Count how many of the three required flags are missing
    missing_flags_mask = REQUIRED_FLAGS & ~security_flag
    
    # Check if HSTS (1) is missing
    is_hsts_missing = bool(missing_flags_mask & SECURITY_FLAGS['HSTS'])
    # Check if CSP (2) is missing
    is_csp_missing = bool(missing_flags_mask & SECURITY_FLAGS['CSP'])
    # Check if XCTO (4) is missing
    is_xcto_missing = bool(missing_flags_mask & SECURITY_FLAGS['XCTO'])
    
    missing_count = is_hsts_missing + is_csp_missing + is_xcto_missing
    
    if missing_count == 0:
        # HSTS, CSP, and XCTO present: +0 (or a small bonus)
        print("HVAL Score: HSTS, CSP, XCTO all present.")
    elif missing_count == 1:
        # Missing one of the three: -20
        scores['Connection_Security'] -= 20
        print(f"HVAL Score: Deduction - Missing 1 critical header (HSTS/CSP/XCTO). -20 pts. (CONN_SEC)")
    elif missing_count >= 2:
        # Missing two or more of the three: -40
        scores['Connection_Security'] -= 40
        print(f"HVAL Score: Major Deduction - Missing {missing_count} critical headers. -40 pts. (CONN_SEC)")

    # Check Dangerous/Advanced Headers (Minor Deductions)
    advanced_flags = SECURITY_FLAGS['COOP'] | SECURITY_FLAGS['CORP'] | SECURITY_FLAGS['COEP']
    if (security_flag & advanced_flags) != advanced_flags:
        scores['Connection_Security'] -= 5 # Minor deduction for incomplete advanced security.
        print("HVAL Score: Minor Deduction - Missing one or more advanced security headers (COOP/CORP/COEP). (CONN_SEC)")

    if tls_version not in ['TLS 1.2', 'TLS 1.3']:
        scores['Connection_Security'] -= 20
        print(f"HVAL Score: Significant Deduction - Outdated TLS version: {tls_version}. (CONN_SEC)")

def score_dom_rep(mail_data: dict, method_data: dict, rdap_data: dict, scores: dict): #NEW FUNCTION
    """Unifies Domain Reputation scoring from Mail, Method, and RDAP scans."""

# --- Mail Scan ---
    # 1. MX Redundancy 
    mx_count = len(mail_data.get("mx", []))
    if mx_count == 0:
        scores['Domain_Reputation'] -= 20
        print("Mail Score: CRITICAL - No MX records (cannot receive mail). (DOM_REP)")
    elif mx_count < 2:
        scores['Domain_Reputation'] -= 5
        print("Mail Score: Significant Deduction - Only one MX record (SPOF). (DOM_REP)")
    else:
        print("Mail Score: MX redundancy is good.")

    # 2. DMARC Policy (Highest Impact)
    dmarc_data = mail_data.get("dmarc", [])
    if not dmarc_data:
        scores['Domain_Reputation'] -= 22
        print("Mail Score: Major Deduction - DMARC record is missing (high spoofing risk). (DOM_REP)")
    else:
        # Parse the DMARC string (e.g., "v=DMARC1; p=reject;...")
        dmarc_policy = next((part.split('=')[1] for part in dmarc_data[0].split(';') if part.strip().startswith('p=')), 'none')
        
        if dmarc_policy.strip() != 'reject' and dmarc_policy.strip() != 'quarantine':
            scores['Domain_Reputation'] -= 7 # Optimal is reject or quarantine
            print(f"Mail Score: Significant Deduction - DMARC policy is '{dmarc_policy}' (no active enforcement). (DOM_REP)")
        
        # Check Subdomain policy (sp=)
        sp_policy = next((part.split('=')[1] for part in dmarc_data[0].split(';') if part.strip().startswith('sp=')), dmarc_policy)
        if sp_policy.strip() != 'reject' and sp_policy.strip() != 'quarantine':
            scores['Domain_Reputation'] -= 2 # Optimal is reject or quarantine
            print(f"Mail Score: Minor Deduction - DMARC subdomain policy is '{sp_policy}' (no active enforcement). (DOM_REP)")

    # 3. SPF Policy
    spf_data = mail_data.get("spf", [])
    if not spf_data or not any("v=spf1" in s for s in spf_data):
        scores['Domain_Reputation'] -= 10
        print("Mail Score: Major Deduction - SPF record is missing. (DOM_REP)")
    else:
        # Extract the SPF mechanism (e.g., "~all" or "-all")
        spf_string = next(s for s in spf_data if "v=spf1" in s)
        if "-all" in spf_string:
            pass # HardFail - Good
        elif "~all" in spf_string:
            scores['Domain_Reputation'] -= 5 # SoftFail (like medium.com)
            print("Mail Score: Minor Deduction - SPF policy is '~all' (SoftFail). (DOM_REP)")
        elif "?all" in spf_string or "+all" in spf_string:
            scores['Domain_Reputation'] -= 12
            print(f"Mail Score: Deduction - SPF policy is too permissive ('{spf_string[-4:]}'). (DOM_REP)")

    # --- Method Scan ---
    # 1. Check for Dangerous Methods (Major Deductions)
    flag = method_data.get("flag", 0)

    # CONNECT AND PATCH (128, 16) - Tunneling/Modification Risk
    if flag & (METHOD_FLAGS['CONNECT'] | METHOD_FLAGS['PATCH']):
        scores['Domain_Reputation'] -= 7
        print("Method Score: Deduction - possible modification/tunneling risk (CONNECT and/or PATCH). (DOM_REP)")

    # PUT, DELETE, and TRACE (8, 32, 64) - Editing Risk
    if flag & (METHOD_FLAGS['TRACE'] | METHOD_FLAGS['DELETE'] | METHOD_FLAGS['PUT']):
        scores['Domain_Reputation'] -= 20
        print("Method Score: Major Deduction - DELETE, TRACE, and/or PUT methods enabled. (DOM_REP)")

    # 2. Optimal Check (Positive Bonus)
    # Optimal for a public web page is usually only HEAD (1) and GET (2), resulting in flag 3.
    if flag == 3:
        print("Method Score: Optimal - Only HEAD and GET methods enabled. (DOM_REP)")
    elif flag == 7:
        print("Method Score: Acceptable - HEAD, GET, and POST methods enabled. (DOM_REP)")

    # --- RDAP Scan ---
    nameservers = rdap_data.get("nameserver", [])

    # 1. Redundancy (Major Deduction)
    if len(nameservers) < 2:
        scores['Domain_Reputation'] -= 15
        print("RDAP Score: CRITICAL - Less than 2 nameservers (SPOF). (DOM_REP)")
    elif len(nameservers) == 2:
        scores['Domain_Reputation'] -= 2
        print("RDAP Score: Deduction - Only 2 nameservers (limited redundancy). (DOM_REP)")
    elif len(nameservers) >= 3:
        pass # Good redundancy, no deduction

    # 2. Diversity (Minor Deduction)
    # Check if all nameservers belong to the same domain (e.g., cloudflare.com)
    # Handle potential errors if ns is not a string
    providers = set()
    for ns in nameservers:
        if isinstance(ns, str) and len(ns.split('.')) >= 2:
            providers.add(ns.split('.')[-2])
    
    if len(providers) == 1 and len(nameservers) >= 2:
        # Example: both are *.cloudflare.com
        scores['Domain_Reputation'] -= 2
        print(f"RDAP Score: Minor Deduction - All nameservers on the same vendor ({list(providers)[0]}). (DOM_REP)")
    elif len(providers) > 1:
        pass # Good diversity, no deduction

    # 3. Reputation (Assume reputable if 2+ nameservers are present)
    # No further deductions without a reputation database check.
    #TODO: functionality to check reputation if database available

def score_cred_safety(cert_data:dict, hval_data:dict, scores:dict): #TODO: IMPLEMENT
    """Initial function for Credential Safety scoring function.
    Currently limited, but can be flushed out further.
    """
    tls_version = cert_data.get('connection', {}).get('tls_version')
    sec_flag = hval_data.get("security", 0)

    if tls_version not in ['TLS 1.2', 'TLS 1.3']:
        scores['Credential_Safety'] -= 50
        print(f"Cred Safety Score: CRITICAL - Outdated TLS version: {tls_version}. (CRED_SAFETY)")

    if (sec_flag & SECURITY_FLAGS['HSTS']) == 0:
        scores['Credential_Safety'] -= 20
        print("Cred Safety Score: Significant Deduction - HSTS header missing. (CRED_SAFETY)")

def score_ip_rep(dns_data:dict, hval_data:dict, scores:dict): #PAUSED: Further investigation needed to determine if helpful
    """Placeholder for IP Reputation scoring function.
    Currently unused, but can be implemented in the future.
    """

    pass

def score_whois_pattern(rdap_data:dict, scores:dict): #TODO: IMPLEMENT
    """Placeholder for WHOIS Pattern scoring function.
    Currently unused, but can be implemented in the future.
    """
    host = rdap_data.get("host","")
    nameservers = rdap_data.get("nameserver", [])
    pass

def calculate_final_score(weights, scores): #CHANGE
    """
    Calculates the final score using the Weighted Harmonic Mean formula:
    Final Score = (Sum of Weights) / (Sum of (Weight / Score))
    """
    
    # 1. Calculate the numerator: Sum of all weights (∑Wi)
    sum_of_weights = 0
    
    # 2. Calculate the denominator: Sum of the ratio of (Weight / Score) (∑i Wi/Scorei)
    # This also handles checking for missing scores or zero scores to prevent DivisionByZeroError.
    sum_of_ratios = 0.0
    
    print("\n--- Individual Component Ratios (Wi / Scorei) ---")
    
    # We only include components in the calculation *if* we have a score for them.
    for tool_name, score in scores.items():
        if tool_name in weights:
            weight = weights[tool_name]
            sum_of_weights += weight
            
            if score <= 0:
                # If any score is zero or negative, the Harmonic Mean approaches zero.
                # We return 1 immediately as a zero score on a critical factor indicates failure.
                print(f"CRITICAL ERROR: {tool_name} score is 0 or less. Returning Final Score of 1.")
                return 1

            # Calculate the ratio Wi / Scorei
            ratio = weight / score
            sum_of_ratios += ratio
            
            # Display the components for clarity
            print(f"  {tool_name:15}: {weight} / {score:.2f} = {ratio:.4f}")

    print("--------------------------------------------------")
    print(f"Sum of Weights (Numerator): {sum_of_weights}")
    print(f"Sum of Ratios (Denominator): {sum_of_ratios:.4f}")
    
    # 3. Calculate the Final Score
    if sum_of_ratios == 0:
        # This happens if no scores were provided.
        print("No valid scores found. Cannot calculate score.")
        return 0.0
        
    final_score = sum_of_weights / sum_of_ratios
    return final_score

# --- Main Scoring Orchestrator ---

def calculate_security_score(all_scans: dict, scan_date: datetime) -> dict: #CHANGE
    """Runs all scoring functions and calculates the average security score."""
    
    scores = {
        'Connection_Security': 100,
        'Certificate_Health': 100,
        'DNS_Record_Health': 100,
        'Domain_Reputation': 100,
        'WHOIS_Pattern': 100,
        'IP_Reputation': 100,
        'Credential_Safety': 100    
    }
    
    print(f"\n--- Calculating Scores (Reference Date: {scan_date.strftime('%Y-%m-%d')}) ---")
    
    # 2. Run each scan function, which will modify the scores dictionary
    # TODO: Simplify? All scans should always exist (remove if statements)
    score_cert_health(all_scans['cert_scan'], scan_date, scores)
        
    score_dns_rec_health(all_scans['dns_scan'], all_scans['rdap_scan'], scores)
        
    score_conn_sec(all_scans['hval_scan'], all_scans['cert_scan'], scores)
        
    score_dom_rep(all_scans['mail_scan'], all_scans['method_scan'], all_scans['rdap_scan'], scores)

    score_cred_safety(all_scans['cert_scan'], all_scans['hval_scan'], scores)

    # 3. Clamp scores between 1 and 100 after all deductions
    for key in scores:
        scores[key] = max(1, min(100, scores[key]))

    # 4. Calculate the final aggregated score
    if scores:
        # Note: calculate_final_score will ignore unused components with weight 0
        average_score = calculate_final_score(WEIGHTS, scores)
        scores['Aggregated_Score'] = round(average_score, 2)
        
    return scores

# --- Test Data ---
test_scans = {
    # Cert Scan Sample (Healthy, 61 days to expiration from 2025-10-15)
    'cert_scan': {
        "not_after":"2025-12-15T20:07:01.252",
        "not_before":"2025-09-16T20:11:24"
    },
    # DNS Scan Sample (Optimal: A, AAAA, Redundancy, rcode 3 implies A+AAAA)
    'dns_scan': {
        "rcode": 3,
        "a":["162.159.153.4","162.159.152.4"],
        "aaaa":["2606:4700:7::a29f:9804","2606:4700:7::a29f:9904"]
    },
    # HVAL Scan Sample (Strong: HTTPS enforced, modern TLS, HSTS+CSP+XCTO=7)
    'hval_scan': {
        "head":[
            {"status":301, "url":"http://medium.com"},
            {"status":200, "url":"https://medium.com/", "tls":"TLS_AES_128_GCM_SHA256"}
        ],
        "n":2,
        "security":7
    },
    # Mail Scan Sample (Excellent: p=reject DMARC, multiple MX, but SPF is ~all)
    'mail_scan': {
        "mx":["aspmx.l.google.com", "alt2.aspmx.l.google.com", "alt1.aspmx.l.google.com", "aspmx2.googlemail.com", "aspmx3.googlemail.com"],
        "spf":["v=spf1 include:amazonses.com ... ~all"],
        "dmarc":["v=DMARC1; p=reject; sp=reject; pct=100;fo=1; ri=3600;  rua=mailto:dmarc.rua@medium.com; ruf=mailto:dmarc.rua@medium.com,mailto:ruf@dmarc.medium.com"]
    },
    # Method Scan Sample (Optimal: Only HEAD (1) + GET (2) allowed)
    'method_scan': {
        "flag":3
    },
    # RDAP Scan Sample (Good: 2 servers, but same vendor)
    'rdap_scan': {
        "nameserver":["alina.ns.cloudflare.com", "kip.ns.cloudflare.com"]
    }
}

# --- Main execution block ---
if __name__ == '__main__':
    
    # 1. Setup argument parser
    parser = argparse.ArgumentParser(
        description="Get a security and infrastructure score for a target domain."
    )
    parser.add_argument(
        '-t', '--target',
        type=str,
        default=DEFAULT_URL,
        help=f"The target hostname to scan (e.g., {DEFAULT_URL})"
    )
    parser.add_argument(
        '--use-test-data',
        action='store_true',
        help="Run the script using the internal test_scans data instead of live API calls."
    )
    
    args = parser.parse_args()
    
    all_scans = {}
    scan_date = None

    # ----------------------------------------------------
    # START TIMER 
    start_time = time.time()
    # ----------------------------------------------------

    # 2. Decide whether to use test data or fetch live data
    if args.use_test_data:
        print(f"--- Running analysis on TEST DATA ---")
        all_scans = test_scans
        # For reproducible results, we'll set a fixed date for the expiration checks.
        # Cert Sample Expiration: 2025-12-15.
        scan_date = datetime(2025, 10, 15)
    else:
        print(f"--- Running analysis on LIVE DATA for {args.target} ---")
        # For live data, use the real date!
        scan_date = datetime.now()
        # *** CHANGED TO THE CONCURRENT FETCH FUNCTION ***
        all_scans = fetch_scan_data_concurrent(args.target)
    
    # 3. Check if we have data, then calculate and print scores
    if not all_scans:
        print("No scan data was retrieved. Exiting.")
        sys.exit(1)

    final_scores = calculate_security_score(all_scans, scan_date)
    
    # ----------------------------------------------------
    # END TIMER AND CALCULATE 
    end_time = time.time()
    elapsed_time = end_time - start_time
    # ----------------------------------------------------

    # Emit a single JSON object for the server (same contract as scoring_main.py).
    scores_out = {k: v for k, v in final_scores.items() if k != "Aggregated_Score"}
    payload = {
        "scores": scores_out,
        "Aggregated_Score": final_scores.get("Aggregated_Score"),
    }
    print(json.dumps(payload))

    # Human-readable summary to stderr (does not affect server parsing)
    print("\n--- Individual Scan Scores (Max 100) ---", file=sys.stderr)
    for key, value in final_scores.items():
        if key != "Aggregated_Score":
            print(f"{key:<15}: {value}", file=sys.stderr)
    print("\n-------------------------------------------", file=sys.stderr)
    print(f"AGGREGATED SECURITY SCORE: {final_scores.get('Aggregated_Score')}", file=sys.stderr)
    print(f"Total execution time: {elapsed_time:.2f} seconds", file=sys.stderr)
    print("-------------------------------------------", file=sys.stderr)


## --- Example of Expected 'all_scans' Structure ---
#     all_scans = {
#     'cert_scan': {
#         'host': 'netstar.ai',
#         'port': 443,
#         'timestamp': '2025-11-17T16:11:40Z',
#         'connection': { --> CONN_SEC
#             'tls_version': 'TLS 1.3',
#             'cipher_suite': 'TLS_AES_128_GCM_SHA256'
#         },
#         'verification': { --> WHOIS_PATTERN? 
#             'hostname_checked': 'netstar.ai',
#             'hostname_matches': True,
#             'chain_verified': True,
#             'chain_length': 3
#         },
#         # Certificate Chain (certs key is a list, details from Tree 2 & 3)
#         'certs': [ --> CERT_HEALTH
#             {
#                 'position': 0, # Assumed from context (Tree 2)
#                 'role': 'leaf',
#                 'subject_cn': 'netstar.ai',
#                 'subject_dns_names': ['netstar.ai', 'www.netstar.ai'], # Inferred from subject_cn context
#                 'not_before': '2024-11-20T14:00:00Z',
#                 'not_after': '2025-12-15T20:07:01Z',
#             },
#             {
#                 'position': 1,
#                 'role': 'intermediate',
#                 'subject_cn': 'Amazon RSA 2048 M03',
#                 # ... (other intermediate properties)
#             },
#         ]
#     },
#     'dns_scan': { --> DNS_REC_HEALTH
#         'rcode': 5,
#         'host': 'netstar.ai',
#         'a': ['35.160.83.94', '34.218.27.242', '44.234.206.55'],
#         'cname': ['netstar.ai'],
#         # ... (other expected records like AAAA, MX, TXT are omitted as they are not explicitly expanded)
#     },
#     'hval_scan': { --> CONN_SEC
#         'item': 'netstar.ai',
#         'security': 7, # HSTS(1), CSP(2), XCTO(4) all present
#         'n': 2,
#         'head': [
#             {
#                 'status': 301,
#                 'url': 'http://netstar.ai',
#                 'ip': ['35.160.83.94', '34.218.27.242'], # Example IP List
#             },
#             {
#                 'status': 200,
#                 'url': 'https://netstar.ai:443/',
#                 'ip': ['44.234.206.55', '35.160.83.94', '34.218.27.242'], # Example IP List (Tree 5)
#                 'tls': 'TLS_AES_128_GCM_SHA256', # Final TLS cipher (Tree 5)
#             }
#         ],
#     },
#     'mail_scan': { --> DOM_REP
#         'host': 'netstar.ai',
#         # ... (other expected mail data like mx, spf, dmarc are omitted, but exist in the API)
#     },
#     'method_scan': { --> DOM_REP
#         'url': 'netstar.ai',
#         'flag': 7 # Flag 7 corresponds to HEAD(1), GET(2), and POST(4) methods enabled.
#     },
#     'rdap_scan': { --> DOM_REP, WHOIS_PATTERN
#         'host': 'netstar.ai',
#         'nameserver': [
#             'ns-1834.awsdns-37.co.uk',
#             'ns-1158.awsdns-16.org',
#             'ns-938.awsdns-53.net',
#             'ns-291.awsdns-36.com'
#         ]
#     }
# }
