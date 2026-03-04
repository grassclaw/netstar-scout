import json
import subprocess
from typing import Optional, List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor
from config import BASE_URL, API_ENDPOINTS
import sys
import config as app_config

# --- Data Fetching Function (Using 'curl' subprocess) ---

def execute_curl_command(command: List[str]) -> Optional[str]: #KEEP
    """
    Executes a shell command (cURL) and returns the standard output.
    Handles potential errors during execution.
    """
    if app_config.VERBOSE:
        print(f"Executing command: {' '.join(command)}", file=sys.stderr)
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
            if app_config.VERBOSE:
                print(f"Error executing command. Return code: {result.returncode}", file=sys.stderr)
                print(f"Standard Error:\n{result.stderr.strip()}", file=sys.stderr)
            return None

        # The output is returned as a string (JSON)
        return result.stdout.strip()

    except FileNotFoundError:
        if app_config.VERBOSE:
            print("Error: The 'curl' command was not found. Make sure it is installed and in your system PATH.", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        if app_config.VERBOSE:
            print("Error: Command execution timed out.", file=sys.stderr)
        return None
    except Exception as e:
        if app_config.VERBOSE:
            print(f"An unexpected error occurred during execution: {e}", file=sys.stderr)
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
    

    # 3. Define the cURL command (with exception for RDAP POST)
    if app_config.VERBOSE:
        print(f"\n[Processing Endpoint: {endpoint.upper()}]", file=sys.stderr)
    
    CURL_COMMAND = [] # Initialize command list

    # --- EXCEPTION LOGIC FOR RDAP POST REQUEST ---
    if endpoint == 'rdap':
        # Target: curl -X POST https://w4.netstar.dev/rdap -d '{"host": "espn.com", "full": true}'
        
        # The URL in this specific POST case is just the base endpoint, not {endpoint}/{host}
        rdap_url = f"{BASE_URL}{endpoint}" 
        json_data = f'{{"host": "{host}", "full": true}}'
        
        CURL_COMMAND = [
            'curl', 
            '-s', 
            '-X', 'POST', 
            rdap_url, 
            '-d', json_data
        ]
        
    # --- DEFAULT LOGIC (for all other GET requests) ---
    else:
        # Target: curl -s {full_url}
        CURL_COMMAND = ['curl', '-s', full_url]


    # 4. Execute the command
    output = execute_curl_command(CURL_COMMAND)
    
    if output is None:
        if app_config.VERBOSE:
            print(f"--> Endpoint {endpoint.upper()} failed execution. Skipping.", file=sys.stderr)
        return (None, None)

    # 5. Parse the JSON output
    try:
        data = json.loads(output)
        # Note: Printing final success message after command execution for clarity
        return (scan_key, data)
    except json.JSONDecodeError:
        if app_config.VERBOSE:
            print(f"--> Endpoint {endpoint.upper()} returned invalid JSON. Skipping.", file=sys.stderr)
        return (None, None)
    except Exception as e:
        if app_config.VERBOSE:
            print(f"--> An error occurred processing {endpoint.upper()}: {e}", file=sys.stderr)
        return (None, None)

def fetch_scan_data_concurrent(host: str) -> dict: 
    """
    Coordinates concurrent fetching of scan data from all API endpoints 
    using a ThreadPoolExecutor.
    """
    all_scans = {}
    if app_config.VERBOSE:
        print(f"\n--- Fetching live data for {host} from NetStar API (via concurrent cURL) ---", file=sys.stderr)
    print(f"\"url\": \"{host}\"")

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
                
    if app_config.VERBOSE:
        print("\n--- Data fetching complete ---", file=sys.stderr)
    return all_scans
