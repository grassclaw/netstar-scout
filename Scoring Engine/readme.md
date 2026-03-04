# Scoring Engine

## Current Functionality
As of December 8th, this code can do the following:
* Uses `curl` to call NetSTAR endpoints (cert, dns, hval, mail, method, rdap)
* Gives each category a score using telemetry from the endpoints and based off of the scoring matrix document
* Puts all the cateogory scores through the scoring engine (using harmonic mean) to get final score
* Presents the deductions and final scores

What it is missing:
* Exceptions are needed for when data is missing
* All scoring needs to be reviewed and finetuned 
* Adding in gates for the specified tools (once grading is migrated to tool format)
* Bug Fix: Final score printing to screen creates duplicates
These functionalities will be included next

## How to use the Code
Use `python scoring_main.py -h` to get the basic flag info

if run without a target URL, it will default to netstar.ai

run `python scoring_main.py -t [TARGET URL]` to test against target URL
* If the cert scan fails, running it again may work

run `python scoring_main.py -v` to get additional information on the execution of curl commands, reasons for score deductions, and runtime information

For running the test suite, see [TESTING.md](TESTING.md).

## Fine-tune February  
Listed below are all of the things that need attention:  
* scoring_main.py
  * Can probably be streamlined/improved --> **Koby**
* **scoring_logic.py**
  * Error handling needed for bad urls/expired websites --> **Katelyn**
  * Implement gates on the chosen categories
  * Implement scoring based on TLDs in dom_rep --> **Cameron**
    * Resolved? Single list of known malicious TLDs used, no gradient used
  * Implement scoring based on registrars in WHOIS_pattern --> **FCFS**
  * cred_safety needs a rehaul --> **Kendel**
    * Repetitive scoring from conn_sec
  * Look into positive scoring to distinguish more between good/bad sites
  * Expand JSON output for the server
  * conn_sec score = 1 may mean that data is not being processed correctly --> **Cameron**
    * Should be resolved. Also, bug fixed when no connection made, score was left 100 with error exit. Now, it catches and drops score
* data_fetch.py
  * Can probably be more streamlined --> Koby
* With subdomain `speeches.byu.edu` rdap doesn't return anything
  * The rdap is connected with `byu.edu`
* Build in FireHOL for IP Reputation




