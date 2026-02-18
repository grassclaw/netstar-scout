from typing import Dict, List

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
    'Connection_Security': 18,
    'Certificate_Health': 15,
    'DNS_Record_Health': 14,
    'Domain_Reputation': 24,    
    'WHOIS_Pattern': 10, #unused currently
    'IP_Reputation': 2, #unused currently (probably won't be used)
    'Credential_Safety': 17
}


BASE_URL = 'https://w4.netstar.dev/'
API_ENDPOINTS = [
    'cert', 
    'dns', 
    'hval', 
    'mail', 
    'method', 
    'rdap',
    'firewall'
]

# Default target hostname used if no argument is provided
DEFAULT_URL = 'netstar.ai' 

# Verbose mode flag
VERBOSE = False

MAL_TLDS = [
    "ac", "ai", "app", "at", "autos", "biz", "bond", "br", "bz", "ca", "cc",
    "cfd", "claims", "click", "cn", "co", "com", "coupons", "courses",
    "cx", "cy", "cyou", "dad", "de", "digital", "es", "eu", "fan",
    "finance", "fit", "fr", "fun", "gay", "gd", "gg", "help", "hk",
    "icu", "id", "im", "in", "info", "ink", "io", "is", "life", "live",
    "locker", "me", "mobi", "money", "ms", "my", "net", "network", "ng",
    "nl", "online", "org", "pl", "pro", "pw", "qpon", "rest", "rocks",
    "ru", "sbs", "sh", "shop", "site", "so", "st", "store", "su",
    "support","tel", "to", "today", "top", "tr", "tv", "ua", "uk",
    "us", "vip", "wiki", "world", "ws" ,"xn--q9jyb4c" ,"xyz"
]

MAL_TLDS_SLIM = [ #removed co, com, eu, uk, org, net
    "ac", "ai", "app", "at", "autos", "biz", "bond", "br", "bz", "ca", "cc",
    "cfd", "claims", "click", "cn", "coupons", "courses",
    "cx", "cy", "cyou", "dad", "de", "digital", "es", "fan",
    "finance", "fit", "fr", "fun", "gay", "gd", "gg", "help", "hk",
    "icu", "id", "im", "in", "info", "ink", "io", "is", "life", "live",
    "locker", "me", "mobi", "money", "ms", "my", "network", "ng",
    "nl", "online", "pl", "pro", "pw", "qpon", "rest", "rocks",
    "ru", "sbs", "sh", "shop", "site", "so", "st", "store", "su",
    "support","tel", "to", "today", "top", "tr", "tv", "ua",
    "us", "vip", "wiki", "world", "ws", "xn--q9jyb4c", "xyz"
]
