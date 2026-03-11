from typing import Dict, List

# --- Configuration and Constants ---

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

MAL_REGISTRARS = [
    "StanCo", "Istanco", "Hangzhou Yunji", "FlokiNET", "NauNet", "OPENPROV-RU", "DomainDelights", "Navicosoft Pty", "Shock Hosting",
    "nicenic.net", "DropCatch.com 1422",  "Dynu Systems Incorporated", "RegRU", "Hello Internet Corp", "PortlandNames.com", "Dynadot",
    "Sav.com", "Gname", "WebNic.cc", "Mat Bao Corporation", "Immaterialism Limited", "MAXNAME-RU", "FE-RU", "温州市中网计算机技术服务有限公司",
    "Namecheap", "Registrar R01.ru", "SPRINTNAMES-RU", "RegRU", "NIC.UA", "Namecheap", "NameSilo", "WebNic.cc", "Name SRS AB", "XServer",
    "PDR", "OwnRegistrar", "Trunkoz", "Hostinger", "GMO", "Tucows", "Sav.com", "Realtime Register", "RU-Center", "Name.com", "Openprovider",
    "Dominet", "GoDaddy", "Ultahost", "WebNic.cc", "河北识道网络科技有限公司", "MainReg Inc.", "Todaynic", "Eranet International" "长春市智绘网络科技有限公司",
    "厦门三五互联信息有限公司", "南昌知乐远科技有限公司", "长沙小豆网络科技有限公司", "西部数码国际有限公司", "GKG NET", "成都垦派科技有限公司",
    "四川域趣网络科技有限公司", "海口智慧康网络科技有限公司", "Global Domain Group", "Beijing Dongfang Ruipeng Digital Information Technology Co.",
    "武汉物与伦比科技有限公司", "厦门纳网科技股份有限公司", "成都西维数码科技有限公司", "west263.com", "rocket"
]


