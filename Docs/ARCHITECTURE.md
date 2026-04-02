# NetSTAR Shield — System Architecture

This document describes the actual system architecture as implemented in this repository.

## Diagram 1 — Full System Architecture

```mermaid
graph TB
  subgraph browserLayer [BrowserLayer]
    direction TB
    user[User]
    popup["ExtensionPopupUI (React)"]
    sw["BackgroundServiceWorker (MV3)"]
    cs["ContentScript (InPageOverlay)"]

    storageLocal["chrome.storage.local"]
    storageSync["chrome.storage.sync"]
    actionIcon["chrome.action"]
    notif["chrome.notifications"]
    tabsApi["chrome.tabs"]

    user --> popup
    user --> tabsApi
    popup <-->|"chrome.runtime.sendMessage"| sw
    cs <-->|"chrome.runtime.sendMessage"| sw
    tabsApi -->|"onUpdated/onActivated"| sw

    sw <-->|"cache,recentScans,toggles"| storageLocal
    popup <-->|"theme,textSize"| storageSync
    sw -->|"setIcon"| actionIcon
    sw -->|"create_notification (optional)"| notif
  end

  subgraph serverLayer [ServerLayer_(SameHost)]
    direction TB
    node["NodeExpressServer (Server/server.js)"]
    py["PythonScoringEngine (Scoring Engine/scoring_main.py)"]
    node -->|"spawn_subprocess stdout(JSON)"| py
  end

  subgraph externalLayer [ExternalLayer]
    direction TB
    netstar["w4.netstar.dev"]
  end

  sw -->|"HTTP fetch GET /scan"| node
  py -->|"HTTPS curl concurrent"| netstar
```

## Diagram 2 — Scan Request Lifecycle (Auto-Scan + Side Effects)

```mermaid
sequenceDiagram
  participant User
  participant Browser
  participant Tabs as "chrome.tabs"
  participant SW as BackgroundServiceWorker
  participant Store as "chrome.storage.local"
  participant Node as NodeExpressServer
  participant Py as PythonScoringEngine
  participant NetSTAR as "w4.netstar.dev"
  participant Icon as "chrome.action"
  participant CS as ContentScript
  participant Notif as "chrome.notifications"

  User->>Browser: Navigate_to_URL
  Browser->>Tabs: tab_load_complete
  Tabs->>SW: onUpdated(tabId,status=complete,url)

  SW->>Store: get(cacheKey)
  alt cache_hit_and_fresh
    Store-->>SW: cached_result
  else cache_miss_or_expired
    SW->>Node: GET_/scan?domain=example.com
    Node->>Node: normalizeScanTarget(domain_or_url)
    Node->>Py: spawn(scoring_main.py_-t_example.com)

    par fetch_cert
      Py->>NetSTAR: GET /cert/example.com
    and fetch_dns
      Py->>NetSTAR: GET "/dns/example.com?A&AAAA&CNAME&DNS&MX&TXT"
    and fetch_hval
      Py->>NetSTAR: GET /hval/example.com
    and fetch_mail
      Py->>NetSTAR: GET /mail/example.com
    and fetch_rdap
      Py->>NetSTAR: POST "/rdap {host: example.com, full: true}"
    and fetch_firewall
      Py->>NetSTAR: GET /firewall/example.com
    end

    NetSTAR-->>Py: JSON_payloads
    Py-->>Node: stdout(JSON_scores+aggregatedScore)
    Node-->>SW: "JSON {safetyScore, indicators, timestamp}"
    SW->>Store: set(cacheKey,result)
  end

  SW->>Icon: setIcon(based_on_safetyScore)
  SW->>Store: updateRecentScans(url,safetyScore)

  opt risky_site(safetyScore_below_threshold)
    SW->>CS: sendMessage(showAlert)
    SW->>Notif: create_notification_if_enabled
  end
```

## Diagram 3 — Extension Component Architecture

```mermaid
graph LR
  subgraph popupUI [PopupUI_(React)]
    direction TB
    popupRoot["popup.jsx"]
    tabHome[HomeTab]
    tabScan[ScanTab]
    tabDetails[DetailsTab]
    tabSettings[SettingsTab]
    tour[Tour]

    popupRoot --> tabHome
    popupRoot --> tabScan
    popupRoot --> tabDetails
    popupRoot --> tabSettings
    popupRoot --> tour
  end

  subgraph serviceWorker [BackgroundServiceWorker]
    direction TB
    bgEntry["background.js"]
    bgMessages["background/messages.js"]
    bgTabs["background/tabs.js"]
    bgScan["background/scan.js"]
    bgIcon["background/icon.js"]
    bgRecent["background/recentScans.js"]
    bgNotif["background/notifications.js"]
    bgInstall["background/install.js"]
    bgNormalize["background/urlNormalize.js"]
    bgConst["background/constants.js"]

    bgEntry --> bgInstall
    bgEntry --> bgTabs
    bgEntry --> bgMessages

    bgMessages --> bgScan
    bgMessages --> bgIcon
    bgMessages --> bgRecent
    bgMessages --> bgNotif

    bgTabs --> bgScan
    bgTabs --> bgIcon
    bgTabs --> bgRecent
    bgTabs --> bgNotif

    bgScan --> bgNormalize
    bgScan --> bgConst
    bgIcon --> bgConst
    bgRecent --> bgConst
    bgNotif --> bgConst
  end

  subgraph inPage [InPage]
    direction TB
    contentEntry["content.js"]
    overlay["ShadowDOM_Overlay"]
    contentEntry --> overlay
  end

  popupRoot <-->|"chrome.runtime.sendMessage"| bgMessages
  contentEntry <-->|"chrome.runtime.onMessage"| bgMessages
```

## Diagram 4 — Scoring Engine Data Flow (What Gets Scored)

```mermaid
graph TB
  target[TargetDomain]
  scoringMain["scoring_main.py"]
  fetcher["data_fetch.py (curl + ThreadPoolExecutor)"]
  logic["scoring_logic.py"]
  cfg["config.py (BASE_URL, API_ENDPOINTS, WEIGHTS)"]

  target --> scoringMain
  scoringMain --> fetcher
  scoringMain --> logic
  scoringMain --> cfg

  subgraph netstarEndpoints [w4_netstar_dev_endpoints]
    cert[cert]
    dns[dns]
    hval[hval]
    mail[mail]
    rdap[rdap]
    firewall[firewall]
  end

  fetcher --> cert
  fetcher --> dns
  fetcher --> hval
  fetcher --> mail
  fetcher --> rdap
  fetcher --> firewall

  cert --> logic
  dns --> logic
  hval --> logic
  mail --> logic
  rdap --> logic
  firewall --> logic

  subgraph categoryScores [CategoryScores_0_to_100]
    conn["Connection_Security"]
    certHealth["Certificate_Health"]
    dnsHealth["DNS_Record_Health"]
    domainRep["Domain_Reputation"]
    whois["WHOIS_Pattern"]
    ipRep["IP_Reputation"]
    cred["Credential_Safety"]
  end

  logic --> conn
  logic --> certHealth
  logic --> dnsHealth
  logic --> domainRep
  logic --> whois
  logic --> ipRep
  logic --> cred

  aggregate[WeightedHarmonicMean]
  conn --> aggregate
  certHealth --> aggregate
  dnsHealth --> aggregate
  domainRep --> aggregate
  whois --> aggregate
  ipRep --> aggregate
  cred --> aggregate

  aggregate --> aggregatedScore[aggregatedScore]
```

## Diagram 5 — Deployment Architecture (As Documented in Repo)

```mermaid
graph TB
  dev[DeveloperMachine]
  repo[GitRepo]
  gha["GitHubActions CI"]
  remote["RemoteServer (VM)"]

  subgraph deployed [RemoteRuntime]
    node[NodeExpress_(Server/server.js)]
    python[Python3_Runtime]
    score["ScoringEngine (Scoring Engine)"]
    node -->|"spawn"| score
    score -->|"curl"| netstar["w4.netstar.dev"]
  end

  dev --> repo
  repo --> gha
  dev -->|"deploy.sh (ssh + tar)"| remote
  remote --> node
  remote --> python
  remote --> score

  subgraph extensionDist [ExtensionDistribution]
    unpacked["UnpackedExtension (dev)"]
    webstoreZip["netstar-shield-webstore.zip (build artifact)"]
  end

  dev --> unpacked
  dev -->|"npm_run_pack"| webstoreZip
```

