VIGILANT Paper Overhaul Plan (Enhanced & Production-Ready)
Agent Instructions: Update CHAPTER_I.md, CHAPTER_II.md, and CHAPTER_III.md to reflect the implemented VIGILANT System architecture as of July 27, 2026.
═══════════════════════════════════════════════════════════════
CRITICAL CONTEXT & EMPIRICAL JUSTIFICATIONS FOR THE AGENT
═══════════════════════════════════════════════════════════════
The theoretical design of VIGILANT has been replaced with an edge-optimized implementation. The agent must update all narrative, methodology, and architectural claims using the factual specs and empirical rationales below:
1. Engagement-Time Model vs. RPM Model
The Implemented Fact: Detection uses a cumulative active engagement timer on social media domains, not a Requests-Per-Minute (RPM) velocity threshold.
The Empirical Rationale: Modern social media platforms rely on aggressive client-side caching, progressive chunk loading (HLS/DASH video streams), and batch background pre-fetching. An RPM model produces high false-positive rates during application startup (where 50+ requests execute in sub-second bursts) and high false-negative rates during active doomscrolling (where a user watches a 45-second reel while generating < 2 HTTP requests/minute). The engagement-time model aligns with psychometric models of doomscrolling by measuring sustained exposure rather than packet frequency.
Parameters:
Level 1 (Pause): 3 min cumulative duration → 128 kbps throttle.
Level 2 (Friction): 6 min cumulative duration → 32 kbps throttle.
Level 3 (Circuit Break): 12 min cumulative duration → 4 kbps throttle.
Reset Condition: 2 consecutive minutes of active idle (zero social traffic) resets engagement timers.
Evaluation Engine: Background evaluation thread polling every 30 seconds.
Scope Limits: Excludes DNS pre-fetch traffic; requires a minimum noise threshold of 10 social HTTP/TLS requests to trigger tracking initialization.
2. TF-IDF Vectorization vs. Deep Learning / spaCy NER
The Implemented Fact: Content categorization uses Scikit-Learn TfidfVectorizer with cosine similarity scoring against pre-computed category centroids, not spaCy Named Entity Recognition (NER).
The Empirical Rationale: In an inline edge-gateway processing encrypted web traffic for up to 30 concurrent users on an 8GB RAM host, running spaCy's deep learning pipeline introduces multi-millisecond per-packet latency overhead and high CPU context-switching. TF-IDF yields O(N) vector calculations, executing in microsecond-level speed, which preserves network throughput while effectively classifying payloads against four baseline target centroids (Educational, Productive, Distracting, Harmful).
Architecture:
Layered Priority Pipeline: (1) Dynamic Bypass List → (2) Category Hint Overrides → (3) Blacklist Keyword Matching → (4) TF-IDF Cosine Scoring → (5) Payload Sampling (512 KB prefix + 256 KB suffix inspection for payloads > 5 MB).
Threshold Limits: Cosine similarity cutoffs set to 0.15 for raw HTML page body text, 0.05 for domain hostnames, and 0.30 for raw URL paths.
3. Hardware & Network Interface Redesign
The Implemented Fact: The gateway host does not use internal Wi-Fi or Linux hostapd. Physical networking relies on a dual-NIC architecture connected to an external wireless access point via PCIe.
The Empirical Rationale: SoftAP modes (hostapd) suffer from driver-level instabilites under concurrent load and lack hardware offloading for multi-user MIMO. Offloading 802.11 Layer-1/Layer-2 physical radio management to a dedicated external Access Point isolates the VIGILANT server to focus exclusively on Layer-3/4 packet inspection, queuing, and routing.
Interfaces:
WAN Interface (enp0s31f6): DHCP client bound to upstream network.
LAN Interface (enp1s0): 172.20.10.1/24 gateway connected via PCIe-to-Ethernet adapter to external AP.
Routing Stack: dnsmasq (DHCP pool 172.20.10.10–172.20.10.250 + local DNS resolver), iptables NAT/MASQUERADE, and PREROUTING REDIRECT targeting local port 8080.
4. Traffic Shaping & Kernel Enforcement
The Implemented Fact: Bandwidth throttling uses Linux Kernel Traffic Control (tc) with Hierarchical Token Bucket (htb) qdisc attached to interface enp1s0.
Mechanics: Per-device classful hierarchy dynamically allocated via IP-derived classid. Bilateral filtering is applied using u32 matching on dst IP (download traffic) and src IP (upload traffic). A 2 KB burst allowance permits fast TCP 3-way handshakes and initial HTTP/TLS negotiation before applying the hard bandwidth floor, avoiding abrupt TCP connection reset errors (RST).
5. Resilient SSL/TLS Inspection & Bypass Pipeline
The Implemented Fact: MITM TLS decryption managed via mitmproxy running in transparent mode, augmented with automated SSL pinning resilience and SNI fallback tracking.
Mechanics: TLS handshake failures caused by client-side certificate pinning (e.g., banking apps, Apple system daemons) trigger automatic detection, logging the target SNI to an SQLite DB WAL file and adding the target to a persistent bypass table. Hardcoded bypasses prevent mobile OS lockups on core system traffic.
═══════════════════════════════════════════════════════════════
CHAPTER I CHANGES
═══════════════════════════════════════════════════════════════
CHANGE 1.1: Scope — Capacity Correction
LOCATION: CHAPTER_I.md, Scope of the Study
FIND: "up to five concurrent client devices"
REPLACE WITH: "up to thirty (30) concurrent client devices"
REASON: Aligns study parameters with stress testing under Specific Objective 5.
CHANGE 1.2: Scope — Network Interface Infrastructure
LOCATION: CHAPTER_I.md, Scope of the Study
FIND: "The system operates as a transparent access point using hostapd"
REPLACE WITH: "The system operates as a transparent network gateway using a dedicated external access point interfaced through a high-throughput PCIe-to-Ethernet adapter (enp1s0)"
CHANGE 1.3: Scope — Contextual Categorization Engine
LOCATION: CHAPTER_I.md, Scope of the Study
FIND: "the system performs contextual filtering through real-time Named Entity Recognition (NER)"
REPLACE WITH: "the system performs contextual filtering through Term Frequency-Inverse Document Frequency (TF-IDF) vector classification paired with cosine similarity and keyword augmentation"
CHANGE 1.4: Scope — Enforcement Mechanism
LOCATION: CHAPTER_I.md, Scope of the Study
FIND: "behavioral throttling, which applies logic-based bandwidth limitations when the system detects rapid request patterns associated with excessive browsing behavior on selected social media platforms"
REPLACE WITH: "behavioral throttling, which enforces multi-tier progressive bandwidth limitations (128 kbps, 32 kbps, and 4 kbps) triggered when the system detects sustained active engagement on social media domains exceeding configured temporal boundaries (3, 6, and 12 minutes, respectively)"
CHANGE 1.5: Limitation — Encrypted Traffic Handling
LOCATION: CHAPTER_I.md, Limitation of the Study
FIND: "the system relies on Server Name Indication (SNI) metadata to identify the domain being accessed and apply behavioral throttling mechanisms"
REPLACE WITH: "the system relies on Server Name Indication (SNI) metadata to identify domains and enforce throttling rules. Additionally, the system incorporates an automated SSL pinning discovery loop: applications exhibiting TLS handshake failures due to strict certificate pinning are auto-registered to a persistent bypass list to eliminate connection breaking, while SNI tracking continues to maintain behavioral oversight."
CHANGE 1.6: Definition — Behavioral Throttling
LOCATION: CHAPTER_I.md, Definition of Terms
REPLACE DEFINITION WITH:
Behavioral Throttling — Refers to the dynamic, multi-tier restriction of network throughput dictated by a client's cumulative engagement duration on designated media platforms. In this study, bandwidth is throttled in three distinct stages—Level 1 (128 kbps at 3 minutes), Level 2 (32 kbps at 6 minutes), and Level 3 (4 kbps at 12 minutes)—and is automatically restored following 2 minutes of continuous network idle state.
CHANGE 1.7: Definition — Request Velocity
LOCATION: CHAPTER_I.md, Definition of Terms
REPLACE DEFINITION WITH:
Request Velocity — Refers to the rate of HTTP/HTTPS requests directed to social media domains within a 60-second rolling window. In this system, request velocity acts as a secondary metric used alongside cumulative engagement time to eliminate initial application startup bursts during classification.
CHANGE 1.8: Definition — Engagement Time (NEW ENTRY)
LOCATION: CHAPTER_I.md, Definition of Terms (Insert after Edge Computing)
INSERT:
Engagement Time — Refers to the total active duration a client device interacts with target social media domains during a browsing session. It serves as the primary metric for triggering progressive bandwidth throttling based on continuous time thresholds.
═══════════════════════════════════════════════════════════════
CHAPTER II CHANGES
═══════════════════════════════════════════════════════════════
CHANGE 2.1: Content Categorization Analysis
LOCATION: CHAPTER_II.md, Related Literature on NLP in Network Edge Filtering
ACTION: Preserve historical context of spaCy/NER, then add the edge-optimization rationale:
ADD TEXT:
"While deep learning architectures and spaCy Named Entity Recognition (NER) models offer fine-grained entity extraction, their computational footprint presents a critical bottleneck when deployed directly on network edge gateways handling multi-user traffic streams. Running complex neural pipelines in real time increases microsecond packet latency and risks CPU exhaustion under peak load. In contrast, Term Frequency-Inverse Document Frequency (TF-IDF) vectorization combined with cosine similarity provides a lightweight, highly deterministic classification framework. TF-IDF yields predictable sub-millisecond execution times, making it ideal for resource-bounded gateway appliances operating within strict memory and compute budgets."
CHANGE 2.2: Digital Wellbeing & Engagement Duration Literature
LOCATION: CHAPTER_II.md, Literature on Behavioral Monitoring and Intervention
ADD TEXT:
"Recent studies in digital wellbeing favor time-bound engagement models over transaction-rate monitoring. Modern social web architectures heavily utilize client-side caching, local state persistence, and adaptive media streaming (e.g., HLS/DASH), rendering packet-frequency metrics unreliable. A user engaged in prolonged short-form video consumption may generate negligible request rates while accumulating significant screen time. Time-based engagement tracking mitigates false positives triggered by app startup bursts while providing a direct proxy for sustained platform exposure."
CHANGE 2.3: Kernel-Level Traffic Control Literature
LOCATION: CHAPTER_II.md, Literature on Traffic Shaping and Bandwidth Management
ADD/UPDATE: Frame the discussion around Linux Traffic Control (tc), specifically citing Hierarchical Token Bucket (htb) class structures, per-device class isolation, and dual-direction (u32) filtering on ingress and egress traffic queues.
═══════════════════════════════════════════════════════════════
CHAPTER III CHANGES (METHODOLOGY OVERHAUL)
═══════════════════════════════════════════════════════════════
CHANGE 3.1: Hardware & Network Topology Redesign
LOCATION: CHAPTER_III.md, System Architecture and Design
REPLACE SECTION WITH:
"The VIGILANT gateway operates on Ubuntu Server 24.04 LTS (8GB RAM) configured with a dual Network Interface Card (NIC) layout.
                  [ Upstream Router / Internet ]
                                │
                        (WAN: enp0s31f6)
                                │
                    ┌───────────┴───────────┐
                    │   VIGILANT Gateway    │
                    │   (Ubuntu Server)     │
                    └───────────┬───────────┘
                        (LAN: enp1s0)
                                │
                 [ PCIe-to-Ethernet Adapter ]
                                │
               [ External Wireless Access Point ]
                    │           │           │
                [Client 1]  [Client 2]  [Client N (up to 30)]
Interface enp0s31f6 handles the WAN uplink via upstream DHCP. Interface enp1s0 serves as the local area gateway (172.20.10.1/24) connected via a high-speed PCIe adapter to an external wireless access point. Network clients obtain leases through dnsmasq in the 172.20.10.10–172.20.10.250 subnet. All traffic routed over ports 80 and 443 is redirected to the transparent proxy via iptables PREROUTING rules."
CHANGE 3.2: NLP Categorization Engine (TF-IDF Specification)
LOCATION: CHAPTER_III.md, Content Inspection Engine
REPLACE SECTION WITH:
"The content inspection engine uses a Scikit-Learn TfidfVectorizer pipeline to calculate cosine similarity scores between incoming web content and pre-computed centroids across four target categories: Educational, Productive, Distracting, and Harmful.
The classification pipeline evaluates requests in five hierarchical stages:
Bypass Verification: Checks if the domain exists within the dynamic or static bypass tables; if present, inspection is skipped.
Explicit Hint Resolution: Checks hardcoded domain-to-category override mappings.
Blacklist Pattern Matching: Scans the URL path and payload headers against blacklisted keyword patterns to trigger immediate blocks on harmful content.
TF-IDF Cosine Classification: Transforms body text into TF-IDF term vectors and calculates the cosine distance S 
C
​	
  against centroid vectors V 
C
​	
 :
S 
C
​	
 = 
∥A∥∥V 
C
​	
 ∥
A⋅V 
C
​	
 
​	
 
A category is assigned if S 
C
​	
  exceeds configured bounds (0.15 for body text, 0.05 for domain names, 0.30 for URLs).
Sampled Payload Scanning: For payloads exceeding 5 MB, inspection is limited to a 512 KB prefix and a 256 KB suffix buffer to prevent gateway memory exhaustion."
CHANGE 3.3: Behavioral Monitoring and Throttling Engine
LOCATION: CHAPTER_III.md, Behavioral Control System
REPLACE SECTION WITH:
"The system utilizes an engagement-time tracking engine designed specifically for modern media consumption behaviors.
3.3.1 Domain Identification
The engine maintains an updating database of social media domains and CDN hostnames (*.facebook.com, *.fbcdn.net, *.tiktok.com, *.tiktokcdn.com, *.googlevideo.com, *.x.com, *.reddit.com). Traffic matching these SNI patterns is categorized as target social media activity.
3.3.2 Engagement State Management
For every connected client IP, the tracking engine maintains an isolated state object:
engagement_start: Timestamp of the initial social request.
engagement_last_request: Timestamp of the most recent social request.
engagement_minutes: Total cumulative exposure duration.
engagement_current_level: Active throttle tier (L 
0
​	
  through L 
3
​	
 ).
Tracking initiates only after observing a baseline threshold of 10 distinct social requests to filter out background application pings. DNS requests are ignored to prevent background system pre-fetching from corrupting the engagement timer.
3.3.3 Background Loop & Escalation Schedule
An asynchronous evaluation thread checks all active client sessions every 30 seconds:
Level 1 (Pause): Duration ≥3 min→ Enforces 128 kbps limit.
Level 2 (Friction): Duration ≥6 min→ Enforces 32 kbps limit.
Level 3 (Circuit Break): Duration ≥12 min→ Enforces 4 kbps limit.
3.3.4 Bandwidth Shaping Infrastructure
Bandwidth shaping is executed via Linux Traffic Control (tc). When a device transitions to an active throttle level, VIGILANT injects an HTB class on interface enp1s0:
Bash
tc class add dev enp1s0 parent 1: classid 1:<ID> htb rate <LIMIT>kbit ceil <LIMIT>kbit burst 2k
tc filter add dev enp1s0 parent 1: protocol ip prio 1 u32 match ip dst <CLIENT_IP> flowid 1:<ID>
tc filter add dev enp1s0 parent 1: protocol ip prio 1 u32 match ip src <CLIENT_IP> flowid 1:<ID>
The burst 2k configuration allows TCP handshakes to resolve without dropping the socket, ensuring stability while limiting overall throughput.
3.3.5 State Recovery and Unthrottle Mechanics
If no social media traffic is observed for a continuous 2-minute window, the background loop clears the active tc queues, resets engagement_start to null, and restores full unthrottled access. System administrators can also trigger manual state resets via the Flask dashboard."
CHANGE 3.4: Comprehensive Testing Framework
LOCATION: CHAPTER_III.md, Testing and Validation Protocols
REPLACE TEST SPECIFICATIONS WITH:
"Validation covers three core phases:
Engagement Accuracy Tests: Synthetic and live browsing sessions simulating 5, 10, and 15 minutes of uninterrupted social video streaming to verify exact time-tier throttle triggers.
Session Reset Verification: Intermittent consumption runs interrupted by 2+ minutes of idle activity to confirm timer zeroing and tc queue purging.
Concurrency Benchmarking: Multi-device loads scaling up to 30 concurrent client devices running mixed traffic (video streams, web browsing, background app sync) to assess gateway throughput, latency impact, and SQLite WAL thread safety."
CHANGE 3.5: Software Stack Specifications
LOCATION: CHAPTER_III.md, Technical Specifications
UPDATE TABLE/LISTING TO:
Operating System: Ubuntu Server 24.04 LTS (Kernel 6.8)
Language Runtime: Python 3.12
Proxy Layer: mitmproxy (Transparent Proxy Mode)
Web Dashboard: Flask (Session-authenticated, running on port 5000, UTC+8 time formatting)
Database Layer: SQLite3 with Write-Ahead Logging (WAL) enabled
Data Science/NLP Libraries: Scikit-Learn (TfidfVectorizer), NumPy
Core System Utilities: iptables, tc (iproute2 package), dnsmasq, systemd
═══════════════════════════════════════════════════════════════
EXECUTION PLAN
═══════════════════════════════════════════════════════════════
To apply these updates cleanly, execute edits in this order:
Update CHAPTER_III.md (Contains the largest structural changes).
Update CHAPTER_I.md (Aligns scope parameters, limitations, and definitions).
Update CHAPTER_II.md (Integrates the literature rationales).

═══════════════════════════════════════════════════════════════
ADDITIONAL CHAPTER III CHANGES
═══════════════════════════════════════════════════════════════

CHANGE 3.6: Administrative Dashboard Specification
LOCATION: CHAPTER_III.md, Monitoring and Management Layer
ADD/REPLACE SECTION WITH:
"The administrative dashboard is a Flask-based web application served on port 5000, accessible from the WAN interface (192.168.100.88:5000) for administrative convenience. Access is protected by session-based authentication using werkzeug password hashing with a first-run setup flow for initial password configuration.

The dashboard comprises seven functional tabs:
1. System (Nerve Center): Displays real-time interface throughput (Rx/Tx Mbps), active/throttled device counts via the circuit breaker panel, service health status for mitmproxy and dnsmasq, and hardware resource metrics (CPU, RAM, storage).
2. Device Management: Shows currently throttled devices with per-device release controls, active devices seen within a 2-minute window, and DHCP lease bindings with configurable whitelist/blacklist filter policies per MAC address.
3. Traffic Logs: Paginated table of decrypted HTTP traffic with category badges, keyword match indicators, CSV export, and log clearing controls.
4. Content Filtering: Keyword enforcement with add/remove controls, active keyword table, domain bypass list management (add/remove domains that skip MITM inspection), and category routing rules for domain-to-category overrides.
5. Behavioral Control: Preset mode selector (Relaxed/Balanced/Strict/Custom) mapping to configurable engagement time thresholds (L1 at 3/5/2 min, L2 at 6/10/4 min, L3 at 12/20/8 min) with an idle reset timer (default 2 min).
6. SNI Monitoring: Encrypted app traffic charts (scroll rate by domain, top domains by request count), paginated SNI request log with domain search, time window selectors (1m to 12h), and throttle reset controls.
7. Setup: Network interface configuration, DHCP range and DNS settings, content blocking toggles, advanced NLP/throttle/password/backup settings."

CHANGE 3.7: Database Persistence Layer
LOCATION: CHAPTER_III.md, Data Management section (or add new subsection)
ADD SECTION:
"The system uses SQLite3 with Write-Ahead Logging (WAL) mode enabled for concurrent read/write access across the proxy addon and dashboard processes. The database schema consists of seven core tables:
- traffic_log: Records of decrypted HTTP requests with timestamp, client IP, host, path, method, category classification, flag status, and block reason.
- sni_requests: TLS Server Name Indication records with timestamp, client IP, domain, request count, and computed velocity in requests per second.
- throttle_events: Audit log of throttle applications and releases with RPM context and action type.
- throttle_state: Current throttle status per client IP with cycle count tracking.
- network_devices: Device registry with IP/MAC/hostname, policy assignments, doomscroll exemption flags, and last-seen timestamps.
- config_settings: Key-value store for all system configuration including engagement thresholds, bypass domains, network interfaces, and authentication credentials.
- category_hints: Manual domain-to-category mapping overrides.
- keyword_blacklist: Explicit blocked keyword registry.

WAL mode enables the mitmproxy addon and Flask dashboard to access the database concurrently without locking conflicts, critical for maintaining proxy throughput while the dashboard renders real-time statistics."

CHANGE 3.8: SSL Pinning Resilience System
LOCATION: CHAPTER_III.md, Traffic Interception Layer or SSL/TLS section
ADD SECTION:
"To address the limitation of SSL certificate pinning in mobile applications, the system implements a multi-layered bypass architecture:

1. Custom Bypass List: Administrators can configure domains that skip MITM inspection entirely through the Content Filtering dashboard tab. These domains and all their subdomains are routed directly without decryption. Default bypass entries include CDN infrastructure for major social platforms (fbcdn.net, tiktokcdn.com, googlevideo.com) to prevent latency on video content delivery.

2. Automatic Pinning Discovery: The mitmproxy tls_failed_client hook captures TLS handshake failures caused by client-side certificate pinning. When an application rejects the proxy's CA certificate, the system logs the offending Server Name Indication (SNI), adds it to mitmproxy's runtime ignore_hosts list for immediate pass-through, and persists the domain to the database bypass table for survival across proxy restarts.

3. Hardcoded System Bypasses: Core Apple infrastructure domains (apple.com, icloud.com, mzstatic.com) are permanently bypassed to prevent operating system-level freezes caused by iOS's strict certificate validation for system services.

This layered approach ensures that SSL-pinned applications remain functional while the system maintains behavioral monitoring capability through SNI metadata tracking, which operates at the TLS ClientHello level before certificate exchange occurs."

CHANGE 3.9: Transparent Proxy Implementation Detail
LOCATION: CHAPTER_III.md, Traffic Interception Layer
ADD/CLARIFY:
"Traffic interception is achieved through a combination of iptables netfilter rules and mitmproxy operating in transparent mode:

iptables -t nat -A PREROUTING -i enp1s0 -p tcp --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -i enp1s0 -p tcp --dport 443 -j REDIRECT --to-ports 8080

These rules redirect all HTTP (port 80) and HTTPS (port 443) traffic entering the LAN interface to mitmproxy's listening port (8080). Because the redirection occurs at the PREROUTING chain before routing decisions, client devices require no manual proxy configuration — the interception is fully transparent. NAT masquerading on the WAN interface enables outbound internet access:

iptables -t nat -A POSTROUTING -o enp0s31f6 -j MASQUERADE

The proxy operates as a systemd service (vigilant-proxy.service) with automatic restart on failure, and the firewall rules are persisted via iptables-persistent for survival across system reboots."

═══════════════════════════════════════════════════════════════
WHAT NOT TO CHANGE
═══════════════════════════════════════════════════════════════
The following elements should be PRESERVED as-is in all chapters:
- All existing citations and reference numbers in brackets
- The 7-layer conceptual framework structure
- The V-Model SDLC methodology description
- All researcher names, university affiliations, and acknowledgment text
- The general problem statement about Philippine internet usage statistics
- The significance of the study sections for each stakeholder group
- All definition of terms entries not explicitly listed for replacement above
- The chapter heading structures and numbering

═══════════════════════════════════════════════════════════════
VERIFICATION CHECKLIST FOR THE AGENT
═══════════════════════════════════════════════════════════════
After applying all changes, verify the following cross-chapter consistencies:

□ Device count is "30" everywhere (Scope, Objective 5, Testing sections)
□ Detection method is "engagement-time" not "request velocity" or "RPM" everywhere
□ NLP method is "TF-IDF" not "spaCy NER" as the implementation choice
□ Hardware mentions "PCIe-to-Ethernet adapter" and "external access point" not "hostapd"
□ Throttle levels are consistently "128/32/4 kbps" not "dynamic bandwidth throttling"
□ Time thresholds are "3/6/12 minutes" not "150% of baseline" or "configurable velocity"
□ No internal WiFi card or hostapd references remain
□ SSL pinning section mentions auto-discovery and bypass persistence
□ Dashboard is described as Flask on port 5000 with session auth
□ Database is SQLite with WAL mode
□ Software stack includes scikit-learn, not just spaCy
□ All original citations remain intact and unmodified