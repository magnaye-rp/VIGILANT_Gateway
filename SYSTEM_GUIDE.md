# VIGILANT Gateway System Guide

## 1. System Overview
VIGILANT Gateway is a hardware-agnostic, network-level appliance designed to combat "doomscrolling" and addictive behavioral loops. Instead of relying on on-device screen time apps (which can easily be bypassed or ignored), VIGILANT operates at the network gateway level (e.g., a Raspberry Pi acting as a Wi-Fi access point). 

It transparently intercepts web traffic, analyzes behavioral patterns (like endless scrolling), and uses **friction** (bandwidth throttling) to break dopamine loops without completely disconnecting the user from the internet.

## 2. Core Dependencies & Why They Are Used

The system is built on a modular stack of open-source Linux utilities and Python libraries:

- **`mitmproxy`:** The core engine of the system. It acts as a transparent proxy that intercepts and decrypts HTTP/HTTPS traffic. We use it because of its powerful Python API, which allows us to write custom scripts to analyze requests in real-time, modify headers, and extract usage telemetry.
- **`Flask` & `Gunicorn`:** A lightweight Python web framework and WSGI server used to build and serve the "Nerve Center" dashboard. Flask was chosen for its simplicity and ease of integration with SQLite, allowing for rapid development of the admin UI and REST APIs.
- **`SQLite3` (with WAL mode):** The database engine. We use SQLite because it requires no separate server process, making it perfect for an embedded gateway device. Write-Ahead Logging (WAL) mode is explicitly enabled to allow concurrent reads and writes, meaning the proxy can write logs while the dashboard reads them without locking each other out.
- **Linux `tc` (Traffic Control):** The utility used to enforce bandwidth limits. When doomscrolling is detected, the system executes `tc` commands to shape the client's traffic down to slow 2G/3G speeds. This introduces the "friction" needed to break the habit.
- **`iptables`:** Used for network routing and NAT. It transparently redirects port 80/443 traffic coming from connected devices into the `mitmproxy` listening port, ensuring devices don't need manual proxy configuration.
- **`dnsmasq` & `hostapd`:** Standard Linux utilities used to broadcast the Wi-Fi network (hostapd) and assign IP addresses / handle DNS resolution (dnsmasq). This allows the gateway to function as a standalone router.

## 3. How the System Works (Architecture)

The system is divided into two primary daemon processes that run concurrently and communicate via the SQLite database:
1. **The Proxy Process (`vigilant-proxy.service`)** running `mitmproxy` with `src/vigilant_addon.py`.
2. **The Dashboard Process (`vigilant-dashboard.service`)** running the Flask app in `src/app.py`.

### A. Traffic Interception & Categorization (`vigilant_addon.py`)
When a device connects to the network, its web traffic flows through the proxy.
- **TF-IDF Classification:** The addon inspects the URLs and body of the requests. It uses a custom TF-IDF (Term Frequency-Inverse Document Frequency) algorithm to classify the traffic into categories (e.g., Social Media, Video, News) based on predefined keywords and hints.
- **Keyword Blacklisting:** Simple keyword matching is used to quickly flag known addictive platforms (e.g., TikTok, Instagram).

### B. Doomscroll Detection & Burst Filtering
VIGILANT doesn't just block websites; it monitors *how* they are used. 
- The proxy maintains a rolling 60-second window of request timestamps for every active IP address.
- It calculates the **Velocity (Requests Per Second)**. 
- **Burst Detection:** A normal page load might fire 80 requests instantly. The system looks at the time elapsed between the first and last request in a batch. If the requests happened in under 10 seconds, it's ignored as a page load. If high request volume is sustained over a longer period, it indicates continuous swiping/scrolling (doomscrolling).

### C. Bandwidth Throttling (Friction)
When doomscrolling is detected:
1. The proxy triggers `should_throttle`, marking the client as flagged.
2. A `subprocess` calls Linux `tc` to artificially limit the client's MAC/IP address to a severely degraded bandwidth (e.g., 50kbps).
3. The throttle is recorded in the `throttle_state` database table, and an automatic recovery timer (e.g., 2 minutes) is started. 
4. Once the timer expires, the `tc` rules are cleared, and normal speeds are restored.

### D. Encrypted App Telemetry (SNI Tracking)
Many modern mobile apps (like native Instagram or TikTok apps) use **SSL Pinning**, meaning they refuse to connect if `mitmproxy` tries to decrypt their traffic.
- VIGILANT detects this and automatically allows the traffic to pass through untouched so the apps don't break.
- However, it still monitors the **SNI (Server Name Indication)** from the initial TLS handshake (the `tls_clienthello` hook). By tracking the frequency and velocity of these SNI requests, the system can still accurately detect doomscrolling and apply bandwidth throttling, even on fully encrypted, pinned mobile apps.

### E. The Nerve Center Dashboard (`app.py`)
The Flask application provides a responsive, web-based UI for system administrators.
- **Active Devices:** Reads from `network_devices` to show exactly who is on the network and when they last transmitted data (via HTTP, SNI, or DNS).
- **Traffic & SNI Logs:** Pulls from `traffic_log` and `sni_requests` to provide real-time graphs and charts of user activity.
- **Manual Overrides:** Administrators can view throttled devices and manually click "Release Throttle." This updates the database, removes the `tc` rules, and sends a signal to the proxy to instantly refresh its internal cache and cancel the recovery timer.

## 4. Data Flow & Synchronization

Because the Proxy and the Dashboard run in separate processes, they rely on SQLite and file signals to stay synchronized:
1. **Database Locks:** Both scripts use `threading.Lock()` to prevent internal thread collisions, and SQLite's WAL mode prevents the two separate processes from locking each other out.
2. **Rule Cache Reloading:** When you change a setting in the dashboard (like unthrottling a user or updating a keyword), `app.py` updates the database and touches a temporary file to update its modified timestamp. The `vigilant_addon.py` runs a background loop (`_cache_refresh_loop`) that monitors this file. When it detects a change, it instantly queries the database to update its in-memory rules and throttle states, ensuring changes take effect immediately without restarting the proxy.
