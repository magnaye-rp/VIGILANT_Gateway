import re
import time
import sqlite3
import threading
import subprocess
import urllib.parse
from collections import defaultdict, deque
from mitmproxy import http, tls
import spacy

# ─── Configuration ────────────────────────────────────────────────
DB_PATH            = "/home/vigilant_admin/vigilant/logs/vigilant.db"
VELOCITY_WINDOW    = 60
MIN_REQUESTS_BASELINE = 10

# Default values (will be overridden by database config)
DEFAULT_VELOCITY_THRESHOLD = 1.5
DEFAULT_THROTTLE_RATE = "512kbit"
DEFAULT_PINNED_DOMAINS = "instagram.com,facebook.com,tiktok.com,x.com,twitter.com"

# Global asset whitelist
GLOBAL_WHITELIST = {
    "github.com", "githubassets.com", "githubusercontent.com", "git-scm.com",
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windows.net", "live.com", "office.com", "apple.com",
    "mzstatic.com", "icloud.com", "aws.amazon.com", "cloudfront.net", "cdnjs.cloudflare.com"
}

def is_whitelisted(host: str) -> bool:
    """Check if a host (or its parent domain) is in the global whitelist."""
    clean = host.lstrip("www.")
    for w in GLOBAL_WHITELIST:
        if clean == w or clean.endswith('.' + w):
            return True
    return False

# Default social domains for doomscroll detection
DEFAULT_SOCIAL_DOMAINS = {
    "facebook.com", "www.facebook.com",
    "twitter.com", "x.com", "www.x.com",
    "tiktok.com", "www.tiktok.com",
    "instagram.com", "www.instagram.com",
    "reddit.com", "www.reddit.com",
    "youtube.com", "www.youtube.com",
}

CATEGORY_KEYWORDS = {
    "Educational":  {"learn", "study", "research", "science", "history",
                     "tutorial", "course", "university", "education",
                     "academic", "journal", "lecture", "textbook",
                     "theory", "experiment", "analysis", "hypothesis"},
    "Productive":   {"work", "project", "report", "deadline", "meeting",
                     "productivity", "business", "office", "task",
                     "professional", "career", "finance", "budget",
                     "code", "development", "deploy", "repository"},
    "Distracting":  {"viral", "trending", "meme", "gossip", "celebrity",
                     "shocking", "unbelievable", "scroll", "feed",
                     "reels", "shorts", "tiktok", "influencer",
                     "entertainment", "funny", "lol", "wtf"},
    "Harmful":      {"hate", "violence", "abuse", "threat", "illegal",
                     "exploit", "self-harm", "dangerous", "extremist"},
}

# ─── NLP Setup ────────────────────────────────────────────────────
nlp = spacy.load("en_core_web_sm")

# ─── Database Setup ───────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL,
            client_ip   TEXT,
            host        TEXT,
            path        TEXT,
            method      TEXT,
            category    TEXT,
            flagged     INTEGER DEFAULT 0,
            entities    TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS throttle_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL,
            client_ip   TEXT,
            host        TEXT,
            rpm_current REAL,
            rpm_baseline REAL,
            action      TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS keyword_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

db_lock = threading.Lock()

def load_proxy_config():
    """Load proxy and behavioral configuration from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Load network velocity threshold (multiplier)
        cursor.execute("SELECT value FROM config_settings WHERE key = 'network_velocity_threshold'")
        row = cursor.fetchone()
        network_velocity_threshold = float(row[0]) if row else DEFAULT_VELOCITY_THRESHOLD
        
        # Load physical scroll threshold (absolute RPM)
        cursor.execute("SELECT value FROM config_settings WHERE key = 'physical_scroll_threshold'")
        row = cursor.fetchone()
        physical_scroll_threshold = int(row[0]) if row else 75
        
        # Load NLP enabled flag
        cursor.execute("SELECT value FROM config_settings WHERE key = 'nlp_enabled'")
        row = cursor.fetchone()
        nlp_enabled_str = row[0] if row else "true"
        nlp_enabled = nlp_enabled_str.lower() in ["true", "1", "yes"]

        # Load throttle rate
        cursor.execute("SELECT value FROM config_settings WHERE key = 'proxy_throttle_rate'")
        row = cursor.fetchone()
        throttle_rate = row[0] if row else DEFAULT_THROTTLE_RATE
        
        # Load pinned domains
        cursor.execute("SELECT value FROM config_settings WHERE key = 'proxy_pinned_domains'")
        row = cursor.fetchone()
        pinned_domains_str = row[0] if row else DEFAULT_PINNED_DOMAINS
        
        # Parse pinned domains into a set
        pinned_domains = set()
        for domain in pinned_domains_str.split(','):
            domain = domain.strip()
            if domain:
                pinned_domains.add(domain)
                # Also add www. variant
                if not domain.startswith('www.'):
                    pinned_domains.add(f'www.{domain}')
        
        conn.close()
        
        return {
            'network_velocity_threshold': network_velocity_threshold,
            'physical_scroll_threshold': physical_scroll_threshold,
            'nlp_enabled': nlp_enabled,
            'throttle_rate': throttle_rate,
            'pinned_domains': pinned_domains
        }
    except Exception as e:
        print(f"[VIGILANT] Error loading proxy config from database: {e}, using defaults")
        return {
            'network_velocity_threshold': DEFAULT_VELOCITY_THRESHOLD,
            'physical_scroll_threshold': 75,
            'nlp_enabled': True,
            'throttle_rate': DEFAULT_THROTTLE_RATE,
            'pinned_domains': set(DEFAULT_PINNED_DOMAINS.split(','))
        }


def load_category_hints():
    """Load category hints from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            conn.close()
            # Return empty dict if table doesn't exist
            return {}
        
        cursor.execute("SELECT category, domain FROM category_hints")
        rows = cursor.fetchall()
        
        category_hints = {}
        for category, domain in rows:
            if category not in category_hints:
                category_hints[category] = set()
            category_hints[category].add(domain)
        
        conn.close()
        return category_hints
    except Exception as e:
        print(f"[VIGILANT] Error loading category hints from database: {e}, using empty set")
        return {}


def load_social_domains():
    """Load social domains from category_hints (Distracting category)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            conn.close()
            return DEFAULT_SOCIAL_DOMAINS
        
        # Load domains from Distracting category
        cursor.execute("SELECT domain FROM category_hints WHERE category = 'Distracting'")
        rows = cursor.fetchall()
        
        social_domains = set()
        for (domain,) in rows:
            social_domains.add(domain)
            # Also add www. variant
            if not domain.startswith('www.'):
                social_domains.add(f'www.{domain}')
        
        conn.close()
        
        # If no domains found, use defaults
        if not social_domains:
            return DEFAULT_SOCIAL_DOMAINS
        
        return social_domains
    except Exception as e:
        print(f"[VIGILANT] Error loading social domains from database: {e}, using defaults")
        return DEFAULT_SOCIAL_DOMAINS

# Categories that represent real, classified user web activity.
# All other category strings (DNS noise, non-HTML assets, uncategorized) are silently dropped.
_LOGGABLE_CATEGORIES = {"educational", "productive", "distracting", "harmful"}

# Category strings that are explicitly considered noise / telemetry and must never
# reach the database — checked case-insensitively to catch all variants.
_NOISE_CATEGORIES = {"non-html", "dns_tracked", "dns", "dns_query", "mobile_bypass", "uncategorized"}


def log_request(client_ip, host, path, method, category, flagged, entities):
    # Normalise the category for comparison – catches mixed-case variants like
    # 'Non-HTML', 'DNS_Tracked', 'Uncategorized', 'UNCATEGORIZED', etc.
    category_key = (category or "").strip().lower()

    # 1. Immediately drop any known noise / telemetry category.
    if category_key in _NOISE_CATEGORIES:
        return  # Silent pass: client gets internet, but we don't log the noise

    # 2. Only write loggable (classified) categories to the database.
    #    Anything not in the allow-set is treated as uncategorized noise.
    if category_key not in _LOGGABLE_CATEGORIES:
        return  # Silent pass: client gets internet, but we don't log the noise
    
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO traffic_log VALUES (NULL,?,?,?,?,?,?,?,?)",
            (time.time(), client_ip, host, path, method,
             category, int(flagged), str(entities))
        )
        conn.commit()
        conn.close()

def log_throttle(client_ip, host, rpm_now, rpm_base, action):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO throttle_events VALUES (NULL,?,?,?,?,?,?)",
            (time.time(), client_ip, host, rpm_now, rpm_base, action)
        )
        conn.commit()
        conn.close()

# ─── Velocity Monitor ─────────────────────────────────────────────
request_history   = defaultdict(lambda: deque())
session_totals    = defaultdict(int)
session_start     = defaultdict(float)
throttled_clients = set()
velocity_lock     = threading.Lock()

def compute_velocity(client_ip):
    now = time.time()
    with velocity_lock:
        if session_start[client_ip] == 0:
            session_start[client_ip] = now
        dq = request_history[client_ip]
        while dq and now - dq[0] > VELOCITY_WINDOW:
            dq.popleft()
        dq.append(now)
        session_totals[client_ip] += 1
        current_rpm = len(dq)
        elapsed_min = max(now - session_start[client_ip], 1) / 60
        session_avg = session_totals[client_ip] / elapsed_min
        return current_rpm, session_avg

def should_throttle(client_ip, host):
    config = load_proxy_config()
    network_velocity_threshold = config['network_velocity_threshold']
    physical_scroll_threshold = config['physical_scroll_threshold']
    social_domains = load_social_domains()
    
    base = ".".join(host.lstrip("www.").split(".")[-2:])
    if not any(base in d for d in social_domains):
        return False, 0, 0
    rpm_now, rpm_base = compute_velocity(client_ip)
    if session_totals[client_ip] < MIN_REQUESTS_BASELINE:
        return False, rpm_now, rpm_base
        
    # Flag if relative velocity (multiplier) OR absolute physical scroll (RPM limit) is violated
    flagged = (rpm_now > (rpm_base * network_velocity_threshold)) or (rpm_now > physical_scroll_threshold)
    return flagged, rpm_now, rpm_base

# ─── Text Normalization Helper ──────────────────────────────────────
def normalize_text(text):
    """
    Normalize text by converting to lowercase and stripping common bypass characters.
    This helps catch obfuscated keywords like "b.r.a.i.n.r.o.t" or "brain-rot" 
    when blocking "brainrot".
    """
    if not text:
        return ""
    # Convert to lowercase and remove common separator characters: _, -, ., +, spaces, and non-alphanumeric noise
    return re.sub(r'[\s_\-\.\+\*\/\\~,;:!@#\$%\^&\(\)\[\]\{\}<>|]+', '', text.lower())


# ─── NLP Categorizer ──────────────────────────────────────────────
def get_domain_hint(host):
    category_hints = load_category_hints()
    clean = host.lstrip("www.")
    for category, domains in category_hints.items():
        if any(clean == d or clean.endswith("." + d) for d in domains):
            return category, 3
    return None, 0

def categorize_content(text, host=""):
    if not text:
        text = ""

    hint_category, hint_score = get_domain_hint(host)
    
    config = load_proxy_config()
    nlp_enabled = config['nlp_enabled']

    if nlp_enabled:
        doc      = nlp(text[:10000]) if len(text) >= 20 else None
        entities = [(ent.text, ent.label_) for ent in doc.ents] if doc else []
        tokens   = {t.lemma_.lower() for t in doc
                    if not t.is_stop and t.is_alpha} if doc else set()
    else:
        doc = None
        entities = []
        tokens = set(normalize_text(text).split()) if len(text) >= 20 else set()

    scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        scores[category] = len(tokens & keywords)

    if hint_category:
        scores[hint_category] = scores.get(hint_category, 0) + hint_score
    
    # NER count weighting - add weighted scores based on entity types
    if doc and doc.ents:
        for ent in doc.ents:
            # Academic/professional entities boost Educational category
            if ent.label_ in ["LAW", "WORK_OF_ART", "EVENT", "ORG", "PERSON", "GPE"]:
                scores["Educational"] = scores.get("Educational", 0) + 2
            # Dates/numbers can indicate productive work
            elif ent.label_ in ["DATE", "TIME", "CARDINAL", "ORDINAL"]:
                scores["Productive"] = scores.get("Productive", 0) + 1

    if scores.get("Harmful", 0) > 0:
        # Downgrade harmful if contains common utility terms
        utility_terms = {"git", "code", "dev", "assets", "static", "github", "google", "microsoft", "apple"}
        if any(term in tokens for term in utility_terms):
            return "Educational", entities
        return "Harmful", entities

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "Uncategorized", entities

    return best, entities

# ─── Traffic Control Throttling ───────────────────────────────────────
def apply_throttle(client_ip):
    """Apply Linux tc traffic control to throttle client bandwidth"""
    config = load_proxy_config()
    throttle_rate = config['throttle_rate']
    
    try:
        # Create root qdisc if not exists
        subprocess.run(
            ["tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb"],
            check=False, capture_output=True
        )
        
        # Create class for throttled traffic
        subprocess.run(
            ["tc", "class", "add", "dev", "eth0", "parent", "1:", "classid", "1:10",
             "htb", "rate", throttle_rate, "ceil", throttle_rate],
            check=False, capture_output=True
        )
        
        # Create filter to mark traffic from client IP
        subprocess.run(
            ["tc", "filter", "add", "dev", "eth0", "protocol", "ip", "parent", "1:0",
             "prio", "1", "u32", "match", "ip", "src", client_ip, "flowid", "1:10"],
            check=False, capture_output=True
        )
        print(f"[VIGILANT] Throttling applied to {client_ip} at {throttle_rate}")
        return True
    except Exception as e:
        print(f"[VIGILANT] Throttling failed for {client_ip}: {e}")
        return False

def remove_throttle(client_ip):
    """Remove traffic control throttling for client IP"""
    try:
        subprocess.run(
            ["tc", "filter", "del", "dev", "eth0", "protocol", "ip", "parent", "1:0",
             "prio", "1", "u32", "match", "ip", "src", client_ip, "flowid", "1:10"],
            check=False, capture_output=True
        )
        print(f"[VIGILANT] Throttling removed for {client_ip}")
        return True
    except Exception as e:
        print(f"[VIGILANT] Throttle removal failed for {client_ip}: {e}")
        return False

# ─── DNS Log Tailing Thread ─────────────────────────────────────────────
def tail_dnsmasq_log():
    """Background thread to tail dnsmasq log for passive DNS tracking"""
    log_path = "/var/log/dnsmasq.log"
    
    while True:
        try:
            with open(log_path, 'r') as f:
                f.seek(0, 2)  # Start from end of file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    # Parse DNS query format: query[A] domain.com from 192.168.10.20
                    if "query[" in line and " from " in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("query["):
                                if i + 2 < len(parts):
                                    domain = parts[i + 1]
                                    client_ip = parts[i + 3]
                                    
                                    # Track velocity for DNS queries
                                    flagged, rpm_now, rpm_base = should_throttle(client_ip, domain)
                                    if flagged and client_ip not in throttled_clients:
                                        throttled_clients.add(client_ip)
                                        log_throttle(client_ip, domain, rpm_now, rpm_base, "DNS_THROTTLE_APPLIED")
                                        apply_throttle(client_ip)
                                        print(f"[VIGILANT] DNS DOOMSCROLL DETECTED {client_ip} @ {domain} "
                                              f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")
                                    
                                    # Log DNS query for dashboard visibility
                                    log_request(client_ip, domain, "(DNS_QUERY)", "DNS", "DNS_Tracked", False, [])
                                    break
        except FileNotFoundError:
            time.sleep(5)
        except Exception as e:
            print(f"[VIGILANT] DNS log tailing error: {e}")
            time.sleep(5)

# ─── mitmproxy Addon ──────────────────────────────────────────────
class VIGILANTAddon:

    def __init__(self):
        init_db()
        print("[VIGILANT] Addon loaded. DB initialised. NLP model ready.")
        
        # Start DNS log tailing thread
        dns_thread = threading.Thread(target=tail_dnsmasq_log, daemon=True)
        dns_thread.start()
        print("[VIGILANT] DNS log tailing thread started")

    def tls_clienthello(self, layer):
        """TLS ClientHello hook for mobile SNI fallback tracking"""
        try:
            # In modern mitmproxy, ClientHelloData does not have direct .client_conn property
            # Access client IP through the context block
            if hasattr(layer, "context") and hasattr(layer.context, "client_conn"):
                client_ip = layer.context.client_conn.peername[0]
            else:
                # Fallback for older mitmproxy versions or different contexts
                print(f"[VIGILANT] TLS ClientHello: Unable to determine client IP, skipping SNI tracking")
                return
            
            sni = layer.client_hello.sni if hasattr(layer, "client_hello") else None
            
            if sni:
                # Check if SNI belongs to bypassed social domains
                clean_sni = sni.lstrip("www.")
                base = ".".join(clean_sni.split(".")[-2:])
                
                # Track velocity at TLS handshake phase
                flagged, rpm_now, rpm_base = should_throttle(client_ip, sni)
                
                if flagged and client_ip not in throttled_clients:
                    throttled_clients.add(client_ip)
                    log_throttle(client_ip, sni, rpm_now, rpm_base, "TLS_THROTTLE_APPLIED")
                    apply_throttle(client_ip)
                    print(f"[VIGILANT] TLS DOOMSCROLL DETECTED {client_ip} @ {sni} "
                          f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")
                
                # If SNI belongs to bypassed domains, log fallback request
                social_domains = load_social_domains()
                if any(base in d for d in social_domains):
                    log_request(client_ip, sni, "(TLS_SNI)", "TLS", "Mobile_Bypass", False, [])
                    print(f"[VIGILANT] TLS SNI bypass logged: {client_ip} -> {sni}")
        except AttributeError as e:
            print(f"[VIGILANT] TLS ClientHello attribute error: {e}")
        except Exception as e:
            print(f"[VIGILANT] TLS ClientHello error: {e}")
    
    def request(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0]
        host      = flow.request.pretty_host
        
        # Whitelist bypass: asset subdomains
        if is_whitelisted(host):
            log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Educational", False, [])
            print(f"[VIGILANT] WHITELIST BYPASS (request): {host} -> {client_ip}")
            return
        
        # TLS Passthrough: Check if host belongs to pinned SSL certificate domains
        # These apps have hardcoded SSL pinning and must pass through without decryption
        config = load_proxy_config()
        pinned_domains = config['pinned_domains']
        
        clean_host = host.lstrip("www.")
        base_domain = ".".join(clean_host.split(".")[-2:])
        is_pinned = any(base_domain in d or clean_host == d or clean_host.endswith("." + d) for d in pinned_domains)
        
        if is_pinned:
            # Allow pinned domains to pass through cleanly without any filtering
            print(f"[VIGILANT] TLS PASSTHROUGH: {host} from {client_ip} (pinned domain)")
            return

        # STEP 1: Exact Domain Evaluation - Check category hints for strict override
        # This takes precedence over all heuristic/keyword rules
        category_hints = load_category_hints()
        domain_category = None
        
        for category, domains in category_hints.items():
            if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                domain_category = category
                print(f"[VIGILANT] DOMAIN OVERRIDE: {host} -> {category} (category hint match)")
                break
        
        # STEP 2: Strict Keyword Scan - Only if domain is unmapped
        # Fully decode URL parameters and enforce clear context boundary checks
        # Using advanced text normalization to catch obfuscated keywords
        if domain_category is None:
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                    keywords = [row[0] for row in cursor.fetchall()]
                    conn.close()

                if keywords:
                    # Decode URL to handle percent-encoding (e.g., %20 for spaces)
                    try:
                        decoded_url = urllib.parse.unquote(flow.request.pretty_url)
                    except Exception:
                        decoded_url = flow.request.pretty_url
                    
                    # Extract raw request body text if available
                    try:
                        request_body = flow.request.get_text(strict=False) if flow.request.content else ""
                    except Exception:
                        request_body = ""

                    # Normalize URL and body for comparison
                    normalized_url = normalize_text(decoded_url)
                    normalized_body = normalize_text(request_body)

                    for keyword in keywords:
                        # Normalize keyword using the same function
                        normalized_keyword = normalize_text(keyword)
                        
                        # Skip empty normalized keywords
                        if not normalized_keyword:
                            continue
                        
                        # Check if normalized keyword found in normalized URL or body
                        if normalized_keyword in normalized_url or normalized_keyword in normalized_body:
                            print(f"[VIGILANT] KEYWORD BLOCKED: {keyword} (normalized: {normalized_keyword}) in {decoded_url[:60]} from {client_ip}")
                            log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [])
                            flow.response = http.Response.make(
                                403,
                                b"Blocked by Vigilant Gateway",
                                {"Content-Type": "text/plain"}
                            )
                            return
            except sqlite3.Error as e:
                print(f"[VIGILANT] Keyword blacklist check failed: {e}")

        flagged, rpm_now, rpm_base = should_throttle(client_ip, host)
        if flagged and client_ip not in throttled_clients:
            throttled_clients.add(client_ip)
            log_throttle(client_ip, host, rpm_now, rpm_base, "HTTP_THROTTLE_APPLIED")
            apply_throttle(client_ip)
            print(f"[VIGILANT] HTTP DOOMSCROLL DETECTED {client_ip} @ {host} "
                  f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

    def response(self, flow: http.HTTPFlow):
        client_ip    = flow.client_conn.peername[0]
        host         = flow.request.pretty_host
        path         = flow.request.path[:120]
        method       = flow.request.method
        content_type = flow.response.headers.get("content-type", "")
        
        # Whitelist bypass: asset subdomains
        if is_whitelisted(host):
            log_request(client_ip, host, path, method, "Educational", False, [])
            print(f"[VIGILANT] WHITELIST BYPASS (response): {host} -> {client_ip}")
            return
        
        # TLS Passthrough: Skip response filtering for pinned domains
        config = load_proxy_config()
        pinned_domains = config['pinned_domains']
        
        clean_host = host.lstrip("www.")
        base_domain = ".".join(clean_host.split(".")[-2:])
        is_pinned = any(base_domain in d or clean_host == d or clean_host.endswith("." + d) for d in pinned_domains)
        
        if is_pinned:
            # Allow pinned domains to pass through without response analysis
            return

        # STEP 1: Exact Domain Evaluation - Check category hints for strict override
        # This takes precedence over all heuristic/keyword rules
        category_hints = load_category_hints()
        domain_category = None
        
        for category, domains in category_hints.items():
            if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                domain_category = category
                break

        # Handle both HTML and JSON responses for keyword filtering
        # Skip binary content types to avoid wasting CPU cycles on image/video/audio data
        TEXT_CONTENT_TYPES = {"text/html", "application/json", "text/plain", "text/javascript", "application/javascript", "text/css", "application/xml", "text/xml"}
        
        if not any(ct in content_type for ct in TEXT_CONTENT_TYPES):
            # Use domain category if available, otherwise categorize as Non-HTML
            final_category = domain_category if domain_category else "Non-HTML"
            log_request(client_ip, host, path, method, final_category, False, [])
            return

        # Error handling for large packet payloads (e.g. > 5MB)
        MAX_PAYLOAD_SIZE = 5 * 1024 * 1024
        try:
            if flow.response.content and len(flow.response.content) > MAX_PAYLOAD_SIZE:
                print(f"[VIGILANT] Payload too large ({len(flow.response.content)} bytes) for {host}, skipping NLP")
                final_category = domain_category if domain_category else "Uncategorized"
                log_request(client_ip, host, path, method, final_category, False, [])
                return
                
            # Safely decode the full content payload with decompression automatically handled
            body = flow.response.text or ""
            
            if "text/html" in content_type:
                # Strip out scripts and styles before removing other HTML tags
                clean = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', body, flags=re.IGNORECASE | re.DOTALL)
                clean = re.sub(r"<[^>]+>", " ", clean)
                clean = re.sub(r"\s+", " ", clean).strip()
            elif "application/json" in content_type:
                # For JSON responses, extract text content by removing structural characters
                clean = re.sub(r'[{}\[\]",:]', ' ', body)
                clean = re.sub(r"\s+", " ", clean).strip()
            else:
                # For other text types, just normalize whitespace
                clean = re.sub(r"\s+", " ", body).strip()
        except ValueError:
            print(f"[VIGILANT] Failed to decode text payload for {host}")
            clean = ""
        except Exception as e:
            print(f"[VIGILANT] Error processing response payload for {host}: {e}")
            clean = ""

        # STEP 2: Use domain category if available, otherwise use NLP categorization
        if domain_category:
            category = domain_category
            entities = []
        else:
            category, entities = categorize_content(clean, host)
        
        flagged = category == "Harmful"

        # STEP 3: Additional keyword blacklist check on response content for text-based responses
        # Only if domain is unmapped (no category hint) and content is text-based
        # Using advanced text normalization to catch obfuscated keywords
        if domain_category is None and any(ct in content_type for ct in TEXT_CONTENT_TYPES):
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                    keywords = [row[0] for row in cursor.fetchall()]
                    conn.close()

                if keywords:
                    # Normalize the cleaned response content
                    normalized_content = normalize_text(clean)
                    
                    for keyword in keywords:
                        # Normalize keyword using the same function
                        normalized_keyword = normalize_text(keyword)
                        
                        # Skip empty normalized keywords
                        if not normalized_keyword:
                            continue
                        
                        # Check if normalized keyword found in normalized content
                        if normalized_keyword in normalized_content:
                            print(f"[VIGILANT] RESPONSE KEYWORD BLOCKED: {keyword} (normalized: {normalized_keyword}) in {content_type} response from {host}")
                            log_request(client_ip, host, path, method, "Harmful", True, [])
                            flow.response = http.Response.make(
                                403,
                                b"Blocked by Vigilant Gateway",
                                {"Content-Type": "text/plain"}
                            )
                            return
            except sqlite3.Error as e:
                print(f"[VIGILANT] Response keyword blacklist check failed: {e}")

        log_request(client_ip, host, path, method, category, flagged, entities[:10])
        print(f"[VIGILANT] {method} {host}{path[:40]} "
              f"-> [{category}] entities={len(entities)} client={client_ip}")

        if flagged:
            flow.response = http.Response.make(
                403,
                f"<html><body><h2>VIGILANT Gateway</h2>"
                f"<p>Access to <b>{host}</b> was blocked.<br>"
                f"Category: {category}</p></body></html>",
                {"Content-Type": "text/html"}
            )

addons = [VIGILANTAddon()]