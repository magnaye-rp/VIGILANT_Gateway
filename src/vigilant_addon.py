import re
import time
import sqlite3
import threading
import subprocess
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
    """Load proxy configuration from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Load velocity threshold
        cursor.execute("SELECT value FROM config_settings WHERE key = 'proxy_velocity_threshold'")
        row = cursor.fetchone()
        velocity_threshold = float(row[0]) if row else DEFAULT_VELOCITY_THRESHOLD
        
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
            'velocity_threshold': velocity_threshold,
            'throttle_rate': throttle_rate,
            'pinned_domains': pinned_domains
        }
    except Exception as e:
        print(f"[VIGILANT] Error loading proxy config from database: {e}, using defaults")
        return {
            'velocity_threshold': DEFAULT_VELOCITY_THRESHOLD,
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

def log_request(client_ip, host, path, method, category, flagged, entities):
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
    velocity_threshold = config['velocity_threshold']
    social_domains = load_social_domains()
    
    base = ".".join(host.lstrip("www.").split(".")[-2:])
    if not any(base in d for d in social_domains):
        return False, 0, 0
    rpm_now, rpm_base = compute_velocity(client_ip)
    if session_totals[client_ip] < MIN_REQUESTS_BASELINE:
        return False, rpm_now, rpm_base
    flagged = rpm_now > (rpm_base * velocity_threshold)
    return flagged, rpm_now, rpm_base

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

    doc      = nlp(text[:10000]) if len(text) >= 20 else None
    entities = [(ent.text, ent.label_) for ent in doc.ents] if doc else []
    tokens   = {t.lemma_.lower() for t in doc
                if not t.is_stop and t.is_alpha} if doc else set()

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

        # Keyword blacklist inspection - request-level payload evaluation
        try:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                keywords = [row[0].lower() for row in cursor.fetchall()]
                conn.close()

            if keywords:
                # Construct normalized inspection string: URL + decoded request body
                url_lower = flow.request.pretty_url.lower()
                payload_lower = flow.request.get_text(strict=False).lower() if flow.request.content else ""

                for keyword in keywords:
                    # Short-circuit: if keyword found in URL or request body, block immediately
                    if keyword in url_lower or keyword in payload_lower:
                        print(f"[VIGILANT] KEYWORD BLOCKED: {keyword} in {url_lower[:60]} from {client_ip}")
                        log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [])
                        flow.response = http.Response.make(
                            403,
                            b"<html><body><h1>Content Blocked by Vigilant Gateway Rule</h1></body></html>",
                            {"Content-Type": "text/html"}
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

        # TLS Passthrough: Skip response filtering for pinned domains
        config = load_proxy_config()
        pinned_domains = config['pinned_domains']
        
        clean_host = host.lstrip("www.")
        base_domain = ".".join(clean_host.split(".")[-2:])
        is_pinned = any(base_domain in d or clean_host == d or clean_host.endswith("." + d) for d in pinned_domains)
        
        if is_pinned:
            # Allow pinned domains to pass through without response analysis
            return

        if "text/html" not in content_type:
            log_request(client_ip, host, path, method, "Non-HTML", False, [])
            return

        try:
            body  = flow.response.get_text(strict=False) or ""
            clean = re.sub(r"<[^>]+>", " ", body)
            clean = re.sub(r"\s+", " ", clean).strip()
        except Exception:
            clean = ""

        category, entities = categorize_content(clean, host)
        flagged = category == "Harmful"

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