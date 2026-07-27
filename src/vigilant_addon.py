import os
import re
import time
import sqlite3
import threading
import subprocess
import urllib.parse
from collections import defaultdict, deque
from pathlib import Path
try:
    from mitmproxy import ctx, http, tls
except ImportError:
    ctx = http = tls = None

try:
    import spacy
except ImportError:
    spacy = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError:
    TfidfVectorizer = cosine_similarity = None

try:
    import numpy as np
except ImportError:
    np = None

BASE_DIR = Path(__file__).resolve().parent.parent
PRODUCTION_DB_PATH = Path("/home/vigilant-admin/vigilant_gateway/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

if PRODUCTION_DB_PATH.exists() and os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
    DB_PATH = str(PRODUCTION_DB_PATH)
else:
    DB_PATH = str(LOCAL_DB_PATH)

VELOCITY_WINDOW    = 60

# Default values (will be overridden by database config)
DEFAULT_VELOCITY_THRESHOLD = 1.5
DEFAULT_THROTTLE_RATE = "32kbit"
DEFAULT_PINNED_DOMAINS = "facebook.com,twitter.com,x.com,tiktok.com,instagram.com,reddit.com,youtube.com"
MIN_REQUESTS_BASELINE = 10

# --- Circuit Breaker Escalation System ----------------------------
CB_LEVEL_NONE = 0
CB_LEVEL_PAUSE = 1           # 30s: Brief bandwidth pause
CB_LEVEL_FRICTION = 2        # 60s: Light throttle 256kbit
CB_LEVEL_CIRCUIT_BREAK = 3   # 120s+: Hard throttle 32kbit

CB_LEVEL_NAMES = {
    0: "None", 1: "Pause", 2: "Friction", 3: "Circuit Break"
}

# Escalation time windows (seconds of continuous social media activity)
CB_PAUSE_SECONDS = 30
CB_FRICTION_SECONDS = 60
CB_BREAK_SECONDS = 120

# Cooldown period after circuit break release (seconds)
CB_COOLDOWN_SECONDS = 120

# Maximum total time a device can stay throttled before auto-release (seconds)
# Prevents throttles from sticking forever due to background traffic preventing
# the 3-minute pause reset from triggering.
CB_MAX_THROTTLE_DURATION = 300

# Maximum payload body size before falling back to sampled scanning.
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024      # hard cap before we stop trying to fully decode
SAMPLE_PREFIX_BYTES = 512 * 1024        # ~512KB from the start (headlines/titles/first posts)
SAMPLE_SUFFIX_BYTES = 256 * 1024        # ~256KB from the end (catches trailing chunks)

# Per-level de-escalation: how long the user must pause before the throttle releases.
# Each level requires a longer pause, so lighter throttles are easier to shake off.
# This replaces the old single-value CB_NO_PAUSE_SECONDS which never fired because
# phones make background requests (iCloud, notifications) every 30-60 seconds.
CB_DEESCALATION_SECONDS = {
    CB_LEVEL_PAUSE: 60,          # L1 (4kbit):  60s pause → release
    CB_LEVEL_FRICTION: 90,       # L2 (2kbit):  90s pause → release
    CB_LEVEL_CIRCUIT_BREAK: 120  # L3 (1kbit): 120s pause → release
}


def get_deescalation_seconds() -> dict:
    """Load per-level de-escalation gaps from database.
    Falls back to CB_DEESCALATION_SECONDS defaults."""
    try:
        conn = _connect_db()
        cursor = conn.cursor()
        result = dict(CB_DEESCALATION_SECONDS)
        for level_key, cb_level in [('deescalation_l1', CB_LEVEL_PAUSE),
                                      ('deescalation_l2', CB_LEVEL_FRICTION),
                                      ('deescalation_l3', CB_LEVEL_CIRCUIT_BREAK)]:
            cursor.execute("SELECT value FROM config_settings WHERE key = ?", (level_key,))
            row = cursor.fetchone()
            if row:
                try:
                    result[cb_level] = int(row[0])
                except (ValueError, TypeError):
                    pass
        conn.close()
        return result
    except Exception:
        return dict(CB_DEESCALATION_SECONDS)


# Global asset whitelist
GLOBAL_WHITELIST = {
    "github.com", "githubassets.com", "githubusercontent.com", "git-scm.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windows.net", "live.com", "office.com", "apple.com",
    "mzstatic.com", "icloud.com", "aws.amazon.com", "cloudfront.net", "cdnjs.cloudflare.com"
}


def is_whitelisted(host: str) -> bool:
    """Check if a host (or its parent domain) is in the global whitelist."""
    clean = host.removeprefix("www.")
    for w in GLOBAL_WHITELIST:
        if clean == w or clean.endswith('.' + w):
            return True
    return False


def is_custom_bypass(host: str) -> bool:
    """Check if a host matches a user-configured bypass domain."""
    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'custom_bypass_domains'")
        row = cursor.fetchone()
        conn.close()
        if not row or not row[0]:
            return False
        clean = host.removeprefix("www.").lower()
        for domain in row[0].split(','):
            domain = domain.strip().lower()
            if not domain:
                continue
            if clean == domain or clean.endswith('.' + domain):
                return True
    except Exception:
        pass
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
nlp = None
try:
    nlp = spacy.load("en_core_web_sm")
except Exception as e:
    print(f"[VIGILANT] Failed to load spacy model 'en_core_web_sm': {e}")
    print("[VIGILANT] NLP features will be disabled. Install with: python -m spacy download en_core_web_sm")

# ─── TF-IDF Classifier ─────────────────────────────────────────────
class VigilantTFIDFClassifier:
    """
    TF-IDF based text classifier using cosine similarity against category centroids.
    Replaces legacy regex word-stripping and string-splitting methods with vector-based
    semantic similarity scoring.
    """
    
    def __init__(self, category_keywords):
        """
        Initialize classifier with category keyword mappings.
        
        Args:
            category_keywords: Dict mapping category names to sets of keywords
        """
        self.category_keywords = category_keywords
        self.category_names = []
        self.centroid_matrix = None
        self.category_centroids = {}
        if TfidfVectorizer is None or np is None:
            self.vectorizer = None
            return
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95
        )
        self._fit_category_centroids()
    
    def _fit_category_centroids(self):
        if self.vectorizer is None or TfidfVectorizer is None:
            return
        category_documents = {}
        for category, keywords in self.category_keywords.items():
            # Create sample documents from keywords for training
            docs = []
            for keyword in keywords:
                docs.append(keyword)
                # Add n-gram variations
                words = keyword.split()
                if len(words) > 1:
                    docs.append(' '.join(words))
            category_documents[category] = docs

        # Fit vectorizer on all category documents
        all_docs = []
        for docs in category_documents.values():
            all_docs.extend(docs)

        # Reset pre-computed structures
        self.category_names = []       # ordered list matching centroid_matrix rows
        self.centroid_matrix = None    # shape: (n_categories, vocab_size) ndarray

        if all_docs:
            self.vectorizer.fit(all_docs)

            # Compute centroids for each category and store individually
            # (kept for any external code that reads category_centroids directly)
            centroid_rows = []
            for category, docs in category_documents.items():
                if docs:
                    tfidf_matrix = self.vectorizer.transform(docs)
                    centroid = np.mean(tfidf_matrix.toarray(), axis=0)
                    self.category_centroids[category] = centroid
                    self.category_names.append(category)
                    centroid_rows.append(centroid)

            # Pre-stack into a single matrix for fast batch cosine_similarity
            if centroid_rows:
                self.centroid_matrix = np.vstack(centroid_rows)  # (n_categories, vocab_size)
    
    def classify(self, text, threshold=0.1):
        if self.vectorizer is None or TfidfVectorizer is None:
            return "Unclassified", 0.0
        """
        Classify text by computing cosine similarity against category centroids.

        Text is truncated to SAMPLE_PREFIX_BYTES characters before vectorisation
        to prevent latency spikes on large HTTP response bodies.

        Cosine similarity is computed in a single batch call against the
        pre-stacked centroid_matrix rather than in a per-category loop.

        Args:
            text: Input text to classify
            threshold: Minimum similarity score to consider a category match

        Returns:
            Tuple of (best_category, similarity_scores_dict)
        """
        if not text or not text.strip():
            return None, {}

        # ── Truncation guard ──────────────────────────────────────────────
        # Cap text at SAMPLE_PREFIX_BYTES characters (UTF-8 decoded length).
        # This is the universal safety net regardless of where classify() is
        # called from; callers that already sample the body get no overhead.
        if len(text) > SAMPLE_PREFIX_BYTES:
            text = text[:SAMPLE_PREFIX_BYTES]

        # Transform input text to TF-IDF vector
        try:
            text_vector = self.vectorizer.transform([text])
        except ValueError:
            # Handle case where text has no features after vectorization
            return None, {}

        # ── Batch cosine similarity (single matrix multiply) ──────────────
        # cosine_similarity returns shape (1, n_categories); flatten to 1-D.
        if self.centroid_matrix is not None and self.category_names:
            scores_array = cosine_similarity(text_vector, self.centroid_matrix)[0]
            similarities = {
                cat: float(scores_array[i])
                for i, cat in enumerate(self.category_names)
            }
        else:
            # Fallback: per-category loop (centroid_matrix not built yet)
            similarities = {}
            for category, centroid in self.category_centroids.items():
                if centroid is not None:
                    similarity = cosine_similarity(
                        text_vector, centroid.reshape(1, -1)
                    )[0][0]
                    similarities[category] = float(similarity)

        # Find best category above threshold
        best_category = None
        best_score = 0.0
        for category, score in similarities.items():
            if score >= threshold and score > best_score:
                best_category = category
                best_score = score

        return best_category, similarities

# Initialize global TF-IDF classifier instance with category keywords
tfidf_classifier = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

# ─── Database Setup ───────────────────────────────────────────────
DB_TIMEOUT = 30.0
CACHE_REFRESH_INTERVAL = 60.0
RULE_CACHE_RELOAD_FILE = Path(DB_PATH).parent / ".rule_cache_reload"

_active_addon = None


def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = _connect_db()
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
            entities    TEXT,
            block_reason TEXT
        )
    """)
    # Ensure all columns exist in traffic_log (handles legacy 6-column tables from setup.sh)
    try:
        columns = [row[1] for row in c.execute("PRAGMA table_info(traffic_log)").fetchall()]
        if columns:
            if "path" not in columns:
                c.execute("ALTER TABLE traffic_log ADD COLUMN path TEXT")
            if "method" not in columns:
                c.execute("ALTER TABLE traffic_log ADD COLUMN method TEXT")
            if "entities" not in columns:
                c.execute("ALTER TABLE traffic_log ADD COLUMN entities TEXT")
            if "block_reason" not in columns:
                c.execute("ALTER TABLE traffic_log ADD COLUMN block_reason TEXT")
    except sqlite3.Error as e:
        print(f"[VIGILANT] Migration error for traffic_log columns in init_db: {e}")

    c.execute("CREATE INDEX IF NOT EXISTS idx_traffic_block_reason ON traffic_log(block_reason)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS throttle_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL,
            client_ip   TEXT,
            host        TEXT,
            rpm_current REAL,
            rpm_baseline REAL,
            action      TEXT,
            reason      TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS keyword_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sni_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL,
            client_ip   TEXT,
            domain      TEXT,
            request_count INTEGER DEFAULT 1,
            velocity_rps REAL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_sni_timestamp ON sni_requests(timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sni_client_ip ON sni_requests(client_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sni_domain ON sni_requests(domain)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sni_client_domain ON sni_requests(client_ip, domain)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS throttle_state (
            client_ip   TEXT PRIMARY KEY,
            is_throttled INTEGER DEFAULT 0,
            applied_at  REAL,
            recovery_at REAL,
            cycle_count INTEGER DEFAULT 0
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_throttle_state_client ON throttle_state(client_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_throttle_state_recovery ON throttle_state(recovery_at)")

    # Ensure network_devices table exists so UPSERT in update_device_activity works
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_devices (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            hostname TEXT,
            custom_name TEXT,
            policy TEXT DEFAULT 'none',
            first_seen REAL,
            last_seen REAL,
            updated_at REAL
        )
    """)
    # Add doomscroll_exempt column if missing (for older databases)
    try:
        columns = [row[1] for row in c.execute("PRAGMA table_info(network_devices)").fetchall()]
        if columns and "doomscroll_exempt" not in columns:
            c.execute("ALTER TABLE network_devices ADD COLUMN doomscroll_exempt INTEGER DEFAULT 0")
    except sqlite3.Error:
        pass

    # Clean up any loopback entries that may have been stored before the guard was added
    try:
        c.execute("DELETE FROM network_devices WHERE ip_address LIKE '127.%' OR ip_address = '::1'")
    except sqlite3.Error:
        pass

    conn.commit()
    conn.close()

db_lock = threading.Lock()

def load_proxy_config():
    """Load proxy and behavioral configuration from database"""
    try:
        conn = _connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT value FROM config_settings WHERE key = 'network_velocity_threshold'")
        row = cursor.fetchone()
        network_velocity_threshold = float(row[0]) if row else DEFAULT_VELOCITY_THRESHOLD

        cursor.execute("SELECT value FROM config_settings WHERE key = 'physical_scroll_threshold'")
        row = cursor.fetchone()
        physical_scroll_threshold = int(row[0]) if row else 30

        cursor.execute("SELECT value FROM config_settings WHERE key = 'nlp_enabled'")
        row = cursor.fetchone()
        nlp_enabled_str = row[0] if row else "true"
        nlp_enabled = nlp_enabled_str.lower() in ["true", "1", "yes"]

        cursor.execute("SELECT value FROM config_settings WHERE key = 'sni_filtering_enabled'")
        row = cursor.fetchone()
        sni_filtering_enabled_str = row[0] if row else "true"
        sni_filtering_enabled = sni_filtering_enabled_str.lower() in ["true", "1", "yes"]

        cursor.execute("SELECT value FROM config_settings WHERE key = 'proxy_throttle_rate'")
        row = cursor.fetchone()
        throttle_rate = row[0] if row else DEFAULT_THROTTLE_RATE

        cursor.execute("SELECT value FROM config_settings WHERE key = 'proxy_pinned_domains'")
        row = cursor.fetchone()
        pinned_domains_str = row[0] if row else DEFAULT_PINNED_DOMAINS

        pinned_domains = set()
        for domain in pinned_domains_str.split(','):
            domain = domain.strip()
            if domain:
                pinned_domains.add(domain)
                if not domain.startswith('www.'):
                    pinned_domains.add(f'www.{domain}')

        conn.close()

        return {
            'network_velocity_threshold': network_velocity_threshold,
            'physical_scroll_threshold': physical_scroll_threshold,
            'nlp_enabled': nlp_enabled,
            'sni_filtering_enabled': sni_filtering_enabled,
            'throttle_rate': throttle_rate,
            'pinned_domains': pinned_domains
        }
    except Exception as e:
        print(f"[VIGILANT] Error loading proxy config from database: {e}, using defaults")
        return {
            'network_velocity_threshold': DEFAULT_VELOCITY_THRESHOLD,
            'physical_scroll_threshold': 30,
            'nlp_enabled': True,
            'sni_filtering_enabled': True,
            'throttle_rate': DEFAULT_THROTTLE_RATE,
            'pinned_domains': set(DEFAULT_PINNED_DOMAINS.split(','))
        }


def load_category_hints():
    """Load category hints from database or in-memory cache when available."""
    if _active_addon is not None:
        with _active_addon._cache_lock:
            if _active_addon._last_cache_refresh > 0:
                return {k: set(v) for k, v in _active_addon.cached_hints.items()}

    try:
        conn = _connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            conn.close()
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


def get_blacklisted_keywords():
    """Return blacklisted keywords from in-memory cache or database."""
    if _active_addon is not None:
        with _active_addon._cache_lock:
            if _active_addon._last_cache_refresh > 0:
                return list(_active_addon.cached_keywords)

    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
        keywords = [row[0] for row in cursor.fetchall()]
        conn.close()
        return keywords
    except Exception as e:
        print(f"[VIGILANT] Error loading keyword blacklist from database: {e}")
        return []


def load_social_domains():
    """Load social domains from category_hints (Distracting category)"""
    category_hints = load_category_hints()
    if category_hints:
        distracting = category_hints.get("Distracting", set())
        if distracting:
            social_domains = set()
            for domain in distracting:
                social_domains.add(domain)
                if not domain.startswith("www."):
                    social_domains.add(f"www.{domain}")
            return social_domains

    try:
        conn = _connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            conn.close()
            return DEFAULT_SOCIAL_DOMAINS

        cursor.execute("SELECT domain FROM category_hints WHERE category = 'Distracting'")
        rows = cursor.fetchall()

        social_domains = set()
        for (domain,) in rows:
            social_domains.add(domain)
            if not domain.startswith('www.'):
                social_domains.add(f'www.{domain}')

        conn.close()

        if not social_domains:
            return DEFAULT_SOCIAL_DOMAINS

        return social_domains
    except Exception as e:
        print(f"[VIGILANT] Error loading social domains from database: {e}, using defaults")
        return DEFAULT_SOCIAL_DOMAINS

# Categories that represent real, classified user web activity.
_LOGGABLE_CATEGORIES = {"educational", "productive", "distracting", "harmful"}

_NOISE_CATEGORIES = {"non-html", "dns_tracked", "dns", "dns_query", "mobile_bypass", "uncategorized"}


def log_request(client_ip, host, path, method, category, flagged, entities, block_reason=None):
    """
    Log HTTP/HTTPS/TLS requests to traffic_log table with block reason tracking.
    
    Args:
        client_ip: Client IP address
        host: Requested host/domain
        path: Request path
        method: HTTP method
        category: Content category (Educational, Productive, Distracting, Harmful)
        flagged: Whether request was blocked
        entities: NER entities detected
        block_reason: Comma-separated block reasons (KEYWORD_MATCH, DOMAIN_BLOCKED, CATEGORY_BLOCKED)
    """
    category_key = (category or "").strip().lower()

    if category_key in _NOISE_CATEGORIES:
        return

    if category_key not in _LOGGABLE_CATEGORIES:
        return

    # Normalize block_reason to comma-separated string
    if block_reason is None:
        block_reason = ""
    elif isinstance(block_reason, list):
        block_reason = ",".join(str(r) for r in block_reason if r)
    else:
        block_reason = str(block_reason)

    try:
        with db_lock:
            conn = _connect_db()
            conn.execute(
                "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged, entities, block_reason) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (time.time(), client_ip, host, path, method,
                 category, int(flagged), str(entities), block_reason)
            )
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in log_request: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in log_request: {e}")

def update_device_activity(client_ip):
    """Update or insert the last_seen timestamp for a device in network_devices.
    Skips loopback addresses (127.0.0.1, ::1) which appear in transparent proxy
    mode when iptables REDIRECT causes peername to resolve to localhost."""
    if not client_ip or client_ip.startswith("127.") or client_ip == "::1":
        return
    try:
        with db_lock:
            conn = _connect_db()
            now = time.time()
            conn.execute(
                "INSERT INTO network_devices (ip_address, last_seen, first_seen) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(ip_address) DO UPDATE SET last_seen = excluded.last_seen",
                (client_ip, now, now)
            )
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[VIGILANT] Error updating device activity for {client_ip}: {e}")

def is_device_exempt(client_ip):
    """Check if a device is exempt from doomscrolling throttling.
    
    Devices with policy='whitelist' or doomscroll_exempt=1 in network_devices
    are exempt from behavioral throttling.
    
    Args:
        client_ip: Client IP address
    
    Returns:
        bool: True if device is exempt from doomscroll throttling
    """
    try:
        with db_lock:
            conn = _connect_db()
            cursor = conn.execute(
                "SELECT policy, doomscroll_exempt FROM network_devices WHERE ip_address = ?",
                (client_ip,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if row:
                policy = row[0] or 'none'
                exempt = row[1] if row[1] is not None else 0
                return policy == 'whitelist' or exempt == 1
            return False
    except Exception as e:
        # If column doesn't exist yet, fall back to policy-only check
        try:
            with db_lock:
                conn = _connect_db()
                cursor = conn.execute(
                    "SELECT policy FROM network_devices WHERE ip_address = ?",
                    (client_ip,)
                )
                row = cursor.fetchone()
                conn.close()
                if row:
                    return (row[0] or 'none') == 'whitelist'
        except Exception:
            # Migration fallback: column may not exist yet
            pass
        return False

def log_throttle(client_ip, host, rpm_now, rpm_base, action, reason=""):
    try:
        with db_lock:
            conn = _connect_db()
            conn.execute(
                "INSERT INTO throttle_events (timestamp, client_ip, host, rpm_current, rpm_baseline, action, reason) VALUES (?,?,?,?,?,?,?)",
                (time.time(), client_ip, host, rpm_now, rpm_base, action, reason)
            )
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in log_throttle: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in log_throttle: {e}")

def log_sni_request(client_ip, domain, velocity_rps):
    """
    Log SNI requests with velocity tracking for scroll rate monitoring.
    
    Args:
        client_ip: Client IP address
        domain: SNI domain name
        velocity_rps: Current requests per second for this client-domain pair
    """
    try:
        with db_lock:
            conn = _connect_db()
            conn.execute(
                "INSERT INTO sni_requests (timestamp, client_ip, domain, request_count, velocity_rps) "
                "VALUES (?,?,?,?,?)",
                (time.time(), client_ip, domain, 1, velocity_rps)
            )
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in log_sni_request: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in log_sni_request: {e}")

# SNI request tracking for velocity calculation
sni_request_history = defaultdict(lambda: deque())
sni_velocity_lock = threading.Lock()
SNI_VELOCITY_WINDOW = 5  # 5-second window for RPS calculation

def compute_sni_velocity(client_ip, domain):
    """
    Calculate requests per second (RPS) for SNI requests from a specific client to a specific domain.
    
    Args:
        client_ip: Client IP address
        domain: SNI domain name
    
    Returns:
        float: Current RPS for this client-domain pair
    """
    now = time.time()
    with sni_velocity_lock:
        key = f"{client_ip}:{domain}"
        dq = sni_request_history[key]
        
        # Remove requests outside the 5-second window
        while dq and now - dq[0] > SNI_VELOCITY_WINDOW:
            dq.popleft()
        
        # Add current request
        dq.append(now)
        
        # Calculate RPS
        rps = len(dq) / SNI_VELOCITY_WINDOW
        return rps

# ─── Velocity Monitor ─────────────────────────────────────────────
request_history   = defaultdict(lambda: deque())
session_totals    = defaultdict(int)
session_start     = defaultdict(float)
throttled_clients = set()
throttled_clients_lock = threading.Lock()
velocity_lock     = threading.Lock()


def _mark_client_throttled(client_ip):
    """Atomically check if a client is throttled and mark them if not.
    Returns True if the client was newly marked, False if already throttled."""
    with throttled_clients_lock:
        if client_ip in throttled_clients:
            return False
        throttled_clients.add(client_ip)
        return True

# Circuit breaker state per client
# Structure: { client_ip: { "level": int, "first_seen": float, "escalation_times": {level: float}, "domain": str, "cooldown_until": float } }
circuit_breaker_state = {}
cb_state_lock = threading.Lock()



def escalate_circuit_breaker(client_ip, domain, rpm_current=0, rpm_baseline=0):
    """Escalate the circuit breaker level based on elapsed time.
    
    Args:
        client_ip: Client IP address
        domain: Social media domain being accessed
        rpm_current: Current requests-per-minute (for logging)
        rpm_baseline: Baseline session average RPM (for logging)
    
    Returns:
        int: The new circuit breaker level
    """
    with cb_state_lock:
        now = time.time()
        if client_ip not in circuit_breaker_state:
            circuit_breaker_state[client_ip] = {
                "level": CB_LEVEL_NONE,
                "first_seen": now,
                "escalation_times": {},
                "domain": domain,
                "cooldown_until": 0
            }
        
        state = circuit_breaker_state[client_ip]
        
        # Check cooldown
        if state.get("cooldown_until", 0) > now:
            return CB_LEVEL_NONE
        
        # Auto-release if throttled for too long
        # Prevents the throttle from sticking forever when background traffic
        # (iCloud, notifications) keeps the pause reset from triggering.
        total_elapsed = now - state["first_seen"]
        if total_elapsed >= CB_MAX_THROTTLE_DURATION and state["level"] != CB_LEVEL_NONE:
            print(f"[VIGILANT] CB auto-release for {client_ip}: throttled for {total_elapsed:.0f}s, max reached")
            # Set a cooldown so it doesn't immediately re-trigger on the next request
            state["cooldown_until"] = now + CB_COOLDOWN_SECONDS
            state["level"] = CB_LEVEL_NONE
            remove_throttle_cycle(client_ip)
            return CB_LEVEL_NONE
        
        # Cooldown expired OR no cooldown — reset level so escalation can re-trigger.
        # Without this, once at Level 3, the circuit breaker can never escalate
        # again because `new_level > state["level"]` would require a Level 4.
        if state["level"] != CB_LEVEL_NONE:
            state["level"] = CB_LEVEL_NONE
            state["first_seen"] = now
            state["escalation_times"] = {}
            print(f"[VIGILANT] CB reset for {client_ip}: cooldown expired, fresh start")
        
        elapsed = now - state["first_seen"]
        
        # Determine level based on elapsed time
        if elapsed >= CB_BREAK_SECONDS:
            new_level = CB_LEVEL_CIRCUIT_BREAK
        elif elapsed >= CB_FRICTION_SECONDS:
            new_level = CB_LEVEL_FRICTION
        elif elapsed >= CB_PAUSE_SECONDS:
            new_level = CB_LEVEL_PAUSE
        else:
            new_level = CB_LEVEL_NONE
        
        # Record escalation time if new level is higher
        if new_level > state["level"]:
            state["level"] = new_level
            state["escalation_times"][new_level] = now
            state["domain"] = domain
            print(f"[VIGILANT] CIRCUIT BREAKER ESCALATED {client_ip} to Level {new_level} ({CB_LEVEL_NAMES[new_level]}) @ {domain}")
        
        return state["level"]

def apply_circuit_breaker_action(client_ip, domain, level, rpm_current=0, rpm_baseline=0):
    """Apply the appropriate intervention based on circuit breaker level.
    
    Args:
        client_ip: Client IP address
        domain: Social media domain being accessed
        level: Circuit breaker level (CB_LEVEL_*)
        rpm_current: Current requests-per-minute (for throttle_events logging)
        rpm_baseline: Baseline session average RPM (for throttle_events logging)
    
    Returns:
        bool: True if action was applied
    """
    if level == CB_LEVEL_NONE:
        return False
    
    if level == CB_LEVEL_PAUSE:
        # Level 1: 4kbit — persists until escalation or pause reset
        log_throttle(client_ip, domain, rpm_current, rpm_baseline, "CB_PAUSE", f"Circuit Breaker Level 1 - Forced Pause @ {domain}")
        success = apply_throttle(client_ip, rate="4kbit")
        if success:
            # No recovery timer — throttle stays until user stops for 60s
            # or circuit breaker escalates to a higher level.
            save_throttle_state(client_ip, is_throttled=True, recovery_at=0)
            print(f"[VIGILANT] CB PAUSE: {client_ip} @ 4kbit applied (persistent)")
        return success
    
    elif level == CB_LEVEL_FRICTION:
        # Level 2: 2kbit — tighter throttle, still persistent
        log_throttle(client_ip, domain, rpm_current, rpm_baseline, "CB_FRICTION", f"Circuit Breaker Level 2 - Bandwidth Friction @ {domain}")
        success = apply_throttle(client_ip, rate="2kbit")
        if success:
            save_throttle_state(client_ip, is_throttled=True, recovery_at=0)
            print(f"[VIGILANT] CB FRICTION: {client_ip} @ 2kbit applied (persistent)")
        return success
    
    elif level == CB_LEVEL_CIRCUIT_BREAK:
        # Level 3: 1kbit — lasts 2 minutes, then cooldown
        log_throttle(client_ip, domain, rpm_current, rpm_baseline, "CB_CIRCUIT_BREAK", f"Circuit Breaker Level 3 - Hard Circuit Break @ {domain}")
        success = apply_throttle(client_ip, rate="1kbit")
        if success:
            recovery_duration = 120
            save_throttle_state(client_ip, is_throttled=True, recovery_at=time.time() + recovery_duration)
            # Only Level 3 gets a recovery timer — the "cool off" period
            recovery_timer = threading.Timer(recovery_duration, remove_throttle_cycle, args=[client_ip])
            with throttle_timers_lock:
                _cancel_timer(client_ip)
                throttle_timers[client_ip] = recovery_timer
            recovery_timer.start()
            with cb_state_lock:
                if client_ip in circuit_breaker_state:
                    circuit_breaker_state[client_ip]["cooldown_until"] = time.time() + recovery_duration + CB_COOLDOWN_SECONDS
            print(f"[VIGILANT] CB CIRCUIT BREAK: {client_ip} - 120s @ 1kbit + {CB_COOLDOWN_SECONDS}s cooldown")
        return success
    
    return False

def release_circuit_breaker(client_ip):
    """Manually release circuit breaker state for a client."""
    with cb_state_lock:
        circuit_breaker_state.pop(client_ip, None)
    remove_throttle_cycle(client_ip)
    print(f"[VIGILANT] Circuit breaker released for {client_ip}")

def get_all_circuit_breaker_states():
    """Get all active circuit breaker states for API query."""
    with cb_state_lock:
        result = []
        now = time.time()
        for ip, state in circuit_breaker_state.items():
            elapsed = now - state["first_seen"]
            result.append({
                "client_ip": ip,
                "level": state["level"],
                "level_name": CB_LEVEL_NAMES.get(state["level"], "Unknown"),
                "domain": state.get("domain", ""),
                "elapsed_seconds": round(elapsed, 1),
                "escalation_times": state.get("escalation_times", {}),
                "cooldown_until": state.get("cooldown_until", 0),
                "is_throttled": ip in throttled_clients
            })
        return result

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


def _cleanup_stale_velocity_state():
    """Periodic cleanup of stale velocity tracking dictionaries to prevent
    unbounded memory growth. Removes entries for IPs that have no recent
    request history (idle for > 2 * VELOCITY_WINDOW)."""
    now = time.time()
    stale_cutoff = now - (VELOCITY_WINDOW * 2)
    with velocity_lock:
        # Identify IPs whose newest request is older than the cutoff
        stale_ips = []
        for ip, dq in list(request_history.items()):
            if not dq or dq[-1] < stale_cutoff:
                stale_ips.append(ip)
        for ip in stale_ips:
            del request_history[ip]
            session_totals.pop(ip, None)
            session_start.pop(ip, None)

def should_throttle(client_ip, host, path=""):
    config = load_proxy_config()
    network_velocity_threshold = config['network_velocity_threshold']
    physical_scroll_threshold = config['physical_scroll_threshold']
    social_domains = load_social_domains()

    # Always accumulate velocity for every request (including CDN/cookie
    # subdomains of social platforms) so the RPM counter reflects actual
    # user activity, not only the primary hostname.  Throttle check on
    # social domains happens below.
    rpm_now, rpm_base = compute_velocity(client_ip)

    # Skip throttle check for exempt devices
    if is_device_exempt(client_ip):
        return False, rpm_now, rpm_base

    # Social-domain + CDN detection: match base domain AND CDN/cookie
    # subdomains of known social platforms so media-fetch traffic is
    # counted alongside API traffic.
    SOCIAL_CDN_SUFFIXES = {
        "tiktokcdn.com", "tiktokv.com", "tiktok.com", "tiktok-minis.us",
        "zijieapi.com", "bytedance.net", "bytedance.com",
        "facebook.com", "fbcdn.net", "facebook.net",
        "instagram.com", "cdninstagram.com",
        "twitter.com", "x.com",
        "reddit.com", "redditmedia.com",
        "youtube.com", "googlevideo.com", "ytimg.com",
    }
    clean_host = host.removeprefix("www.")

    # Match on the base domain (e.g. "facebook.com" from "graph.facebook.com")
    # AND on CDN suffixes ("fbcdn.net" matches directly)
    is_social = False
    for suffix in social_domains | DEFAULT_SOCIAL_DOMAINS | SOCIAL_CDN_SUFFIXES:
        if clean_host == suffix:
            is_social = True
            break
        if clean_host.endswith("." + suffix):
            is_social = True
            break

    if not is_social:
        return False, rpm_now, rpm_base

    # Optional: YouTube / IG short-form detection
    is_youtube = "youtube.com" in clean_host or "googlevideo.com" in clean_host
    if is_youtube and not ("/shorts/" in path or "shorts" in path):
        return False, rpm_now, rpm_base

    if session_totals[client_ip] < MIN_REQUESTS_BASELINE:
        return False, rpm_now, rpm_base

    flagged = (rpm_now > (rpm_base * network_velocity_threshold)) or (rpm_now > physical_scroll_threshold)
    
    # Combined spacing check + sustained activity detector
    # (single velocity_lock to avoid nesting issues)
    with velocity_lock:
        dq = request_history[client_ip]
        
        # Sustained activity detector: if the user has been on social media for
        # longer than the pause threshold (30s), flag them regardless of RPM.
        if not flagged and session_totals[client_ip] >= MIN_REQUESTS_BASELINE:
            session_elapsed = time.time() - session_start[client_ip]
            if session_elapsed >= CB_PAUSE_SECONDS:
                flagged = True
                print(f"[VIGILANT] Sustained social media for {client_ip}: {session_elapsed:.0f}s active, flagging")
        
        # Burst detection (only if already flagged)
        if flagged and len(dq) >= physical_scroll_threshold:
            time_for_threshold_reqs = time.time() - dq[-physical_scroll_threshold]
            if time_for_threshold_reqs < 10:
                print(f"[VIGILANT] Burst detected for {client_ip}: "
                      f"{physical_scroll_threshold} requests in {time_for_threshold_reqs:.1f}s")
        
        # Spacing check: if avg gap between requests < 20s, flag
        if len(dq) >= 10:
            time_gaps = []
            for i in range(len(dq) - 1):
                gap = dq[i + 1] - dq[i]
                time_gaps.append(gap)
            if time_gaps:
                avg_gap = sum(time_gaps) / len(time_gaps)
                if avg_gap < 20:
                    flagged = True
                    print(f"[VIGILANT] Rapid spacing detect for {client_ip}: avg_gap={avg_gap:.1f}s")
                # Per-level de-escalation: check if the user paused long enough
                # to recover from the current throttle level.
                # L1 (4kbit): needs 60s pause → release
                # L2 (2kbit): needs 90s pause → release
                # L3 (1kbit): needs 120s pause → release
                max_gap = max(time_gaps) if time_gaps else 0
                with cb_state_lock:
                    current_level = circuit_breaker_state.get(client_ip, {}).get("level", CB_LEVEL_NONE)
                deescalation_gap = get_deescalation_seconds().get(current_level, 120)
                if max_gap > deescalation_gap:
                    with cb_state_lock:
                        if client_ip in circuit_breaker_state:
                            del circuit_breaker_state[client_ip]
                            print(f"[VIGILANT] CB RESET: {client_ip} paused {max_gap:.0f}s at L{current_level} (>{deescalation_gap}s) — releasing")
                    remove_throttle_cycle(client_ip)
                    flagged = False

    return flagged, rpm_now, rpm_base

def normalize_text_simple(text: str) -> str:
    """
    Simple text normalization for keyword matching.
    Lowercase and collapse whitespace/punctuation to single spaces.
    """
    if not text:
        return ""
    lowered = text.lower()
    collapsed = re.sub(r'[^a-z0-9]+', ' ', lowered)
    return re.sub(r'\s+', ' ', collapsed).strip()


def scan_text_for_keywords(text: str, keywords) -> str:
    """
    Efficient keyword detection using normalized token intersection.
    Returns the first matched keyword or None.
    
    This approach is much faster than TF-IDF for explicit blacklist checking
    since blacklist keywords are exact matches rather than semantic similarity.
    """
    if not text or not keywords:
        return None
    
    normalized_text = normalize_text_simple(text)
    normalized_tokens = set(normalized_text.split())
    
    for keyword in keywords:
        normalized_keyword = normalize_text_simple(keyword)
        keyword_tokens = set(normalized_keyword.split())
        
        # Check if all keyword tokens are present in the text
        if keyword_tokens.issubset(normalized_tokens):
            return keyword
    
    return None


def get_domain_hint(host):
    category_hints = load_category_hints()
    clean = host.removeprefix("www.")
    for category, domains in category_hints.items():
        if any(clean == d or clean.endswith("." + d) for d in domains):
            return category, 3
    return None, 0


def categorize_content(text, host=""):
    if not text:
        text = ""

    hint_category, _hint_score = get_domain_hint(host)
    protected_hint = hint_category in ("Educational", "Productive")

    config = load_proxy_config()
    nlp_enabled = config['nlp_enabled']

    if nlp_enabled:
        doc      = nlp(text[:10000]) if len(text) >= 20 else None
        entities = [(ent.text, ent.label_) for ent in doc.ents] if doc else []
    else:
        doc = None
        entities = []

    # Use TF-IDF classifier for cosine similarity-based categorization.
    # Use higher threshold (0.15-0.20) for full page content to avoid false
    # positives from boilerplate.  Truncate to SAMPLE_PREFIX_BYTES at the
    # call-site so the classify() truncation guard never needs to copy a
    # large string unnecessarily (classify() also guards internally).
    classification_threshold = float(config.get('tfidf_classification_threshold', 0.15))
    classify_text = text[:SAMPLE_PREFIX_BYTES] if len(text) > SAMPLE_PREFIX_BYTES else text
    tfidf_category, tfidf_scores = tfidf_classifier.classify(classify_text, threshold=classification_threshold)

    # If domain hint exists and is protected, give it priority
    if hint_category:
        if protected_hint:
            # For protected hints, require strong TF-IDF evidence to override
            if tfidf_category == "Harmful" and tfidf_scores.get("Harmful", 0) > 0.3:
                category = "Harmful"
            else:
                category = hint_category
        else:
            # For non-protected hints, TF-IDF can override with moderate confidence
            if tfidf_category and tfidf_scores.get(tfidf_category, 0) > 0.15:
                category = tfidf_category
            else:
                category = hint_category
    else:
        # No domain hint, use TF-IDF classification
        category = tfidf_category if tfidf_category else "Uncategorized"

    # NER weighting for additional context
    if doc and doc.ents:
        for ent in doc.ents:
            if ent.label_ in {"LAW", "WORK_OF_ART", "EVENT", "ORG", "PERSON", "GPE"} and category == "Uncategorized":
                category = "Educational"
            elif ent.label_ in {"DATE", "TIME", "CARDINAL", "ORDINAL"} and category == "Uncategorized":
                category = "Productive"

    # Utility context guard for Harmful classification
    if category == "Harmful":
        utility_terms = {"git", "code", "dev", "assets", "static", "github", "google", "microsoft", "apple"}
        text_lower = text.lower()
        has_utility_context = any(term in text_lower for term in utility_terms)
        if has_utility_context:
            category = "Educational"

    return category, entities


# ─── Traffic Control Throttling ───────────────────────────────────────
def get_distribution_interface():
    """Get the distribution interface from database config or auto-detect.
    
    First tries the database config. If that's missing or the interface doesn't
    exist, scans /proc/net/dev for the interface that carries the gateway IP
    (192.168.10.1). This ensures tc rules are applied to the correct interface
    even if the database has stale defaults like "eth1".
    """
    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'distribution_interface'")
        row = cursor.fetchone()
        conn.close()
        candidate = row[0] if row else None
        # Verify the configured interface actually exists
        if candidate:
            try:
                with open("/proc/net/dev") as f:
                    for line in f:
                        if line.strip().startswith(candidate + ":"):
                            return candidate
            except OSError:
                pass
    except Exception:
        pass
    
    # Auto-detect: find the interface with the LAN gateway IP (192.168.10.1)
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, check=False, timeout=3
        )
        current_iface = None
        for line in result.stdout.split("\n"):
            # Line with interface name: "2: enp1s0: <BROADCAST,...>"
            if ": " in line and "state" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    name = parts[1].strip().split()[0] if parts[1].strip() else None
                    if name:
                        current_iface = name
            # Line with IP address: "    inet 192.168.10.1/24 ..."
            if current_iface and "inet 192.168.10." in line:
                return current_iface
    except Exception:
        pass
    
    # Last resort: scan /proc/net/dev for any eth/en interface that's UP
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if "eth" in line or "enp" in line or "enx" in line:
                    iface = line.split(":")[0].strip()
                    if iface and iface != "lo":
                        return iface
    except OSError:
        pass
    
    return "eth1"

def apply_throttle(client_ip, rate=None):
    """
    Apply Linux traffic control (tc) rules to throttle bandwidth for a given client IP.
    Uses a unique classId per device so that each client gets its own bandwidth ceiling.
    
    Args:
        client_ip: Client IP address to throttle
        rate: Throttle rate (e.g., "64kbit", "128kbit"). If None, uses config default.
    
    Returns:
        bool: True if throttle applied successfully, False otherwise
    """
    config = load_proxy_config()
    # Use the explicit rate if provided (e.g. from circuit breaker),
    # otherwise fall back to the configured default from the database.
    # NOTE: we check `rate is not None` rather than `rate or ...` because
    # an empty string "" is falsy but should be treated as a valid rate.
    if rate is not None:
        throttle_rate = str(rate)
    else:
        throttle_rate = config['throttle_rate']
    interface = get_distribution_interface()
    
    # Derive a unique classId from the client IP (1:10 through 1:fffe)
    ip_hash = abs(hash(client_ip)) % 0xfff0 + 0x0010  # range 1:10 to 1:fffe
    class_id = f"1:{ip_hash:x}"
    prio = ip_hash

    try:
        # Ensure root qdisc exists (quietly; it may already be set up)
        result = subprocess.run(
            ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "1"],
            check=False, capture_output=True, text=True
        )
        if result.returncode != 0 and "RTNETLINK answers: File exists" not in result.stderr:
            print(f"[VIGILANT] tc qdisc add error on {interface}: {result.stderr.strip()}")

        # Remove any stale class + filter for this client first (clean re-apply).
        # This is critical: without it, tc class add fails with "File exists"
        # when circuit breaker escalates to a higher throttle level, meaning
        # the user would be stuck at the old rate indefinitely.
        remove_throttle(client_ip)

        # Add a dedicated class for this client IP.
        # burst=2k allows only ~2KB at line rate before the throttle kicks in.
        # This means the TCP handshake completes but the very first data packet
        # gets shaped, making throttling immediately noticeable.
        result = subprocess.run(
            ["tc", "class", "add", "dev", interface, "parent", "1:", "classid", class_id,
             "htb", "rate", throttle_rate, "ceil", throttle_rate,
             "burst", "2k", "cburst", "2k"],
            check=False, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[VIGILANT] tc class add failed for {client_ip} on {interface}: {result.stderr.strip()}")
            return False

        # Match traffic sent TO the client (downloads)
        result = subprocess.run(
            ["tc", "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "dst", client_ip, "flowid", class_id],
            check=False, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[VIGILANT] tc filter dst failed for {client_ip} on {interface}: {result.stderr.strip()}")
            return False

        # Match traffic FROM the client (uploads)
        result = subprocess.run(
            ["tc", "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "src", client_ip, "flowid", class_id],
            check=False, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[VIGILANT] tc filter src failed for {client_ip} on {interface}: {result.stderr.strip()}")
            return False
        
        # Store mapping for later removal
        _throttle_map[client_ip] = class_id
        
        print(f"[VIGILANT] Throttling applied to {client_ip} on {interface} at {throttle_rate} burst=2k (classId={class_id})")
        return True
    except Exception as e:
        print(f"[VIGILANT] Throttling FAILED for {client_ip} on {interface}: {e}")
        return False

def remove_throttle(client_ip, client_ip_only=False):
    """
    Remove traffic control throttling for a specific client IP.
    Only removes the filters and class for THIS client – does NOT destroy other devices' throttles.
    
    Args:
        client_ip: Client IP address to unthrottle
        client_ip_only: If True, removes only the matching IP filter (internal re-apply usage)
    
    Returns:
        bool: True if throttle removed successfully, False otherwise
    """
    interface = get_distribution_interface()
    
    # Get the classId assigned to this client
    ip_hash = abs(hash(client_ip)) % 0xfff0 + 0x10
    class_id = f"1:{ip_hash:x}"
    prio = ip_hash
    
    # Also try stored mapping if available
    stored_class = _throttle_map.get(client_ip)
    if stored_class:
        class_id = stored_class
        del _throttle_map[client_ip]
    
    try:
        # Remove dst filter for this specific client
        subprocess.run(
            ["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "dst", client_ip, "flowid", class_id],
            check=False, capture_output=True
        )
        # Remove src filter for this specific client
        subprocess.run(
            ["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "src", client_ip, "flowid", class_id],
            check=False, capture_output=True
        )
        
        if not client_ip_only:
            # Remove the dedicated class for this client ONLY
            subprocess.run(
                ["tc", "class", "del", "dev", interface, "parent", "1:", "classid", class_id],
                check=False, capture_output=True
            )
        
        print(f"[VIGILANT] Throttle cleanup completed for {client_ip} on {interface}")
        return True
    except Exception as e:
        print(f"[VIGILANT] Throttle cleanup failed for {client_ip}: {e}")
        return False

# Throttle cycle tracking
throttle_timers = {}  # client_ip -> Timer object
_throttle_map = {}  # client_ip -> tc classId mapping
throttle_timers_lock = threading.Lock()
THROTTLE_CYCLE_DURATION = 600  # 10 minutes in seconds


def _cancel_timer(client_ip):
    """Safely cancel and remove an existing throttle timer for a client."""
    timer = throttle_timers.pop(client_ip, None)
    if timer is not None:
        try:
            timer.cancel()
        except Exception:
            pass


def apply_throttle_cycle(client_ip):
    """
    Apply progressive 100% -> 10% -> 100% throttle cycle for doomscrolling detection.
    
    Args:
        client_ip: Client IP address to throttle
    
    Returns:
        bool: True if throttle cycle started successfully, False otherwise
    """
    # Cancel any existing timer for this client
    with throttle_timers_lock:
        old_timer = throttle_timers.pop(client_ip, None)
        if old_timer is not None:
            try:
                old_timer.cancel()
                print(f"[VIGILANT] Cancelled existing throttle timer for {client_ip}")
            except Exception as e:
                print(f"[VIGILANT] Error cancelling timer for {client_ip}: {e}")

    # Drop to a strict rate immediately when doomscrolling detected.
    # 32kbit = 4 KB/s.  Enough for plain-text and a trickle of header metadata
    # so pages partially load, but images/video stall hard.  Combined with the
    # 16k burst in apply_throttle, the initial TCP handshake + HTTP request
    # complete quickly, then the client hits the wall.
    success = apply_throttle(client_ip, rate="32kbit")

    if success:
        # Save throttle state to database
        save_throttle_state(client_ip, is_throttled=True, recovery_at=time.time() + THROTTLE_CYCLE_DURATION)

        # Schedule automatic recovery after 2 minutes
        recovery_timer = threading.Timer(
            THROTTLE_CYCLE_DURATION,
            remove_throttle_cycle,
            args=[client_ip]
        )

        with throttle_timers_lock:
            throttle_timers[client_ip] = recovery_timer

        recovery_timer.start()

        # Log to behavioral throttling table (separate from content filtering)
        log_throttle(client_ip, "throttle_cycle", 0, 0, "THROTTLE_CYCLE_APPLIED", "Doomscrolling detected - 10-minute throttle cycle")

        print(f"[VIGILANT] Throttle cycle started for {client_ip} - will recover in {THROTTLE_CYCLE_DURATION}s")

    return success


def remove_throttle_cycle(client_ip):
    """
    Remove throttle and clean up timer for a client IP.
    Also clears the circuit breaker state so the dashboard shows accurate info.
    
    Args:
        client_ip: Client IP address to unthrottle
    """
    # Remove TC rules
    remove_throttle(client_ip)

    # Clean up timer
    with throttle_timers_lock:
        throttle_timers.pop(client_ip, None)

    # Clean up from active throttled_clients set
    with throttled_clients_lock:
        throttled_clients.discard(client_ip)

    # Clear circuit breaker state so dashboard shows accurate info
    with cb_state_lock:
        circuit_breaker_state.pop(client_ip, None)

    # Update throttle state in database
    save_throttle_state(client_ip, is_throttled=False, recovery_at=0)

    # Log recovery
    log_throttle(client_ip, "throttle_cycle", 0, 0, "THROTTLE_CYCLE_REMOVED", "Throttle cycle completed - bandwidth restored")

    print(f"[VIGILANT] Throttle cycle completed for {client_ip} - bandwidth restored")


def save_throttle_state(client_ip, is_throttled, recovery_at):
    """
    Save throttle state to database for persistence across restarts.
    
    Args:
        client_ip: Client IP address
        is_throttled: Whether client is currently throttled
        recovery_at: Unix timestamp when throttle should recover
    """
    try:
        with db_lock:
            conn = _connect_db()

            cursor = conn.execute("SELECT cycle_count FROM throttle_state WHERE client_ip = ?", (client_ip,))
            existing = cursor.fetchone()

            if existing:
                cycle_count = existing[0] + 1 if is_throttled else existing[0]
                conn.execute(
                    "UPDATE throttle_state SET is_throttled=?, applied_at=?, recovery_at=?, cycle_count=? WHERE client_ip=?",
                    (int(is_throttled), time.time(), recovery_at, cycle_count, client_ip)
                )
            else:
                cycle_count = 1 if is_throttled else 0
                conn.execute(
                    "INSERT INTO throttle_state (client_ip, is_throttled, applied_at, recovery_at, cycle_count) "
                    "VALUES (?,?,?,?,?)",
                    (client_ip, int(is_throttled), time.time(), recovery_at, cycle_count)
                )

            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in save_throttle_state: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in save_throttle_state: {e}")


def load_throttle_state(client_ip):
    """
    Load throttle state from database.
    
    Args:
        client_ip: Client IP address
    
    Returns:
        dict: Throttle state or None
    """
    try:
        with db_lock:
            conn = _connect_db()
            cursor = conn.execute(
                "SELECT is_throttled, applied_at, recovery_at, cycle_count FROM throttle_state WHERE client_ip = ?",
                (client_ip,)
            )
            row = cursor.fetchone()
            conn.close()

            if row:
                return {
                    "is_throttled": bool(row[0]),
                    "applied_at": row[1],
                    "recovery_at": row[2],
                    "cycle_count": row[3]
                }
            return None
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in load_throttle_state: {e}")
        return None
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in load_throttle_state: {e}")
        return None



def restore_throttle_states():
    """
    Restore active throttle states from database on proxy startup.
    Re-applies throttling for clients that were throttled before restart.
    """
    time.sleep(5)  # Wait for proxy to fully initialize

    try:
        with db_lock:
            conn = _connect_db()
            now = time.time()
            cursor = conn.execute(
                "SELECT client_ip, recovery_at FROM throttle_state WHERE is_throttled = 1 AND recovery_at > ?",
                (now,)
            )
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                client_ip = row[0]
                recovery_at = row[1]
                time_remaining = recovery_at - now

                if time_remaining > 0:
                    print(f"[VIGILANT] Restoring throttle for {client_ip} ({time_remaining:.0f}s remaining)")
                    apply_throttle(client_ip, rate="32kbit")

                    recovery_timer = threading.Timer(
                        time_remaining,
                        remove_throttle_cycle,
                        args=[client_ip]
                    )

                    with throttle_timers_lock:
                        throttle_timers[client_ip] = recovery_timer

                    recovery_timer.start()
                    with throttled_clients_lock:
                        throttled_clients.add(client_ip)
                else:
                    save_throttle_state(client_ip, False, 0)

            print(f"[VIGILANT] Restored {len(rows)} throttle states from database")
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in restore_throttle_states: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in restore_throttle_states: {e}")

# ─── DNS Log Tailing Thread ─────────────────────────────────────────────
def tail_dnsmasq_log():
    """Background thread to tail dnsmasq log for passive DNS tracking"""
    log_path = "/var/log/dnsmasq.log"

    while True:
        try:
            with open(log_path, 'r') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    if "query[" in line and " from " in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("query[") and i + 2 < len(parts):
                                    domain = parts[i + 1]
                                    client_ip = parts[i + 3]
                                    
                                    update_device_activity(client_ip)

                                    flagged, rpm_now, rpm_base = should_throttle(client_ip, domain)
                                    if flagged and not is_device_exempt(client_ip):
                                        level = escalate_circuit_breaker(client_ip, domain, rpm_now, rpm_base)
                                        if level >= CB_LEVEL_PAUSE:
                                            _mark_client_throttled(client_ip)
                                        apply_circuit_breaker_action(client_ip, domain, level, rpm_now, rpm_base)
                                        if level >= CB_LEVEL_PAUSE:
                                            print(f"[VIGILANT] DNS CB Level {level} ({CB_LEVEL_NAMES[level]}) {client_ip} @ {domain} "
                                                  f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

                                    # DNS queries are NOT logged to traffic_log to avoid noise.
                                    # Velocity tracking (should_throttle above) and
                                    # update_device_activity cover the behavioral detection
                                    # and device-liveness tracking already.
                                    break
        except FileNotFoundError:
            time.sleep(5)
        except Exception as e:
            print(f"[VIGILANT] DNS log tailing error: {e}")
            time.sleep(5)





def get_scan_text(flow_response) -> (str, bool):
    """
    Returns (text_to_scan, was_sampled). For payloads under the cap,
    returns the fully decoded text. For oversized payloads, decodes only
    a bounded prefix+suffix slice of the raw bytes so we never hold or
    regex-scan the entire multi-megabyte body in memory.
    """
    raw = flow_response.content or b""
    if len(raw) <= MAX_PAYLOAD_SIZE:
        return (flow_response.text or ""), False

    charset = flow_response.charset or "utf-8"
    prefix = raw[:SAMPLE_PREFIX_BYTES]
    suffix = raw[-SAMPLE_SUFFIX_BYTES:] if len(raw) > SAMPLE_PREFIX_BYTES else b""

    def _decode(chunk):
        try:
            return chunk.decode(charset, errors="ignore")
        except (LookupError, Exception):
            return chunk.decode("utf-8", errors="ignore")

    sample_text = _decode(prefix) + " " + _decode(suffix)
    return sample_text, True


# ══════════════════════════════════════════════════════════════════
# ─── Flagged / Blocked Page ─────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════
# Self-contained HTML (no external CSS/font/CDN dependencies, since this
# is served directly by the proxy to arbitrary devices) shown whenever
# a request or response is blocked. Grey background, verdigris shield
# icon, white text, plus a plain-language explanation of why the page
# was flagged so it doesn't just look like a dead end.

_CATEGORY_EXPLANATIONS = {
    "Harmful": (
        "This page was flagged because it matched language patterns associated "
        "with harmful, violent, or exploitative content. Flagging is based on "
        "automated keyword and category analysis, not a manual review, so if you "
        "think this was blocked by mistake, ask whoever manages this network to "
        "take a look."
    ),
    "Distracting": (
        "This page was flagged as a high-distraction destination based on its "
        "content and recent browsing activity (endless-scroll feeds, viral or "
        "trending content). This is a network-level filter, not a judgment about "
        "you - ask whoever manages this network if you think the rules need "
        "adjusting."
    ),
}
_DEFAULT_EXPLANATION = (
    "This page matched a rule configured for this network's content filter. "
    "If you think this was blocked by mistake, ask whoever manages this "
    "network to take a look."
)

_BLOCK_PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Blocked - Vigilant Gateway</title>
<style>
  body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#4b4f54;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
       color:#ffffff;}}
  .card{{max-width:420px;text-align:center;padding:2.5rem 2rem;}}
  .shield{{width:64px;height:64px;color:#43B3AE;margin-bottom:1.25rem;}}
  h1{{font-size:22px;font-weight:600;margin:0 0 .5rem;}}
  .meta{{font-size:14px;color:#c7cacd;margin-bottom:1.25rem;word-break:break-all;}}
  .category-badge{{display:inline-block;background:rgba(67,179,174,0.15);color:#43B3AE;
                   font-size:12px;font-weight:600;padding:4px 10px;border-radius:12px;margin-bottom:1.25rem;
                   letter-spacing:.02em;}}
  .explain{{font-size:14px;line-height:1.6;color:#e3e5e7;border-top:1px solid rgba(255,255,255,0.15);
           padding-top:1.25rem;text-align:left;}}
  .brand{{font-size:12px;font-weight:600;color:#43B3AE;letter-spacing:.08em;margin-bottom:1.5rem;
         text-transform:uppercase;}}
</style>
</head>
<body>
<div class="card">
  <div class="brand">V.I.G.I.LA.N.T Gateway</div>
  <svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" stroke-linejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <h1>Access blocked</h1>
  <div class="meta">{host}</div>
  <div class="category-badge">{category}</div>
  <div class="explain">{explanation}</div>
</div>
</body>
</html>"""


def render_block_page(host: str, category: str = "Harmful") -> bytes:
    """
    Builds the styled block/flagged page shown to the user. Returns
    UTF-8 encoded bytes ready to hand to http.Response.make().
    """
    explanation = _CATEGORY_EXPLANATIONS.get(category, _DEFAULT_EXPLANATION)
    html = _BLOCK_PAGE_TEMPLATE.format(
        host=host or "this page",
        category=category or "Flagged",
        explanation=explanation,
    )
    return html.encode("utf-8")


# ─── mitmproxy Addon ──────────────────────────────────────────────
class VIGILANTAddon:

    def __init__(self):
        global _active_addon
        init_db()
        self.cached_keywords = []
        self.cached_hints = {}
        self.cached_exempt_devices = set()
        self._cache_lock = threading.Lock()
        self._last_cache_refresh = 0.0
        _active_addon = self
        self.pinned_hosts = set()
        self._refresh_rule_cache()
        print("[VIGILANT] Addon loaded. DB initialised. NLP model ready.")

        cache_thread = threading.Thread(target=self._cache_refresh_loop, daemon=True)
        cache_thread.start()
        print("[VIGILANT] Rule cache refresh thread started (interval=%ss)" % CACHE_REFRESH_INTERVAL)

        dns_thread = threading.Thread(target=tail_dnsmasq_log, daemon=True)
        dns_thread.start()
        print("[VIGILANT] DNS log tailing thread started")

        restore_thread = threading.Thread(target=restore_throttle_states, daemon=True)
        restore_thread.start()
        print("[VIGILANT] Throttle state restoration thread started")

    def _refresh_rule_cache(self):
        """Fetch blacklisted keywords and category hints from the database."""
        try:
            conn = _connect_db()
            cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
            keywords = [row[0] for row in cursor.fetchall()]

            hints = {}
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'"
            )
            if cursor.fetchone():
                cursor = conn.execute("SELECT category, domain FROM category_hints")
                for category, domain in cursor.fetchall():
                    hints.setdefault(category, set()).add(domain)
                    
            cursor = conn.execute(
                "SELECT client_ip FROM throttle_state WHERE is_throttled = 1"
            )
            currently_throttled_ips = [row[0] for row in cursor.fetchall()]
            
            # Load exempt devices
            try:
                cursor = conn.execute(
                    "SELECT ip_address FROM network_devices WHERE doomscroll_exempt = 1 OR policy = 'whitelist'"
                )
                exempt_ips = {row[0] for row in cursor.fetchall()}
            except sqlite3.OperationalError:
                exempt_ips = set()
            conn.close()

            with self._cache_lock:
                self.cached_keywords = keywords
                self.cached_hints = hints
                
                # Sync throttled_clients set
                current_set = set(currently_throttled_ips)
                
                # If an IP was released in DB but is still in our set, unthrottle it
                with throttled_clients_lock:
                    for ip in list(throttled_clients):
                        if ip not in current_set:
                            print(f"[VIGILANT] Sync: {ip} was released externally, removing from throttle set.")
                            throttled_clients.discard(ip)
                            # We don't call remove_throttle_cycle because app.py already removed the TC rule.
                            
                            # Cleanup timer if it exists
                            with throttle_timers_lock:
                                _cancel_timer(ip)

                self._last_cache_refresh = time.time()
                self.cached_exempt_devices = exempt_ips
        except Exception as e:
            print(f"[VIGILANT] Error refreshing rule cache: {e}")

    def _cache_refresh_loop(self):
        """Periodically refresh cached rules or reload immediately on API trigger.
        Also runs periodic cleanup of stale velocity tracking state."""
        _cleanup_counter = 0
        while True:
            time.sleep(1.0)
            reload_requested = False
            try:
                if RULE_CACHE_RELOAD_FILE.exists():
                    RULE_CACHE_RELOAD_FILE.unlink(missing_ok=True)
                    reload_requested = True
            except OSError:
                pass

            with self._cache_lock:
                stale = (time.time() - self._last_cache_refresh) >= CACHE_REFRESH_INTERVAL

            if reload_requested or stale:
                self._refresh_rule_cache()

            # Periodically clean up stale velocity tracking state (every 60s)
            _cleanup_counter += 1
            if _cleanup_counter >= 60:
                _cleanup_counter = 0
                _cleanup_stale_velocity_state()  
            
    @staticmethod
    def _extract_client_ip_from_tls(data) -> str | None:
        """Extract real client IP from TLS ClientHelloData, rejecting loopback addresses.

        In transparent proxy mode with iptables REDIRECT, peername in the
        tls_clienthello hook can resolve to 127.0.0.1 (the redirect
        destination) rather than the original client.  This helper tries
        multiple attributes and falls back through them until a non-loopback
        address is found.
        """
        _LOOPBACK = {"127.0.0.1", "::1"}
        candidates = []
        client_conn = getattr(getattr(data, "context", None), "client_conn", None)

        if client_conn is not None:
            # Gather candidate IPs from all known attributes
            for attr in ("peername", "address", "sockname"):
                val = getattr(client_conn, attr, None)
                if val and isinstance(val, (tuple, list)) and len(val) >= 1:
                    candidates.append(str(val[0]))

            ip_attr = getattr(client_conn, "ip", None)
            if ip_attr:
                candidates.append(str(ip_attr))

            # Return first non-loopback candidate
            for ip in candidates:
                if ip and ip not in _LOOPBACK:
                    print(f"[VIGILANT DEBUG] TLS client IP from peername/address: {ip}")
                    return ip
        else:
            print("[VIGILANT DEBUG] TLS client_conn is None (transparent proxy may need DB fallback)")

        # All candidates are loopback or client_conn was unavailable –
        # try resolving real client IP from active network_devices.
        try:
            with db_lock:
                conn = _connect_db()
                cursor = conn.execute(
                    "SELECT ip_address FROM network_devices "
                    "WHERE ip_address NOT LIKE '127.%' AND ip_address NOT LIKE '0.0.0%' AND ip_address != '::1' "
                    "ORDER BY last_seen DESC LIMIT 1"
                )
                row = cursor.fetchone()
                conn.close()
                if row and row[0]:
                    print(f"[VIGILANT DEBUG] TLS client IP from network_devices fallback: {row[0]}")
                    return row[0]
                else:
                    print("[VIGILANT DEBUG] network_devices fallback returned no rows")
        except Exception as exc:
            print(f"[VIGILANT DEBUG] network_devices fallback error: {exc}")

        # Return None if only loopback candidates found - don't log loopback traffic
        if candidates:
            print(f"[VIGILANT] Warning: Only loopback IPs found for TLS client: {candidates} - skipping SNI logging")
        else:
            print("[VIGILANT] Warning: No client IP found for TLS ClientHello - skipping SNI logging "
                  "(ensure devices are registered in network_devices)")
        return None

    def tls_clienthello(self, data: tls.ClientHelloData):
        """Unified TLS ClientHello hook: Dynamic SSL Pinning Bypass + SNI Logging."""
        try:
            # 1. Safely extract SNI name across mitmproxy API versions
            server_name = None
            if hasattr(data, "client_hello") and hasattr(data.client_hello, "sni"):
                server_name = data.client_hello.sni
            if not server_name:
                server_name = getattr(data, "sni", None)
            if not server_name and hasattr(data, "context") and hasattr(data.context, "server_conn"):
                server_name = data.context.server_conn.sni

            if not server_name:
                return

            # 2. Extract Client IP (robust fallback for transparent proxy REDIRECT)
            client_ip = self._extract_client_ip_from_tls(data)
            if not client_ip:
                return

            update_device_activity(client_ip)

            # 3. SNI Filtering & Behavioral Checks (do this BEFORE bypassing pinned apps)
            config = load_proxy_config()
            # load_proxy_config returns sni_filtering_enabled as a bool already;
            # do NOT call .lower() on it (was causing an AttributeError that silently
            # skipped all SNI logging).
            sni_filtering_enabled = bool(config.get('sni_filtering_enabled', True))

            print(f"[VIGILANT DEBUG] SNI filtering enabled: {sni_filtering_enabled}")

            if sni_filtering_enabled:
                print(f"[VIGILANT DEBUG] About to log SNI request: {client_ip} @ {server_name}")
                self.log_to_dashboard(client_ip, server_name)

                # Calculate SNI velocity (RPS)
                velocity_rps = compute_sni_velocity(client_ip, server_name)

                # Log SNI request with velocity
                log_sni_request(client_ip, server_name, velocity_rps)

                flagged, rpm_now, rpm_base = should_throttle(client_ip, server_name)
                if flagged and not is_device_exempt(client_ip):
                    level = escalate_circuit_breaker(client_ip, server_name, rpm_now, rpm_base)
                    if level >= CB_LEVEL_PAUSE:
                        _mark_client_throttled(client_ip)
                    apply_circuit_breaker_action(client_ip, server_name, level, rpm_now, rpm_base)
                    if level >= CB_LEVEL_PAUSE:
                        print(f"[VIGILANT] TLS CB Level {level} ({CB_LEVEL_NAMES[level]}) {client_ip} @ {server_name} "
                              f"RPM={rpm_now:.1f} baseline={rpm_base:.1f} RPS={velocity_rps:.2f}")

            # 4. Certificate Pinning Dynamic Bypass (AFTER logging)
            if server_name in self.pinned_hosts:
                print(f"[VIGILANT DEBUG] SSL pinned, bypassing: {server_name}")
                data.ignore_connection = True
                print(f"[VIGILANT] Dynamic L4 Passthrough activated for pinned SNI: {server_name}")
                return

            # 5. Bypass core internal Apple traffic to prevent OS-level freezes.
            # Uses suffix matching (not substring) to avoid a malicious site like
            # "evilapple.com" or "scam-apple.com" inadvertently bypassing MITM.
            _APPLE_DOMAINS = {"apple.com", "icloud.com", "mzstatic.com"}
            clean_sni = server_name.lower().removeprefix("www.")
            if any(clean_sni == d or clean_sni.endswith("." + d) for d in _APPLE_DOMAINS):
                data.ignore_connection = True
                return

            # 6. Log social domain requests to traffic log (non-pinned only)
            social_domains = load_social_domains()
            clean_sni = server_name.removeprefix("www.")
            base = ".".join(clean_sni.split(".")[-2:])
            if any(base in d for d in social_domains):
                log_request(client_ip, server_name, "(TLS_SNI)", "TLS", "Distracting", False, [], None)

        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] TLS ClientHello data structure parsing issue: {e}")
        except Exception as e:
            print(f"[VIGILANT] TLS ClientHello error: {e}")

    def tls_failed_client(self, data: tls.TlsData):
        """Automatically catch TLS pinning rejections and register for dynamic passthrough."""
        server_name = getattr(data.conn, "sni", None)

        if server_name and server_name not in self.pinned_hosts:
            print(
                f"[VIGILANT] Detected TLS Certificate Pinning on {server_name}. Registering for L4 bypass."
            )
            self.pinned_hosts.add(server_name)

            # Instruct mitmproxy to dynamically ignore future connections to this SNI
            current_ignores = list(ctx.options.ignore_hosts)
            pattern = f"^{re.escape(server_name)}:443$"
            if pattern not in current_ignores:
                current_ignores.append(pattern)
                ctx.options.ignore_hosts = current_ignores
                print(f"[VIGILANT] Added {server_name} to mitmproxy ignore_hosts rule.")


    def log_to_dashboard(self, client_ip: str, sni: str):
        """Log SNI domain to dashboard database for transparent passthrough tracking using TF-IDF classification"""
        try:
            # Get domain hint for categorization
            hint_category, _ = get_domain_hint(sni)
            
            # Use domain hint category if it's loggable
            if hint_category and hint_category.lower() in _LOGGABLE_CATEGORIES:
                category = hint_category
            else:
                # Use TF-IDF classifier to categorize SNI domain name
                # Convert domain to text for classification (e.g., "instagram.com" -> "instagram social media")
                # Use lower threshold (0.05-0.08) for domain names/short URLs
                config = load_proxy_config()
                domain_threshold = float(config.get('tfidf_url_threshold', 0.05))
                domain_text = sni.replace(".", " ").replace("-", " ")
                tfidf_category, _tfidf_scores = tfidf_classifier.classify(domain_text, threshold=domain_threshold)
                
                if tfidf_category and tfidf_category.lower() in _LOGGABLE_CATEGORIES:
                    category = tfidf_category
                else:
                    category = "Productive"  # Default category for SNI logs to ensure database logging
            
            # Log the SNI domain request
            log_request(client_ip, sni, "(TLS_SNI)", "TLS", category, False, [], None)
            print(f"[VIGILANT] SNI logged to dashboard: {client_ip} -> {sni} [{category}]")
        except Exception as e:
            print(f"[VIGILANT] Failed to log SNI to dashboard: {e}")

    def request(self, flow: http.HTTPFlow):
        try:
            client_ip = flow.client_conn.peername[0]
            update_device_activity(client_ip)
        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] Request: Failed to extract client IP from peername: {e}")
            return
        host      = flow.request.pretty_host

        # Whitelist bypass: asset subdomains (kept ahead of everything else - these
        # are infrastructure/CDN domains, not user-navigable content).
        if is_whitelisted(host) or is_custom_bypass(host):
            log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Educational", False, [], None)
            print(f"[VIGILANT] WHITELIST BYPASS (request): {host} -> {client_ip}")
            return

        try:
            keywords = get_blacklisted_keywords()
            if keywords:
                decoded_url = urllib.parse.unquote(flow.request.pretty_url)
                req_body = ""

                if flow.request.content:
                    req_body = urllib.parse.unquote(flow.request.get_text(strict=False))

                combined_search_text = f"{decoded_url} {req_body}"

                matched = scan_text_for_keywords(combined_search_text, keywords)
                if matched:
                    print(f"[VIGILANT] INSTAGRAM KEYWORD BLOCKED: {matched} from {client_ip}")
                    log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [], "KEYWORD_MATCH")
                    flow.response = http.Response.make(
                        403,
                        render_block_page(host, "Harmful"),
                        {"Content-Type": "text/html"}
                    )
                    return
        except sqlite3.Error as e:
            print(f"[VIGILANT] Database error during keyword blacklist check: {e}")
        except Exception as e:
            print(f"[VIGILANT] Error during keyword blacklist check: {e}")

        # TLS Passthrough: Check if host belongs to pinned SSL certificate domains.
        # This now only skips CATEGORY/NLP filtering - the explicit blacklist scan
        # above has already run regardless of pin status.
        config = load_proxy_config()
        pinned_domains = config['pinned_domains']

        clean_host = host.removeprefix("www.")
        base_domain = ".".join(clean_host.split(".")[-2:])
        is_pinned = any(base_domain in d or clean_host == d or clean_host.endswith("." + d) for d in pinned_domains)

        if is_pinned:
            print(f"[VIGILANT] TLS PASSTHROUGH: {host} from {client_ip} (pinned domain, blacklist already checked)")
            return

        # STEP 1: Exact Domain Evaluation - Check category hints for strict override
        category_hints = load_category_hints()
        domain_category = None

        for category, domains in category_hints.items():
            if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                domain_category = category
                print(f"[VIGILANT] DOMAIN OVERRIDE: {host} -> {category} (category hint match)")
                break

        # Optional secondary check: scan request BODY (POST payloads) with the more
        # lenient body-context rules, since body text is closer to passive content
        # than a deliberately-typed URL.
        if domain_category is None:
            try:
                keywords = get_blacklisted_keywords()
                if keywords:
                    try:
                        request_body = flow.request.get_text(strict=False) if flow.request.content else ""
                    except Exception:
                        request_body = ""
                    # Use efficient token intersection for keyword detection (unified approach for all domains)
                    matched = scan_text_for_keywords(request_body, keywords)
                    if matched:
                        print(f"[VIGILANT] REQUEST KEYWORD BLOCKED: {matched} in request body from {host}")
                        log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [], "KEYWORD_MATCH")
                        flow.response = http.Response.make(
                            403,
                            render_block_page(host, "Harmful"),
                            {"Content-Type": "text/html"}
                        )
                        return
            except sqlite3.Error as e:
                print(f"[VIGILANT] Request body keyword blacklist check failed: {e}")

        flagged, rpm_now, rpm_base = should_throttle(client_ip, host)
        if flagged and not is_device_exempt(client_ip):
            level = escalate_circuit_breaker(client_ip, host, rpm_now, rpm_base)
            if level >= CB_LEVEL_PAUSE:
                _mark_client_throttled(client_ip)
            apply_circuit_breaker_action(client_ip, host, level, rpm_now, rpm_base)
            if level >= CB_LEVEL_PAUSE:
                print(f"[VIGILANT] HTTP CB Level {level} ({CB_LEVEL_NAMES[level]}) {client_ip} @ {host} "
                      f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

    def response(self, flow: http.HTTPFlow):
        try:
            client_ip = flow.client_conn.peername[0]
        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] Response: Failed to extract client IP from peername: {e}")
            return
        host         = flow.request.pretty_host
        path         = flow.request.path[:120]
        method       = flow.request.method
        content_type = flow.response.headers.get("content-type", "")

        if is_whitelisted(host) or is_custom_bypass(host):
            log_request(client_ip, host, path, method, "Educational", False, [], None)
            print(f"[VIGILANT] WHITELIST BYPASS (response): {host} -> {client_ip}")
            return

        config = load_proxy_config()
        pinned_domains = config['pinned_domains']

        clean_host = host.removeprefix("www.")
        base_domain = ".".join(clean_host.split(".")[-2:])
        is_pinned = any(base_domain in d or clean_host == d or clean_host.endswith("." + d) for d in pinned_domains)

        if is_pinned:
            # Response bodies for pinned (cert-pinned social) apps are still skipped -
            # the request-side blacklist scan is the enforcement point for these, since
            # response bodies for these apps are frequently binary/protobuf rather than
            # readable text anyway.
            return

        category_hints = load_category_hints()
        domain_category = None

        for category, domains in category_hints.items():
            if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                domain_category = category
                break

        TEXT_CONTENT_TYPES = {"text/html", "application/json", "text/plain", "text/javascript", "application/javascript", "text/css", "application/xml", "text/xml"}

        if not any(ct in content_type for ct in TEXT_CONTENT_TYPES):
            final_category = domain_category if domain_category else "Non-HTML"
            log_request(client_ip, host, path, method, final_category, False, [], None)
            return

        # ── Sampled scanning for oversized payloads (see get_scan_text) ──
        try:
            body, was_sampled = get_scan_text(flow.response)
            if was_sampled:
                print(f"[VIGILANT] Large payload for {host} ({len(flow.response.content)} bytes) - "
                      f"scanning sampled prefix/suffix instead of skipping analysis entirely")

            if "text/html" in content_type:
                clean = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', body, flags=re.IGNORECASE | re.DOTALL)
                clean = re.sub(r"<[^>]+>", " ", clean)
                clean = re.sub(r"\s+", " ", clean).strip()
            elif "application/json" in content_type:
                clean = re.sub(r'[{}\[\]",:]', ' ', body)
                clean = re.sub(r"\s+", " ", clean).strip()
            else:
                clean = re.sub(r"\s+", " ", body).strip()
        except ValueError:
            print(f"[VIGILANT] Failed to decode text payload for {host}")
            clean = ""
        except Exception as e:
            print(f"[VIGILANT] Error processing response payload for {host}: {e}")
            clean = ""

        if domain_category:
            category = domain_category
            entities = []
        else:
            category, entities = categorize_content(clean, host)

        flagged = category == "Harmful"

        # Additional keyword blacklist check on response content, using the lenient
        # body-context rules (repeat occurrences or stuffed-bypass required - see
        # FIX #2), only when the domain isn't already explicitly categorized.
        if domain_category is None and any(ct in content_type for ct in TEXT_CONTENT_TYPES):
            try:
                keywords = get_blacklisted_keywords()
                if keywords:
                    if clean:
                        # Use efficient token intersection for keyword detection
                        matched = scan_text_for_keywords(clean, keywords)
                    else:
                        matched = None
                    if matched:
                        print(f"[VIGILANT] RESPONSE KEYWORD BLOCKED: {matched} in {content_type} response from {host}")
                        log_request(client_ip, host, path, method, "Harmful", True, [], "KEYWORD_MATCH")
                        flow.response = http.Response.make(
                            403,
                            render_block_page(host, "Harmful"),
                            {"Content-Type": "text/html"}
                        )
                        return
            except sqlite3.Error as e:
                print(f"[VIGILANT] Response keyword blacklist check failed: {e}")

        block_reason = "CATEGORY_BLOCKED" if flagged else None
        log_request(client_ip, host, path, method, category, flagged, entities[:10], block_reason)
        print(f"[VIGILANT] {method} {host}{path[:40]} "
              f"-> [{category}] entities={len(entities)} client={client_ip}")

        if flagged:
            flow.response = http.Response.make(
                403,
                render_block_page(host, category),
                {"Content-Type": "text/html"}
            )

addons = [VIGILANTAddon()]