import os
import re
import time
import sqlite3
import threading
import subprocess
import urllib.parse
import ipaddress
import difflib
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

try:
    import profiler
except ImportError:
    profiler = None

BASE_DIR = Path(__file__).resolve().parent.parent
PRODUCTION_DB_PATH = Path("/home/vigilant-admin/vigilant_gateway/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

# Resolve DB_PATH consistently with app.py: prefer production if the parent
# directory exists and is writable (NOT checking whether the file itself
# exists, since it may not have been created yet on first run).
if PRODUCTION_DB_PATH.parent.exists() and os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
    DB_PATH = str(PRODUCTION_DB_PATH)
else:
    DB_PATH = str(LOCAL_DB_PATH)

VELOCITY_WINDOW    = 60

# Default values (will be overridden by database config)
DEFAULT_VELOCITY_THRESHOLD = 1.5
DEFAULT_THROTTLE_RATE = "32kbit"
DEFAULT_PINNED_DOMAINS = "facebook.com,twitter.com,x.com,tiktok.com,instagram.com,reddit.com,youtube.com"
MIN_REQUESTS_BASELINE = 10
MIN_SOCIAL_REQUESTS_BASELINE = 30  # Social requests needed before flagging (immune to app-load bursts)

# --- Doomscroll Detection: Session-Time Model ---------------------------------
# Real doomscrolling isn't rapid-fire requests — it's watching a reel for
# 20-30s, swiping, watching another. Gaps are long, RPM is low. We track
# cumulative engagement time instead of request velocity.

# Thresholds: minutes of sustained social media engagement
ENGAGEMENT_L1_MINUTES = 3    # 128kbit — mild nudge
ENGAGEMENT_L2_MINUTES = 6    # 32kbit  — noticeable
ENGAGEMENT_L3_MINUTES = 12   # 4kbit   — hard stop

# How often we check engagement (seconds)
ENGAGEMENT_CHECK_INTERVAL = 30.0

# How long without ANY social request before engagement resets
ENGAGEMENT_RESET_IDLE = 120  # 2 minutes of no activity = session over

# Minimum social requests before engagement tracking starts
ENGAGEMENT_MIN_REQUESTS = 10

CB_LEVEL_NONE = 0
CB_LEVEL_PAUSE = 1
CB_LEVEL_FRICTION = 2
CB_LEVEL_CIRCUIT_BREAK = 3

CB_LEVEL_NAMES = {1: "Pause", 2: "Friction", 3: "Circuit Break"}

# ── Engagement state ──
_engagement_start = defaultdict(float)     # client_ip → when social session began
_engagement_minutes = defaultdict(float)    # client_ip → accumulated minutes
_engagement_last_request = defaultdict(float)  # client_ip → last social request time
_engagement_current_level = defaultdict(int)   # client_ip → active level 0-3
_engagement_lock = threading.Lock()
_previous_rate = {}
_engagement_low_activity_since = defaultdict(float)  # client_ip → when RPM first dropped below baseline
_engaged_log_times = {}  # client_ip → last "Engaged:" log timestamp (rate-limited)

# Level → tc rate
ENGAGEMENT_LEVEL_RATE = {
    0: None,
    1: "128kbit",
    2: "32kbit",
    3: "4kbit",
}

# Maximum payload body size before falling back to sampled scanning.
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024
SAMPLE_PREFIX_BYTES = 512 * 1024
SAMPLE_SUFFIX_BYTES = 256 * 1024


# ── Global Asset Whitelist ──────────────────────────────────────────
# Default seed values; the authoritative list lives in the database
# (global_whitelist table) and is refreshed into an in-memory cache
# every CACHE_REFRESH_INTERVAL seconds or on dashboard signal.
DEFAULT_WHITELIST = {
    "github.com", "githubassets.com", "githubusercontent.com", "git-scm.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windows.net", "live.com", "office.com", "apple.com",
    "mzstatic.com", "icloud.com", "aws.amazon.com", "cloudfront.net", "cdnjs.cloudflare.com"
}

_cached_whitelist = DEFAULT_WHITELIST.copy()
_whitelist_lock = threading.Lock()


def _refresh_whitelist_cache():
    """Reload the global whitelist from the database into the in-memory cache."""
    conn = None
    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT domain FROM global_whitelist")
        domains = {row[0] for row in cursor.fetchall()}
        with _whitelist_lock:
            _cached_whitelist.clear()
            if domains:
                _cached_whitelist.update(domains)
            else:
                _cached_whitelist.update(DEFAULT_WHITELIST)
    except Exception:
        pass
    finally:
        if conn:
            conn.close()


def is_whitelisted(host: str) -> bool:
    """Check if a host (or its parent domain) is in the global whitelist.
    Uses an in-memory cache refreshed from the database."""
    clean = host.removeprefix("www.")
    with _whitelist_lock:
        for w in _cached_whitelist:
            if clean == w or clean.endswith('.' + w):
                return True
    return False


# In-memory cache for custom bypass domains, refreshed periodically
_cached_bypass_domains = set()
_cached_bypass_lock = threading.Lock()


def _refresh_bypass_cache():
    """Load the custom bypass domains into the module-level cache."""
    conn = None
    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'custom_bypass_domains'")
        row = cursor.fetchone()
        with _cached_bypass_lock:
            _cached_bypass_domains.clear()
            if row and row[0]:
                for d in row[0].split(','):
                    d = d.strip().lower()
                    if d:
                        _cached_bypass_domains.add(d)
        return True
    except Exception:
        return False
    finally:
        if conn:
            conn.close()


def is_custom_bypass(host: str) -> bool:
    """Check if a host matches a user-configured bypass domain using the
    in-memory cache (no database hit on every request)."""
    if not host:
        return False
    with _cached_bypass_lock:
        if not _cached_bypass_domains:
            return False
        clean = host.removeprefix("www.").lower()
        for domain in _cached_bypass_domains:
            if clean == domain or clean.endswith('.' + domain):
                print(f"[VIGILANT] Custom bypass match: {host} via {domain}")
                return True
    return False


def is_pinned_host(host: str) -> bool:
    """Check if a host matches the configured SSL-pinned domain list."""
    if not host:
        return False
    config = load_proxy_config()
    pinned_domains = config['pinned_domains']
    clean_host = host.removeprefix("www.").lower()
    base_domain = ".".join(clean_host.split(".")[-2:])
    return any(
        base_domain in d or clean_host == d or clean_host.endswith("." + d)
        for d in pinned_domains
    )


# Two-label public suffixes that require 3 labels to form a registrable domain
# (e.g. "api.seabank.com.ph" -> "seabank.com.ph", not "com.ph").
_MULTI_LABEL_TLDS = {
    "com.ph", "net.ph", "org.ph", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "com.br", "com.mx", "com.sg", "com.hk", "com.tw", "co.in", "net.in", "org.in",
}


def _base_domain(host: str) -> str:
    """Extract the registrable domain from a hostname (drops subdomains).
    E.g. tnc0-normal-alisg.tiktokv.com -> tiktokv.com;
         api.seabank.com.ph -> seabank.com.ph."""
    clean = host.removeprefix("www.").lower().strip().rstrip(".")
    labels = clean.split(".")
    if len(labels) <= 2:
        return clean
    if ".".join(labels[-2:]) in _MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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

# IMPORTANT: These paths are computed lazily via helper functions because
# DB_PATH is resolved at import time and may differ from what Flask (app.py)
# resolves at runtime.  If the production DB file does not exist when this
# module is first imported, DB_PATH falls back to the local path, while
# Flask may resolve DB_PATH to the production path.  Computing the signal
# files at access time ensures both processes target the same directory.
def _rule_cache_reload_path() -> Path:
    return Path(DB_PATH).parent / ".rule_cache_reload"

def _throttle_release_queue_path() -> Path:
    return Path(DB_PATH).parent / ".throttle_release_queue"

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

    c.execute("""
        CREATE TABLE IF NOT EXISTS pending_bypass_review (
            domain TEXT PRIMARY KEY,
            client_ip TEXT,
            error_msg TEXT,
            first_seen REAL,
            last_seen REAL,
            occurrence_count INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS global_whitelist (
            domain TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed default whitelist domains if table is empty
    if c.execute("SELECT COUNT(*) FROM global_whitelist").fetchone()[0] == 0:
        for d in sorted(DEFAULT_WHITELIST):
            try:
                c.execute("INSERT OR IGNORE INTO global_whitelist (domain) VALUES (?)", (d,))
            except sqlite3.Error:
                pass
    c.execute("""
        CREATE TABLE IF NOT EXISTS domain_behavior_policies (
            domain TEXT PRIMARY KEY,
            policy_type TEXT CHECK(policy_type IN ('auto', 'enforce_doomscroll', 'exempt_media')) NOT NULL DEFAULT 'auto',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed default behavioral policies for obvious long-form vs short-form platforms.
    DEFAULT_BEHAVIOR_POLICIES = {
        'exempt_media': ['youtube.com', 'coursera.org', 'netflix.com', 'vimeo.com', 'spotify.com', 'ted.com'],
        'enforce_doomscroll': ['tiktok.com', 'instagram.com'],
    }
    for policy_type, domains in DEFAULT_BEHAVIOR_POLICIES.items():
        for d in domains:
            try:
                c.execute(
                    "INSERT OR IGNORE INTO domain_behavior_policies (domain, policy_type) VALUES (?, ?)",
                    (d, policy_type)
                )
            except sqlite3.Error:
                pass
    c.execute("""
        CREATE TABLE IF NOT EXISTS pinning_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            base_domain TEXT NOT NULL,
            exact_domain TEXT NOT NULL,
            first_seen REAL,
            last_seen REAL,
            count INTEGER DEFAULT 1,
            UNIQUE(client_ip, exact_domain)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_pinning_base ON pinning_observations(base_domain)")
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


def get_domain_behavior_policy(domain: str) -> str:
    """Return the behavior policy for a domain ('auto', 'enforce_doomscroll',
    or 'exempt_media'). Defaults to 'auto' when no explicit policy exists."""
    clean = domain.removeprefix("www.").lower()
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            cursor = conn.execute(
                "SELECT policy_type FROM domain_behavior_policies WHERE domain = ?", (clean,)
            )
            row = cursor.fetchone()
            return str(row[0]) if row else "auto"
    except Exception as e:
        print(f"[VIGILANT] Error loading behavior policy for {domain}: {e}")
        return "auto"
    finally:
        if conn:
            conn.close()


def set_domain_behavior_policy(domain: str, policy_type: str) -> None:
    """Insert or update the behavior policy for a domain."""
    clean = domain.removeprefix("www.").lower()
    if policy_type not in ("auto", "enforce_doomscroll", "exempt_media"):
        raise ValueError(f"Invalid policy_type: {policy_type}")
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                conn.execute(
                    "INSERT INTO domain_behavior_policies (domain, policy_type, updated_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(domain) DO UPDATE SET policy_type = excluded.policy_type, "
                    "updated_at = excluded.updated_at",
                    (clean, policy_type, time.time())
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        print(f"[VIGILANT] Error setting behavior policy for {domain}: {e}")


def get_all_domain_behavior_policies() -> dict:
    """Return a mapping of domain -> policy_type for all stored policies."""
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            cursor = conn.execute("SELECT domain, policy_type FROM domain_behavior_policies ORDER BY domain")
            return {str(row[0]): str(row[1]) for row in cursor.fetchall()}
    except Exception as e:
        print(f"[VIGILANT] Error loading domain behavior policies: {e}")
        return {}
    finally:
        if conn:
            conn.close()


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

        # Engagement time thresholds (dashboard-tunable)
        def _read_int(key, default):
            cursor.execute("SELECT value FROM config_settings WHERE key = ?", (key,))
            r = cursor.fetchone()
            return int(r[0]) if r else default
        eng_l1 = _read_int('engagement_l1_minutes', ENGAGEMENT_L1_MINUTES)
        eng_l2 = _read_int('engagement_l2_minutes', ENGAGEMENT_L2_MINUTES)
        eng_l3 = _read_int('engagement_l3_minutes', ENGAGEMENT_L3_MINUTES)
        eng_reset = _read_int('engagement_reset_idle', ENGAGEMENT_RESET_IDLE)

        # Engagement throttle rates (dashboard-tunable)
        def _read_str(key, default):
            cursor.execute("SELECT value FROM config_settings WHERE key = ?", (key,))
            r = cursor.fetchone()
            return str(r[0]) if r else default
        eng_l1_rate = _read_str('engagement_l1_rate', ENGAGEMENT_LEVEL_RATE.get(1, '128kbit'))
        eng_l2_rate = _read_str('engagement_l2_rate', ENGAGEMENT_LEVEL_RATE.get(2, '32kbit'))
        eng_l3_rate = _read_str('engagement_l3_rate', ENGAGEMENT_LEVEL_RATE.get(3, '4kbit'))

        # Engagement check interval and min requests (dashboard-tunable)
        eng_check_interval = _read_int('engagement_check_interval', 30)
        eng_min_requests = _read_int('engagement_min_requests', ENGAGEMENT_MIN_REQUESTS)

        conn.close()

        return {
            'network_velocity_threshold': network_velocity_threshold,
            'physical_scroll_threshold': physical_scroll_threshold,
            'nlp_enabled': nlp_enabled,
            'sni_filtering_enabled': sni_filtering_enabled,
            'throttle_rate': throttle_rate,
            'pinned_domains': pinned_domains,
            'engagement_l1_minutes': eng_l1,
            'engagement_l2_minutes': eng_l2,
            'engagement_l3_minutes': eng_l3,
            'engagement_reset_idle': eng_reset,
            'engagement_l1_rate': eng_l1_rate,
            'engagement_l2_rate': eng_l2_rate,
            'engagement_l3_rate': eng_l3_rate,
            'engagement_check_interval': eng_check_interval,
            'engagement_min_requests': eng_min_requests,
        }
    except Exception as e:
        print(f"[VIGILANT] Error loading proxy config from database: {e}, using defaults")
        return {
            'network_velocity_threshold': DEFAULT_VELOCITY_THRESHOLD,
            'physical_scroll_threshold': 30,
            'nlp_enabled': True,
            'sni_filtering_enabled': True,
            'throttle_rate': DEFAULT_THROTTLE_RATE,
            'pinned_domains': set(DEFAULT_PINNED_DOMAINS.split(',')),
            'engagement_l1_minutes': ENGAGEMENT_L1_MINUTES,
            'engagement_l2_minutes': ENGAGEMENT_L2_MINUTES,
            'engagement_l3_minutes': ENGAGEMENT_L3_MINUTES,
            'engagement_reset_idle': ENGAGEMENT_RESET_IDLE,
            'engagement_l1_rate': ENGAGEMENT_LEVEL_RATE.get(1, '128kbit'),
            'engagement_l2_rate': ENGAGEMENT_LEVEL_RATE.get(2, '32kbit'),
            'engagement_l3_rate': ENGAGEMENT_LEVEL_RATE.get(3, '4kbit'),
            'engagement_check_interval': 30,
            'engagement_min_requests': ENGAGEMENT_MIN_REQUESTS,
        }


def load_category_hints():
    """Load category hints from database or in-memory cache when available."""
    if _active_addon is not None:
        with _active_addon._cache_lock:
            if _active_addon._last_cache_refresh > 0:
                return {k: set(v) for k, v in _active_addon.cached_hints.items()}

    conn = None
    try:
        conn = _connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            return {}

        cursor.execute("SELECT category, domain FROM category_hints")
        rows = cursor.fetchall()

        category_hints = {}
        for category, domain in rows:
            if category not in category_hints:
                category_hints[category] = set()
            category_hints[category].add(domain)

        return category_hints
    except Exception as e:
        print(f"[VIGILANT] Error loading category hints from database: {e}, using empty set")
        return {}
    finally:
        if conn:
            conn.close()


def get_blacklisted_keywords():
    """Return blacklisted keywords from in-memory cache or database."""
    if _active_addon is not None:
        with _active_addon._cache_lock:
            if _active_addon._last_cache_refresh > 0:
                return list(_active_addon.cached_keywords)

    conn = None
    try:
        conn = _connect_db()
        cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
        keywords = [row[0] for row in cursor.fetchall()]
        return keywords
    except Exception as e:
        print(f"[VIGILANT] Error loading keyword blacklist from database: {e}")
        return []
    finally:
        if conn:
            conn.close()


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

    conn = None
    try:
        conn = _connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='category_hints'")
        if not cursor.fetchone():
            return DEFAULT_SOCIAL_DOMAINS

        cursor.execute("SELECT domain FROM category_hints WHERE category = 'Distracting'")
        rows = cursor.fetchall()

        social_domains = set()
        for (domain,) in rows:
            social_domains.add(domain)
            if not domain.startswith('www.'):
                social_domains.add(f'www.{domain}')

        if not social_domains:
            return DEFAULT_SOCIAL_DOMAINS

        return social_domains
    except Exception as e:
        print(f"[VIGILANT] Error loading social domains from database: {e}, using defaults")
        return DEFAULT_SOCIAL_DOMAINS
    finally:
        if conn:
            conn.close()

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
            try:
                conn.execute(
                    "INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged, entities, block_reason) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (time.time(), client_ip, host, path, method,
                     category, int(flagged), str(entities), block_reason)
                )
                conn.commit()
            finally:
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
            try:
                now = time.time()
                conn.execute(
                    "INSERT INTO network_devices (ip_address, last_seen, first_seen) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(ip_address) DO UPDATE SET last_seen = excluded.last_seen",
                    (client_ip, now, now)
                )
                conn.commit()
            finally:
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
            try:
                conn.execute(
                    "INSERT INTO throttle_events (timestamp, client_ip, host, rpm_current, rpm_baseline, action, reason) VALUES (?,?,?,?,?,?,?)",
                    (time.time(), client_ip, host, rpm_now, rpm_base, action, reason)
                )
                conn.commit()
            finally:
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
            try:
                conn.execute(
                    "INSERT INTO sni_requests (timestamp, client_ip, domain, request_count, velocity_rps) "
                    "VALUES (?,?,?,?,?)",
                    (time.time(), client_ip, domain, 1, velocity_rps)
                )
                conn.commit()
            finally:
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

# Social-only tracking — immune to DNS/iCloud/Google noise.
# Only counts requests to social media domains (fb, ig, tiktok, etc.).
# This prevents the initial app-load burst (50+ requests in 2s when
# opening Instagram) from looking like an RPM spike against a low
# baseline. By the time 30 social requests accumulate, the burst
# has passed and normal scrolling patterns emerge.
social_request_history = defaultdict(lambda: deque())
social_session_totals  = defaultdict(int)
social_session_start   = defaultdict(float)
# client_ip → when social RPM first dropped below the engaged threshold (2 RPM),
# used to reset stale sessions kept alive by low-rate background pings.
_social_low_activity_since = defaultdict(float)

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


def _engagement_tracking_loop():
    """Background thread: every 30s, check which devices are engaged in
    social media and update their cumulative engagement minutes.
    If engagement exceeds thresholds, apply/escalate throttle.
    If idle too long, reset engagement.
    Thresholds are read from DB config so the dashboard can tune them."""
    while True:
        try:
            # Read all behavioral params from DB (allows dashboard tuning)
            config = load_proxy_config()
            l1_min = int(config.get('engagement_l1_minutes', ENGAGEMENT_L1_MINUTES))
            l2_min = int(config.get('engagement_l2_minutes', ENGAGEMENT_L2_MINUTES))
            l3_min = int(config.get('engagement_l3_minutes', ENGAGEMENT_L3_MINUTES))
            reset_idle = int(config.get('engagement_reset_idle', ENGAGEMENT_RESET_IDLE))
            l1_rate = config.get('engagement_l1_rate', ENGAGEMENT_LEVEL_RATE.get(1, '128kbit'))
            l2_rate = config.get('engagement_l2_rate', ENGAGEMENT_LEVEL_RATE.get(2, '32kbit'))
            l3_rate = config.get('engagement_l3_rate', ENGAGEMENT_LEVEL_RATE.get(3, '4kbit'))
            check_interval = int(config.get('engagement_check_interval', 30))
            
            now = time.time()

            # ── Low-activity session reset (never-flagged devices) ──
            # Background app pings (TikTok's icube-api.bytedance.net ~1 req/50s)
            # keep social_session_start alive without ever reaching the engaged
            # threshold (2 RPM). Complete-idle reset (below) never fires because
            # the pings are too frequent. Here we reset the session when social
            # activity stays BELOW 2 RPM for reset_idle seconds — so a stale
            # session start cannot inflate engagement minutes and cause an instant
            # L3 throttle when the user finally picks the device up.
            # (Benign unlocked .get() on _engagement_start — GIL-atomic in CPython;
            # taking _engagement_lock here would invert lock order and risk deadlock.)
            with velocity_lock:
                for ip in list(social_session_start.keys()):
                    if _engagement_start.get(ip, 0) != 0:
                        continue  # flagged devices are handled by the checks below
                    sdq = social_request_history.get(ip)
                    recent = len([t for t in sdq if now - t <= VELOCITY_WINDOW]) if sdq else 0
                    if recent < 2:
                        low_start = _social_low_activity_since.get(ip, 0)
                        if low_start == 0:
                            _social_low_activity_since[ip] = now
                        elif now - low_start >= reset_idle:
                            social_session_start.pop(ip, None)
                            social_session_totals.pop(ip, None)
                            social_request_history.pop(ip, None)
                            _social_low_activity_since.pop(ip, None)
                    else:
                        _social_low_activity_since.pop(ip, None)

            with _engagement_lock:
                for ip in list(_engagement_start.keys()):
                    started = _engagement_start[ip]
                    if started == 0:
                        continue
                    last_req = _engagement_last_request.get(ip, 0)
                    idle = now - last_req

                    # ── Check 1: Zero requests for reset_idle ──
                    if idle >= reset_idle:
                        old_level = _engagement_current_level.get(ip, 0)
                        if old_level > 0:
                            print(f"[VIGILANT] ENGAGEMENT RESET (idle): {ip} idle {idle:.0f}s, releasing")
                            log_throttle(ip, "engagement", 0, 0, "ENGAGEMENT_RESET_IDLE", f"idle {idle:.0f}s, releasing")
                            _previous_rate.pop(ip, None)
                            remove_throttle_cycle(ip)
                        _engagement_start[ip] = 0
                        _engagement_minutes[ip] = 0
                        _engagement_current_level[ip] = 0
                        _engagement_low_activity_since.pop(ip, None)
                        # Reset social session counters so engagement_min_requests
                        # threshold applies to each new scrolling session
                        with velocity_lock:
                            social_session_totals.pop(ip, None)
                            social_session_start.pop(ip, None)
                        continue

                    # ── Check 2: Low activity for reset_idle ──
                    # Background pings (1 RPM) keep _engagement_last_request fresh,
                    # so the idle check above never fires. We also check the social
                    # request deque (60s window): if the user has fewer than 3
                    # requests/min for the entire reset_idle period, they've stopped
                    # doomscrolling and we should release the throttle.
                    sdq = social_request_history.get(ip)
                    recent_req_count = len(sdq) if sdq else 0
                    if recent_req_count < 3:
                        low_start = _engagement_low_activity_since.get(ip, 0)
                        if low_start == 0:
                            _engagement_low_activity_since[ip] = now
                        elif now - low_start >= reset_idle:
                            old_level = _engagement_current_level.get(ip, 0)
                            if old_level > 0:
                                print(f"[VIGILANT] ENGAGEMENT RESET (low activity): {ip} {recent_req_count} reqs/min for {(now - low_start):.0f}s, releasing")
                                log_throttle(ip, "engagement", 0, 0, "ENGAGEMENT_RESET_LOW", f"{recent_req_count} reqs/min for {(now - low_start):.0f}s")
                                _previous_rate.pop(ip, None)
                                remove_throttle_cycle(ip)
                            _engagement_start[ip] = 0
                            _engagement_minutes[ip] = 0
                            _engagement_current_level[ip] = 0
                            _engagement_low_activity_since.pop(ip, None)
                            # Reset social session counters so engagement_min_requests
                            # threshold applies to each new scrolling session
                            with velocity_lock:
                                social_session_totals.pop(ip, None)
                                social_session_start.pop(ip, None)
                            continue
                    else:
                        # Activity picked up → clear low-activity tracker
                        _engagement_low_activity_since.pop(ip, None)
                    
                    elapsed = (now - started) / 60.0
                    if elapsed > _engagement_minutes.get(ip, 0):
                        _engagement_minutes[ip] = elapsed
                        if elapsed >= l3_min:
                            new_level = CB_LEVEL_CIRCUIT_BREAK
                        elif elapsed >= l2_min:
                            new_level = CB_LEVEL_FRICTION
                        elif elapsed >= l1_min:
                            new_level = CB_LEVEL_PAUSE
                        else:
                            new_level = CB_LEVEL_NONE
                        old_level = _engagement_current_level.get(ip, 0)
                        if new_level != old_level:
                            _engagement_current_level[ip] = new_level
                            if new_level > 0:
                                # Build dynamic rate lookup from config
                                _engagement_rates = {0: None, 1: l1_rate, 2: l2_rate, 3: l3_rate}
                                rate = _engagement_rates.get(new_level)
                                if rate and _previous_rate.get(ip) != rate:
                                    apply_throttle(ip, rate=rate)
                                    _previous_rate[ip] = rate
                                    save_throttle_state(ip, is_throttled=True, recovery_at=0)
                                    _mark_client_throttled(ip)
                                    log_throttle(ip, "engagement", elapsed, 0, f"ENGAGEMENT_L{new_level}", f"{elapsed:.1f}min → L{new_level} @ {rate}")
                                    print(f"[VIGILANT] ENGAGEMENT {ip}: {elapsed:.1f}min → L{new_level} @ {rate}")
        except Exception as e:
            print(f"[VIGILANT] Engagement loop error: {e}")
            check_interval = 5  # Fast retry on error

        time.sleep(check_interval)



def _engagement_level_from_minutes(minutes: float) -> int:
    if minutes >= ENGAGEMENT_L3_MINUTES:
        return CB_LEVEL_CIRCUIT_BREAK
    if minutes >= ENGAGEMENT_L2_MINUTES:
        return CB_LEVEL_FRICTION
    if minutes >= ENGAGEMENT_L1_MINUTES:
        return CB_LEVEL_PAUSE
    return CB_LEVEL_NONE


def escalate_circuit_breaker(client_ip, domain, rpm_current=0, rpm_baseline=0):
    """Mark social activity — engagement tracking is handled by background loop."""
    session_started = time.time()
    with velocity_lock:
        social_started = social_session_start.get(client_ip, 0)
        if social_started:
            session_started = social_started
    with _engagement_lock:
        _engagement_last_request[client_ip] = time.time()
        if _engagement_start[client_ip] == 0:
            # Use the existing social session start so L1/L2/L3 thresholds are
            # measured from the actual scrolling session, not from the moment
            # the first "engaged" event is emitted.
            _engagement_start[client_ip] = session_started
    return _engagement_current_level.get(client_ip, 0)


def apply_circuit_breaker_action(client_ip, domain, level, rpm_current=0, rpm_baseline=0):
    """Apply throttle if level changed. Engagement loop calls this, not request path."""
    if level == CB_LEVEL_NONE:
        return False
    config = load_proxy_config()
    _engagement_rates = {
        0: None,
        1: config.get('engagement_l1_rate', ENGAGEMENT_LEVEL_RATE.get(1, '128kbit')),
        2: config.get('engagement_l2_rate', ENGAGEMENT_LEVEL_RATE.get(2, '32kbit')),
        3: config.get('engagement_l3_rate', ENGAGEMENT_LEVEL_RATE.get(3, '4kbit')),
    }
    rate = _engagement_rates.get(level)
    if not rate:
        return False
    prev = _previous_rate.get(client_ip)
    if prev == rate:
        return True
    success = apply_throttle(client_ip, rate=rate)
    if success:
        _previous_rate[client_ip] = rate
        save_throttle_state(client_ip, is_throttled=True, recovery_at=0)
        mins = _engagement_minutes.get(client_ip, 0)
        log_throttle(client_ip, domain, rpm_current, rpm_baseline, f"CB_L{level}", f"{mins:.1f}min → L{level} @ {rate}")
        print(f"[VIGILANT] ENGAGEMENT {client_ip}: {mins:.1f}min → L{level} @ {rate}")
    return success


def release_circuit_breaker(client_ip):
    """Manual release: reset engagement, remove throttle."""
    with _engagement_lock:
        _engagement_start[client_ip] = 0
        _engagement_minutes[client_ip] = 0
        _engagement_current_level[client_ip] = 0
        _engagement_low_activity_since.pop(client_ip, None)
    _previous_rate.pop(client_ip, None)
    success = remove_throttle_cycle(client_ip)
    # Reset social session counters so next session starts fresh
    with velocity_lock:
        social_session_totals.pop(client_ip, None)
        social_session_start.pop(client_ip, None)
    if success:
        log_throttle(client_ip, "manual_release", 0, 0, "ENGAGEMENT_RESET_MANUAL", "Manual release from dashboard")
        print(f"[VIGILANT] Manual release: {client_ip} engagement reset")
    else:
        print(f"[VIGILANT] Manual release failed tc cleanup for {client_ip}")
    return success


def get_all_circuit_breaker_states():
    with _engagement_lock:
        result = []
        now = time.time()
        for ip, level in _engagement_current_level.items():
            if level == CB_LEVEL_NONE:
                continue
            elapsed = now - _engagement_start.get(ip, 0)
            last_req = _engagement_last_request.get(ip, 0)
            idle = now - last_req if last_req > 0 else 0
            mins = _engagement_minutes.get(ip, 0)
            rate = _previous_rate.get(ip, '')
            result.append({
                "client_ip": ip,
                "level": level,
                "level_name": CB_LEVEL_NAMES.get(level, "Unknown"),
                "domain": "",
                "elapsed_seconds": round(elapsed, 1),
                "idle_seconds": round(idle, 1),
                "engagement_minutes": round(mins, 1),
                "throttle_rate": rate,
                "is_throttled": True
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
            social_request_history.pop(ip, None)
            social_session_totals.pop(ip, None)
            social_session_start.pop(ip, None)
            _social_low_activity_since.pop(ip, None)

    # Prune rate-limit timestamps for devices idle > 10 minutes
    prune_cutoff = now - 600
    for ip in [ip for ip, ts in _engaged_log_times.items() if ts < prune_cutoff]:
        _engaged_log_times.pop(ip, None)

    # Prune the PFR traffic windows to prevent unbounded memory growth.
    if profiler is not None:
        try:
            profiler.cleanup_stale_traffic_windows(now)
        except Exception as e:
            print(f"[VIGILANT] PFR cleanup error: {e}")

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

    # ── Social-only tracking: accumulate velocity for social media
    # domains separately from the global request_history. This prevents
    # the initial app-load burst (50+ requests in 2s when opening
    # Instagram/TikTok) from triggering the RPM spike detector against
    # a low baseline. By the time 30 social requests accumulate, the
    # burst has passed and normal scrolling patterns emerge.
    with velocity_lock:
        if social_session_start[client_ip] == 0:
            social_session_start[client_ip] = time.time()
        sdq = social_request_history[client_ip]
        now = time.time()
        while sdq and now - sdq[0] > VELOCITY_WINDOW:
            sdq.popleft()
        sdq.append(now)
        social_session_totals[client_ip] += 1
        social_count = social_session_totals[client_ip]

    if social_count < int(config.get('engagement_min_requests', MIN_SOCIAL_REQUESTS_BASELINE)):
        return False, rpm_now, rpm_base

    # Optional: YouTube / IG short-form detection
    is_youtube = "youtube.com" in clean_host or "googlevideo.com" in clean_host
    if is_youtube and not ("/shorts/" in path or "shorts" in path):
        return False, rpm_now, rpm_base

    # ── Detection: engagement-based ──
    # Real doomscrolling = watching a reel 25s → swipe → watch 25s → swipe.
    # RPM is low (2-4/min) but engagement is continuous. We flag when the
    # user has been on social media for 3+ minutes with regular activity.
    with velocity_lock:
        sdq = social_request_history[client_ip]
        social_rpm = len(sdq)
        social_elapsed = time.time() - social_session_start[client_ip]

    # Flag if: 3+ min on social media AND actively making requests (2+ RPM).
    # At 1 RPM the user has stopped scrolling — those are just background pings
    # from the app staying open. We require 2+ RPM to consider them "engaged."
    flagged = social_elapsed >= 180 and social_rpm >= 2

    if flagged:
        # Rate-limit the "Engaged" log — should_throttle is called on every
        # request (TLS + HTTP + response hooks), so without throttling this
        # floods journalctl at the device's RPM rate (20+ lines/min).
        now_ts = time.time()
        if now_ts - _engaged_log_times.get(client_ip, 0) >= 10.0:
            _engaged_log_times[client_ip] = now_ts
            # Show domain + total requests so you can see the baseline and which app
            short_host = host.removeprefix("www.")
            print(f"[VIGILANT] Engaged: {client_ip} on {short_host} — {social_rpm} RPM ({social_count} total) for {social_elapsed:.0f}s")

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


def normalize_query(text: str) -> str:
    """Decode percent-encoding, lowercase, strip non-alphanumerics, and extract
    search-query parameter values (q, search_query, query, p) if present.

    Returns a normalized string combining the extracted query values.
    """
    if not text:
        return ""
    decoded = urllib.parse.unquote(text)
    # Split off the query string and pull out recognized search params.
    query_terms = []
    try:
        parts = urllib.parse.urlsplit(decoded)
        params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        for key in ("q", "search_query", "query", "p"):
            if key in params:
                query_terms.extend(params[key])
    except Exception:
        query_terms = []
    extracted = " ".join(query_terms)
    return normalize_text_simple(extracted)


def scan_text_for_keywords(text: str, keywords) -> str:
    """
    Keyword detection with query normalization + fuzzy matching.
    Returns the first matched keyword or None.

    - Keywords with len(keyword) <= 3 require an EXACT word match to prevent
      catastrophic false positives on short words.
    - Keywords with len(keyword) > 3 match if the keyword is a substring of a
      token OR difflib.SequenceMatcher ratio >= 0.82 (catches typos / dropped
      letters, e.g. "por" vs "porn", "p0rn", "pornn").
    """
    if not text or not keywords:
        return None

    normalized_text = normalize_text_simple(text)
    tokens = normalized_text.split()
    token_set = set(tokens)

    for keyword in keywords:
        if not keyword:
            continue
        normalized_keyword = normalize_text_simple(keyword)
        if not normalized_keyword:
            continue

        # Multi-word keyword: exact subset of all tokens (fuzzy multi-word is
        # noisy; exact presence is the reliable signal).
        keyword_tokens = normalized_keyword.split()
        if len(keyword_tokens) > 1:
            if set(keyword_tokens).issubset(token_set):
                return keyword
            continue

        word = normalized_keyword
        if len(word) <= 3:
            # Short keyword — exact word match only.
            if word in token_set:
                return keyword
            continue

        # Long keyword — substring or fuzzy ratio.
        for token in tokens:
            if word in token:
                return keyword
            if difflib.SequenceMatcher(None, token, word).ratio() >= 0.82:
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
    (172.20.10.1). This ensures tc rules are applied to the correct interface
    even if the database has stale defaults like "eth1".
    """
    try:
        conn = _connect_db()
        try:
            cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'distribution_interface'")
            row = cursor.fetchone()
        finally:
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
    
    # Auto-detect: find the interface with the LAN gateway IP (172.20.10.1)
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
            # Line with IP address: "    inet 172.20.10.1/24 ..."
            if current_iface and "inet 172.20.10." in line:
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
    
    return "enp1s0"

def _ip_to_class_id(client_ip: str) -> tuple:
    """Derive a deterministic tc class ID and priority from an IP address.
    Uses the last two octets of the IP (e.g. 172.20.10.25 → octets 10.25)
    to compute a unique ID in range 1:10 through 1:fffe.
    
    This is deterministic across all processes, unlike Python's hash()
    which is randomized per-interpreter and would break cross-process
    tc rule removal (e.g., Flask dashboard vs mitmproxy addon).
    """
    try:
        parts = client_ip.split('.')
        if len(parts) == 4:
            # Use last two octets: ensures uniqueness within a /16 subnet
            ip_hash = (int(parts[2]) << 8 | int(parts[3])) + 0x10
        else:
            # Fallback for non-IPv4 addresses
            import hashlib
            ip_hash = int(hashlib.md5(client_ip.encode()).hexdigest()[:8], 16) % 0xfff0 + 0x10
    except (ValueError, IndexError):
        import hashlib
        ip_hash = int(hashlib.md5(client_ip.encode()).hexdigest()[:8], 16) % 0xfff0 + 0x10
    class_id = f"1:{ip_hash:x}"
    return class_id, ip_hash


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
    
    # Derive a unique, deterministic classId from the client IP
    class_id, prio = _ip_to_class_id(client_ip)

    try:
        # Ensure root qdisc exists. Using 'replace' is idempotent and avoids
        # RTNETLINK "File exists" errors from bare 'add' on pre-existing qdiscs.
        subprocess.run(
            ["tc", "qdisc", "replace", "dev", interface, "root", "handle", "1:", "htb", "default", "1"],
            check=False, capture_output=True, text=True
        )

        # Remove any stale class + filter for this client first (clean re-apply).
        # This is critical: without it, tc class add fails with "File exists"
        # when circuit breaker escalates to a higher throttle level, meaning
        # the user would be stuck at the old rate indefinitely.
        remove_throttle(client_ip)

        # Add a dedicated class for this client IP.
        # burst=2k allows only ~2KB at line rate before the throttle kicks in.
        # This means the TCP handshake completes but the very first data packet
        # gets shaped, making throttling immediately noticeable.
        #
        # First try 'add'; if the class survived remove_throttle (e.g. due to
        # a prio mismatch from a previous process), fall back to 'replace'.
        result = subprocess.run(
            ["tc", "class", "add", "dev", interface, "parent", "1:", "classid", class_id,
             "htb", "rate", throttle_rate, "ceil", throttle_rate,
             "burst", "2k", "cburst", "2k"],
            check=False, capture_output=True, text=True
        )
        if result.returncode != 0:
            if "RTNETLINK answers: File exists" in result.stderr:
                result = subprocess.run(
                    ["tc", "class", "replace", "dev", interface, "parent", "1:",
                     "classid", class_id, "htb", "rate", throttle_rate,
                     "ceil", throttle_rate, "burst", "2k", "cburst", "2k"],
                    check=False, capture_output=True, text=True
                )
            if result.returncode != 0:
                print(f"[VIGILANT] tc class add/replace failed for {client_ip} on {interface}: {result.stderr.strip()}")
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
    
    # Get the deterministic classId for this client
    class_id, prio = _ip_to_class_id(client_ip)
    
    # Also try stored mapping if available (in-process cache)
    stored_class = _throttle_map.get(client_ip)
    if stored_class:
        class_id = stored_class
        del _throttle_map[client_ip]
    
    errors = []
    try:
        # Remove dst filter for this specific client
        r = subprocess.run(
            ["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "dst", client_ip, "flowid", class_id],
            check=False, capture_output=True, text=True
        )
        if r.returncode != 0:
            errors.append(f"dst filter: {r.stderr.strip()}")
        
        # Remove src filter for this specific client
        r = subprocess.run(
            ["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", str(prio), "u32", "match", "ip", "src", client_ip, "flowid", class_id],
            check=False, capture_output=True, text=True
        )
        if r.returncode != 0:
            errors.append(f"src filter: {r.stderr.strip()}")
        
        if not client_ip_only:
            # Remove the dedicated class for this client ONLY
            r = subprocess.run(
                ["tc", "class", "del", "dev", interface, "parent", "1:", "classid", class_id],
                check=False, capture_output=True, text=True
            )
            if r.returncode != 0:
                # Some tc builds reject the parent-qualified form for deletes.
                retry = subprocess.run(
                    ["tc", "class", "del", "dev", interface, "classid", class_id],
                    check=False, capture_output=True, text=True
                )
                if retry.returncode != 0:
                    errors.append(
                        f"class delete: {r.stderr.strip() or retry.stderr.strip()}"
                    )
        
        if errors:
            print(f"[VIGILANT] Throttle removal for {client_ip} on {interface} had errors: {'; '.join(errors)}")
            # Even with filter errors, the class may have been deleted. Check if it still exists.
            r = subprocess.run(
                ["tc", "class", "show", "dev", interface],
                check=False, capture_output=True, text=True
            )
            if class_id in r.stdout:
                print(f"[VIGILANT] WARNING: Class {class_id} still exists on {interface} after removal attempt!")
                return False
        
        print(f"[VIGILANT] Throttle cleanup completed for {client_ip} on {interface} (class={class_id})")
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
    Remove tc throttle rules and clean up timer/throttled set.
    Does NOT touch circuit_breaker_state — that's managed by
    escalate_circuit_breaker / release_circuit_breaker so cooldowns work.
    """
    # Remove TC rules
    success = remove_throttle(client_ip)

    # Cancel any pending recovery timer for this client so a stale timer
    # cannot race with a manual release.
    with throttle_timers_lock:
        _cancel_timer(client_ip)

    # Clean up from active throttled_clients set
    with throttled_clients_lock:
        throttled_clients.discard(client_ip)

    # Only update DB state if tc removal actually succeeded.
    # This prevents the state mismatch where DB says "not throttled"
    # but tc rules are still active on the interface.
    if success:
        save_throttle_state(client_ip, is_throttled=False, recovery_at=0)
        log_throttle(client_ip, "throttle_cycle", 0, 0, "THROTTLE_CYCLE_REMOVED", "Throttle cycle completed - bandwidth restored")
        print(f"[VIGILANT] Throttle cycle completed for {client_ip} - bandwidth restored")
    else:
        print(f"[VIGILANT] WARNING: Throttle removal failed for {client_ip} - DB not updated")
    return success


def save_throttle_state(client_ip, is_throttled, recovery_at):
    """
    Save throttle state to database for persistence across restarts.
    
    Args:
        client_ip: Client IP address
        is_throttled: Whether client is currently throttled
        recovery_at: Unix timestamp when throttle should recover
    """
    try:
        now = time.time()
        with db_lock:
            conn = _connect_db()
            try:
                cursor = conn.execute("SELECT cycle_count FROM throttle_state WHERE client_ip = ?", (client_ip,))
                existing = cursor.fetchone()

                if existing:
                    cycle_count = existing[0] + 1 if is_throttled else existing[0]
                    conn.execute(
                        "UPDATE throttle_state SET is_throttled=?, applied_at=?, recovery_at=?, cycle_count=? WHERE client_ip=?",
                        (int(is_throttled), now, recovery_at, cycle_count, client_ip)
                    )
                else:
                    cycle_count = 1 if is_throttled else 0
                    conn.execute(
                        "INSERT INTO throttle_state (client_ip, is_throttled, applied_at, recovery_at, cycle_count) "
                        "VALUES (?,?,?,?,?)",
                        (client_ip, int(is_throttled), now, recovery_at, cycle_count)
                    )

                conn.commit()
            finally:
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
    All current throttle levels are persistent (no timer), so we restore
    every throttled client and let the de-escalation system handle release.
    """
    time.sleep(5)  # Wait for proxy to fully initialize

    try:
        with db_lock:
            conn = _connect_db()
            now = time.time()
            # All throttles are persistent — recovery_at=0 means no timer.
            # Restore every device marked as throttled.
            cursor = conn.execute(
                "SELECT client_ip FROM throttle_state WHERE is_throttled = 1"
            )
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                client_ip = row[0]
                print(f"[VIGILANT] Restoring throttle for {client_ip} (persistent)")
                # Re-apply at a reasonable default rate. The circuit breaker
                # escalation will adjust to the correct level on next request.
                apply_throttle(client_ip, rate="128kbit")
                with throttled_clients_lock:
                    throttled_clients.add(client_ip)

            print(f"[VIGILANT] Restored {len(rows)} throttle states from database")
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in restore_throttle_states: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in restore_throttle_states: {e}")

# ─── DNS Log Tailing Thread ─────────────────────────────────────────────
def tail_dnsmasq_log():
    """Background thread to tail dnsmasq log for passive DNS tracking.

    Monitors /var/log/dnsmasq.log and reopens it when the file is rotated
    (rename-based: inode change) or truncated in place (copytruncate-based:
    size regression), so device liveness tracking keeps working across
    logrotate runs.
    """
    log_path = "/var/log/dnsmasq.log"
    f = None
    last_inode = None
    last_pos = 0

    while True:
        try:
            if not os.path.exists(log_path):
                if f is not None:
                    f.close()
                    f = None
                last_inode = None
                last_pos = 0
                time.sleep(5)
                continue

            stat = os.stat(log_path)
            current_inode = stat.st_ino
            size = stat.st_size

            # Reopen when: first open, rename-rotated (inode changed), or
            # copytruncate-rotated (file shrank below our read position).
            if f is None or current_inode != last_inode or size < last_pos:
                if f is not None:
                    f.close()
                f = open(log_path, 'r')
                f.seek(0, 2)  # start at end: only process NEW queries
                last_inode = current_inode
                last_pos = f.tell()
                continue

            # Drain any newly-appended lines without blocking.
            while True:
                line = f.readline()
                if not line:
                    break
                last_pos = f.tell()

                if "query[" in line and " from " in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.startswith("query[") and i + 3 < len(parts):
                            domain = parts[i + 1]
                            client_ip = parts[i + 3]

                            update_device_activity(client_ip)

                            # DNS queries are used ONLY for velocity/RPM tracking
                            # and device-liveness. Throttle escalation comes from
                            # actual TLS/content traffic, not DNS lookups — background
                            # app refreshes generate DNS prefetches for social CDNs
                            # (graph.facebook.com etc.) even when the user is idle.
                            compute_velocity(client_ip)

                            # DNS queries are NOT logged to traffic_log to avoid noise.
                            break

            time.sleep(0.2)
        except FileNotFoundError:
            if f is not None:
                f.close()
                f = None
            last_inode = None
            last_pos = 0
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
        _refresh_bypass_cache()
        _refresh_whitelist_cache()
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

        engagement_thread = threading.Thread(target=_engagement_tracking_loop, daemon=True)
        engagement_thread.start()
        print("[VIGILANT] Engagement tracking loop started (interval=%ss)" % ENGAGEMENT_CHECK_INTERVAL)

    def _refresh_rule_cache(self):
        """Fetch blacklisted keywords and category hints from the database."""
        conn = None
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
                    
            # Load exempt devices
            try:
                cursor = conn.execute(
                    "SELECT ip_address FROM network_devices WHERE doomscroll_exempt = 1 OR policy = 'whitelist'"
                )
                exempt_ips = {row[0] for row in cursor.fetchall()}
            except sqlite3.OperationalError:
                exempt_ips = set()

            with self._cache_lock:
                self.cached_keywords = keywords
                self.cached_hints = hints
                self.cached_exempt_devices = exempt_ips

                self._last_cache_refresh = time.time()
        except Exception as e:
            print(f"[VIGILANT] Error refreshing rule cache: {e}")
        finally:
            if conn:
                conn.close()

    def _cache_refresh_loop(self):
        """Periodically refresh cached rules or reload immediately on API trigger.
        Also processes throttle release requests from the Flask dashboard, and
        runs periodic cleanup of stale velocity tracking state."""
        _cleanup_counter = 0
        while True:
            time.sleep(1.0)
            reload_requested = False
            try:
                reload_file = _rule_cache_reload_path()
                if reload_file.exists():
                    reload_file.unlink(missing_ok=True)
                    reload_requested = True
            except OSError:
                pass

            # Process throttle release queue (Flask -> mitmproxy IPC).
            # Flask writes release requests here because it lacks CAP_NET_ADMIN
            # for tc commands; mitmproxy has the capability.
            try:
                release_queue = _throttle_release_queue_path()
                if release_queue.exists():
                    lines = release_queue.read_text().strip().split('\n')
                    release_queue.unlink(missing_ok=True)
                    for line in lines:
                        ip = line.strip()
                        if not ip:
                            continue
                        if ip == '__RESET_ALL__':
                            print("[VIGILANT] Processing RESET_ALL from release queue")
                            iface = get_distribution_interface()
                            # Atomically replace the root qdisc — avoids the race window
                            # between 'del' and 'add' where no qdisc exists.
                            subprocess.run(["tc", "qdisc", "replace", "dev", iface, "root",
                                            "handle", "1:", "htb", "default", "1"],
                                           capture_output=True, check=False)
                            with _engagement_lock:
                                _engagement_start.clear()
                                _engagement_minutes.clear()
                                _engagement_last_request.clear()
                                _engagement_current_level.clear()
                                _engagement_low_activity_since.clear()
                            _previous_rate.clear()
                            with throttled_clients_lock:
                                throttled_clients.clear()
                            with velocity_lock:
                                social_request_history.clear()
                                social_session_totals.clear()
                                social_session_start.clear()
                            print("[VIGILANT] RESET_ALL complete")
                        else:
                            print(f"[VIGILANT] Processing release queue: {ip}")
                            try:
                                ok = release_circuit_breaker(ip)
                            except Exception as e:
                                print(f"[VIGILANT] Release queue exception for {ip}: {e}")
                                ok = False
                            if not ok:
                                print(f"[VIGILANT] Release queue failed to remove tc state for {ip}")
            except Exception as e:
                # A transient failure here must NEVER kill the refresh loop,
                # otherwise releases + cache reloads stop working entirely.
                print(f"[VIGILANT] Release queue processing error: {e}")

            with self._cache_lock:
                stale = (time.time() - self._last_cache_refresh) >= CACHE_REFRESH_INTERVAL

            if reload_requested or stale:
                self._refresh_rule_cache()
                _refresh_bypass_cache()
                _refresh_whitelist_cache()

            # Periodically clean up stale velocity tracking state (every 60s)
            _cleanup_counter += 1
            if _cleanup_counter >= 60:
                _cleanup_counter = 0
                _cleanup_stale_velocity_state()  
            
    def _extract_client_ip_from_tls(self, data=None) -> str:
        """Extract client IP safely across all mitmproxy object shapes."""
        if data is None:
            return os.getenv("LAN_IP", "172.20.10.1")

        client_ip = None
        conn = None

        # 1. Resolve connection object across mitmproxy layer versions
        if hasattr(data, "context"):
            ctx = data.context
            conn = getattr(ctx, "client", None) or getattr(ctx, "client_conn", None)
        
        if not conn:
            # Prefer data.client_conn (HTTPFlow-like) then data.conn (TlsData).
            # Do NOT fall back to `data` itself — TlsData objects lack peername.
            conn = getattr(data, "client_conn", None) or getattr(data, "conn", None)

        # 2. Extract peername IP string
        if conn:
            # Check peername attribute (e.g. ('172.20.10.127', 64429))
            peer = getattr(conn, "peername", None)
            if peer and isinstance(peer, (tuple, list)) and len(peer) > 0 and peer[0]:
                client_ip = str(peer[0])
            
            # Check address attribute fallback
            if not client_ip:
                addr = getattr(conn, "address", None)
                if addr and isinstance(addr, (tuple, list)) and len(addr) > 0 and addr[0]:
                    client_ip = str(addr[0])

        # 3. Guard against loopback or self-referential IPs using the ipaddress module
        #    to catch all representations (127.0.0.1, ::1, ::ffff:127.0.0.1, etc.)
        if client_ip:
            try:
                ip_obj = ipaddress.ip_address(client_ip)
                if not ip_obj.is_loopback:
                    return client_ip
            except ValueError:
                # Not a valid IP — check for literal 'localhost'
                if client_ip.lower() != "localhost":
                    return client_ip

        # If socket lookup failed, fallback to default LAN IP
        return os.getenv("LAN_IP", "172.20.10.1")

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

            # Resolve the real client IP before any bypass decision so
            # transparent passthrough traffic can still be logged to the DB.
            client_ip = self._extract_client_ip_from_tls(data)
            if not client_ip:
                return

            # Always log SNI requests and check throttling on TLS connections.
            # sni_filtering_enabled only affects dashboard display filtering.
            print(f"[VIGILANT DEBUG] About to log SNI request: {client_ip} @ {server_name}")
            self.log_to_dashboard(client_ip, server_name)

            # Calculate and persist SNI velocity for the dashboard's SNI tab.
            velocity_rps = compute_sni_velocity(client_ip, server_name)
            log_sni_request(client_ip, server_name, velocity_rps)

            # 2. Check bypass conditions in explicit order
            is_bypassed = False
            
            # a) Global asset whitelist (infrastructure/CDN domains — checked first
            #    to avoid intercepting TLS for known-trusted asset domains)
            if is_whitelisted(server_name):
                is_bypassed = True
            
            # b) Admin DB overrides
            elif is_custom_bypass(server_name):
                is_bypassed = True
                
            # c) In-memory SSL pinning auto-detected during current uptime
            elif server_name in self.pinned_hosts:
                is_bypassed = True
                
            # d) Hardcoded system safety domains
            else:
                _APPLE_DOMAINS = {"apple.com", "icloud.com", "mzstatic.com"}
                clean_sni = server_name.lower().removeprefix("www.")
                if any(clean_sni == d or clean_sni.endswith("." + d) for d in _APPLE_DOMAINS):
                    is_bypassed = True

            # Throttling is applied via tc on the interface regardless of bypass
            flagged, rpm_now, rpm_base = should_throttle(client_ip, server_name)
            if flagged and not is_device_exempt(client_ip):
                level = escalate_circuit_breaker(client_ip, server_name, rpm_now, rpm_base)
                if level >= CB_LEVEL_PAUSE:
                    _mark_client_throttled(client_ip)
                apply_circuit_breaker_action(client_ip, server_name, level, rpm_now, rpm_base)
                if level >= CB_LEVEL_PAUSE and not is_bypassed:
                    print(f"[VIGILANT] TLS CB Level {level} ({CB_LEVEL_NAMES[level]}) {client_ip} @ {server_name} "
                          f"RPM={rpm_now:.1f} baseline={rpm_base:.1f} RPS={velocity_rps:.2f}")

            if is_bypassed:
                data.ignore_connection = True
                return

            # 3. Log social domain requests to traffic log (non-pinned only)
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
        """Detect SSL-pinning rejections and record them as observations.

        Records every pinning-symptom failure into pinning_observations,
        grouped under the registrable base domain. NEVER auto-bypasses — a
        domain only becomes a review candidate once it reaches the configured
        occurrence threshold (pinning_min_occurrences, default 3).
        """
        server_name = getattr(data.conn, "sni", None)
        if not server_name:
            return

        error_msg = str(getattr(data.conn, "error", "")).lower()
        if not error_msg:
            error_msg = str(getattr(data, "error", "")).lower()

        # Check for missing root CA errors (client does not trust the proxy CA)
        # — these are benign, NOT pinning.
        ca_errors = ["unknown ca", "bad certificate", "certificate unknown", "sec_error_unknown_issuer", "self signed certificate"]
        if any(err in error_msg for err in ca_errors):
            print(f"[VIGILANT] Ignored TLS failure for {server_name} (Missing Root CA)")
            return

        # Genuine pinning signature (e.g. "the client disconnected during the handshake").
        client_ip = self._extract_client_ip_from_tls(data)
        base = _base_domain(server_name)
        try:
            with db_lock:
                conn = _connect_db()
                try:
                    now = time.time()
                    conn.execute(
                        "INSERT INTO pinning_observations "
                        "(client_ip, base_domain, exact_domain, first_seen, last_seen, count) "
                        "VALUES (?, ?, ?, ?, ?, 1) "
                        "ON CONFLICT(client_ip, exact_domain) DO UPDATE SET "
                        "last_seen = excluded.last_seen, count = count + 1",
                        (client_ip, base, server_name, now, now)
                    )
                    conn.commit()
                finally:
                    conn.close()
            print(f"[VIGILANT] Pinning observation recorded: {server_name} (base {base}) by {client_ip} — queued for review")
        except Exception as e:
            print(f"[VIGILANT] Error recording pinning observation for {server_name}: {e}")

    def _persist_bypass_domain(self, domain: str):
        """Add exact domain to custom_bypass_domains in DB without broad base-domain wildcards."""
        # Prevent broad Google/Apple core domains from auto-persisting globally
        PROTECTED_ROOTS = {"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com"}
        
        clean = domain.removeprefix("www.").lower()
        if clean in PROTECTED_ROOTS:
            print(f"[VIGILANT] Skipping broad auto-bypass persistence for protected domain: {clean}")
            return

        try:
            with db_lock:
                conn = _connect_db()
                try:
                    cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'custom_bypass_domains'")
                    row = cursor.fetchone()
                    existing = set()
                    if row and row[0]:
                        existing = set(d.strip() for d in row[0].split(",") if d.strip())
                    
                    if clean not in existing:
                        existing.add(clean)
                        new_value = ",".join(sorted(existing))
                        conn.execute(
                            "INSERT OR REPLACE INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)",
                            ("custom_bypass_domains", new_value, time.time())
                        )
                        conn.commit()
                        _refresh_bypass_cache()
                        print(f"[VIGILANT] Persisted exact domain {clean} to custom_bypass_domains")
                finally:
                    conn.close()
        except Exception as e:
            print(f"[VIGILANT] Failed to persist bypass domain {domain}: {e}")

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
            if not client_ip:
                return
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
                    print(f"[VIGILANT] KEYWORD BLOCKED (request): {matched} from {client_ip} @ {host}")
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
        # Throttle check still runs for pinned domains — only content scanning is skipped.
        clean_host = host.removeprefix("www.").lower()
        is_pinned = is_pinned_host(host)

        # ── Dynamic Traffic Profiling (PFR) ──
        # Only tick the doomscroll engagement timer for INTERACTIVE_FEED sessions.
        # PASSIVE_MEDIA (long-form video/audio) and STANDARD_WEB skip the timer.
        if profiler is not None:
            behavior = profiler.evaluate_session_behavior(client_ip, clean_host)
        else:
            # Profiler unavailable — fall back to always tick (legacy behavior).
            behavior = "INTERACTIVE_FEED"

        if behavior == "INTERACTIVE_FEED":
            flagged, rpm_now, rpm_base = should_throttle(client_ip, host)
            if flagged and not is_device_exempt(client_ip):
                level = escalate_circuit_breaker(client_ip, host, rpm_now, rpm_base)
                if level >= CB_LEVEL_PAUSE:
                    _mark_client_throttled(client_ip)
                apply_circuit_breaker_action(client_ip, host, level, rpm_now, rpm_base)
                if level >= CB_LEVEL_PAUSE:
                    print(f"[VIGILANT] HTTP CB Level {level} ({CB_LEVEL_NAMES[level]}) {client_ip} @ {host} "
                          f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")
        elif behavior == "PASSIVE_MEDIA":
            # Long-form media — pause the engagement timer, no throttle escalation.
            pass
        # STANDARD_WEB — normal processing, no doomscroll tick.

        if is_pinned:
            print(f"[VIGILANT] TLS PASSTHROUGH: {host} from {client_ip} (pinned domain, content scan skipped)")
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
        # than a deliberately-typed URL. Runs for ALL domains — a category hint
        # (e.g. "Distracting") routes traffic but must NOT exempt POST bodies
        # from keyword blocking.
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

    def response(self, flow: http.HTTPFlow):
        try:
            client_ip = flow.client_conn.peername[0]
            if not client_ip:
                return
        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] Response: Failed to extract client IP from peername: {e}")
            return
        host         = flow.request.pretty_host
        path         = flow.request.path[:120]
        method       = flow.request.method
        content_type = flow.response.headers.get("content-type", "")

        # ── Bypass rules ──
        # Already blocked by request-side inspection — do not re-scan.
        if flow.response.status_code == 403:
            return
        # SSL-pinned app domains — binary/protobuf bodies, request-side scan is
        # the enforcement point.
        if is_pinned_host(host):
            return
        # Global whitelist / custom bypass — pass through unmodified.
        if is_whitelisted(host) or is_custom_bypass(host):
            log_request(client_ip, host, path, method, "Educational", False, [], None)
            print(f"[VIGILANT] WHITELIST BYPASS (response): {host} -> {client_ip}")
            return

        clean_host = host.removeprefix("www.").lower()

        # ── Payload profiling (PFR window) ──
        payload_bytes = len(flow.response.content) if flow.response.content else 0
        if profiler is not None:
            profiler.record_response(client_ip, clean_host, payload_bytes)

        # ── Content gate — only text/HTML/JSON/plain gets deep inspection ──
        TEXT_CONTENT_TYPES = {"text/html", "application/json", "text/plain"}
        if not any(ct in content_type for ct in TEXT_CONTENT_TYPES):
            category_hints = load_category_hints()
            domain_category = None
            for category, domains in category_hints.items():
                if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                    domain_category = category
                    break
            log_request(client_ip, host, path, method, domain_category or "Non-HTML", False, [], None)
            return

        # ── Sample first 20KB of response body (sub-ms execution) ──
        try:
            body_text = flow.response.get_text(strict=False)[:20000]
        except Exception:
            body_text = ""

        # ── Stage A — Fuzzy keyword scan ──
        try:
            keywords = get_blacklisted_keywords()
            if keywords and body_text:
                matched = scan_text_for_keywords(body_text, keywords)
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

        # ── Stage B — TF-IDF vectorizer scan ──
        config = load_proxy_config()
        threshold = float(config.get('tfidf_classification_threshold', 0.15))
        tfidf_category, _tfidf_scores = tfidf_classifier.classify(body_text, threshold=threshold)
        if tfidf_category == "Harmful":
            print(f"[VIGILANT] RESPONSE TF-IDF BLOCKED: {host} classified Harmful")
            log_request(client_ip, host, path, method, "Harmful", True, [], "TFIDF_HARMFUL")
            flow.response = http.Response.make(
                403,
                render_block_page(host, "Harmful"),
                {"Content-Type": "text/html"}
            )
            return

        # ── Normal logging (non-block) ──
        category_hints = load_category_hints()
        domain_category = None
        for category, domains in category_hints.items():
            if any(clean_host == d or clean_host.endswith("." + d) for d in domains):
                domain_category = category
                break

        final_category = domain_category or tfidf_category or "Uncategorized"
        log_request(client_ip, host, path, method, final_category, False, [], None)
        print(f"[VIGILANT] {method} {host}{path[:40]} -> [{final_category}] client={client_ip}")

def get_pending_bypasses(min_occurrences: int = 3):
    """Return pinning clusters that reached the occurrence threshold, grouped
    by registrable base domain. Each cluster lists the exact pinning-failing
    domains observed (display shows pinning-failing exact domains only)."""
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                cursor = conn.execute(
                    """SELECT base_domain, SUM(count), COUNT(DISTINCT exact_domain), MAX(last_seen)
                       FROM pinning_observations
                       GROUP BY base_domain
                       HAVING SUM(count) >= ?
                       ORDER BY MAX(last_seen) DESC""",
                    (int(min_occurrences),)
                )
                results = []
                for base, total, sub_count, last_seen in cursor.fetchall():
                    obs = conn.execute(
                        "SELECT exact_domain, count, last_seen FROM pinning_observations "
                        "WHERE base_domain = ? ORDER BY count DESC, last_seen DESC",
                        (base,)
                    ).fetchall()
                    results.append({
                        "base_domain": base,
                        "total_occurrences": int(total or 0),
                        "subdomain_count": int(sub_count or 0),
                        "last_seen": last_seen,
                        "observed_domains": [
                            {"domain": o[0], "count": int(o[1]), "last_seen": o[2]} for o in obs
                        ],
                    })
                return results
            finally:
                conn.close()
    except Exception as e:
        print(f"[VIGILANT] Error fetching pending bypasses: {e}")
        return []


def approve_pending_bypass(base_domain: str, scope: str = "exact"):
    """Approve a pinning cluster and persist it.

    scope='exact' persists each exact pinning-failing SNI domain only — web
    versions sharing the parent domain remain inspectable.
    scope='all' persists the registrable base domain — fully bypasses the app,
    but also covers any web traffic on that base domain.
    """
    base_domain = base_domain.strip().lower()
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                rows = conn.execute(
                    "SELECT DISTINCT exact_domain FROM pinning_observations WHERE base_domain = ?",
                    (base_domain,)
                ).fetchall()
                exact_domains = [str(r[0]).strip().lower() for r in rows if r[0]]

                if scope == "all":
                    domains_to_add = [base_domain]
                else:
                    domains_to_add = exact_domains

                cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'custom_bypass_domains'")
                row = cursor.fetchone()
                existing = set()
                if row and row[0]:
                    existing = set(d.strip() for d in row[0].split(",") if d.strip())
                existing.update(d for d in domains_to_add if d)
                new_value = ",".join(sorted(existing))
                conn.execute(
                    "INSERT OR REPLACE INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)",
                    ("custom_bypass_domains", new_value, time.time())
                )
                # Remove observations for this cluster
                conn.execute("DELETE FROM pinning_observations WHERE base_domain = ?", (base_domain,))
                conn.commit()
            finally:
                conn.close()

        _refresh_bypass_cache()
        print(f"[VIGILANT] Approved pinning cluster {base_domain} (scope={scope}, {len(domains_to_add)} domains persisted)")
        return True, len(domains_to_add)
    except Exception as e:
        print(f"[VIGILANT] Error approving bypass for {base_domain}: {e}")
        return False, 0


def reject_pending_bypass(base_domain: str):
    """Reject a pinning cluster: drop its observations. Nothing is bypassed."""
    base_domain = base_domain.strip().lower()
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                conn.execute("DELETE FROM pinning_observations WHERE base_domain = ?", (base_domain,))
                conn.commit()
            finally:
                conn.close()
        return True
    except Exception as e:
        print(f"[VIGILANT] Error rejecting bypass for {base_domain}: {e}")
        return False


def clear_pending_bypasses():
    """Delete ALL pinning observations (the full review waitlist)."""
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                deleted = conn.execute("DELETE FROM pinning_observations").rowcount or 0
                conn.commit()
                return deleted
            finally:
                conn.close()
    except Exception as e:
        print(f"[VIGILANT] Error clearing pinning observations: {e}")
        return 0


def export_pending_bypasses():
    """Return the FULL pinning observations detail (all exact subdomains) for export."""
    conn = None
    try:
        with db_lock:
            conn = _connect_db()
            try:
                rows = conn.execute(
                    "SELECT base_domain, exact_domain, client_ip, count, first_seen, last_seen "
                    "FROM pinning_observations ORDER BY base_domain, exact_domain"
                ).fetchall()
                return [
                    {
                        "base_domain": r[0],
                        "exact_domain": r[1],
                        "client_ip": r[2],
                        "count": int(r[3]),
                        "first_seen": r[4],
                        "last_seen": r[5],
                    }
                    for r in rows
                ]
            finally:
                conn.close()
    except Exception as e:
        print(f"[VIGILANT] Error exporting pinning observations: {e}")
        return []

addons = [VIGILANTAddon()]
