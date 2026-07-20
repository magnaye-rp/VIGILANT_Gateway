import re
import time
import sqlite3
import threading
import subprocess
import urllib.parse
from collections import defaultdict, deque, Counter
from mitmproxy import http, tls
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

# ─── Configuration ────────────────────────────────────────────────
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PRODUCTION_DB_PATH = Path("/home/vigilant_admin/vigilant/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

if PRODUCTION_DB_PATH.exists() and os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
    DB_PATH = str(PRODUCTION_DB_PATH)
else:
    DB_PATH = str(LOCAL_DB_PATH)

VELOCITY_WINDOW    = 60
MIN_REQUESTS_BASELINE = 10

# Default values (will be overridden by database config)
DEFAULT_VELOCITY_THRESHOLD = 1.5
DEFAULT_THROTTLE_RATE = "512kbit"
DEFAULT_PINNED_DOMAINS = "instagram.com, facebook.com,tiktok.com,x.com,twitter.co, youtube.com"

# Global asset whitelist
GLOBAL_WHITELIST = {
    "github.com", "githubassets.com", "githubusercontent.com", "git-scm.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com",
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
    # "youtube.com", "www.youtube.com",
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
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95
        )
        self.category_centroids = {}
        self._fit_category_centroids()
    
    def _fit_category_centroids(self):
        """
        Build TF-IDF vectors for each category's keywords and compute centroids.
        Each category's centroid is the mean TF-IDF vector of all its keyword documents.

        Centroids are pre-stacked into a single 2-D matrix
        (shape: n_categories × vocab_size) so that classify() can perform a
        single batch cosine_similarity call instead of one call per category.
        """
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

        cursor.execute("SELECT value FROM config_settings WHERE key = 'network_velocity_threshold'")
        row = cursor.fetchone()
        network_velocity_threshold = float(row[0]) if row else DEFAULT_VELOCITY_THRESHOLD

        cursor.execute("SELECT value FROM config_settings WHERE key = 'physical_scroll_threshold'")
        row = cursor.fetchone()
        physical_scroll_threshold = int(row[0]) if row else 75

        cursor.execute("SELECT value FROM config_settings WHERE key = 'nlp_enabled'")
        row = cursor.fetchone()
        nlp_enabled_str = row[0] if row else "true"
        nlp_enabled = nlp_enabled_str.lower() in ["true", "1", "yes"]

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


def load_social_domains():
    """Load social domains from category_hints (Distracting category)"""
    try:
        conn = sqlite3.connect(DB_PATH)
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


def log_request(client_ip, host, path, method, category, flagged, entities):
    category_key = (category or "").strip().lower()

    if category_key in _NOISE_CATEGORIES:
        return

    if category_key not in _LOGGABLE_CATEGORIES:
        return

    try:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO traffic_log VALUES (NULL,?,?,?,?,?,?,?,?)",
                (time.time(), client_ip, host, path, method,
                 category, int(flagged), str(entities))
            )
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in log_request: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in log_request: {e}")

def log_throttle(client_ip, host, rpm_now, rpm_base, action):
    try:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO throttle_events VALUES (NULL,?,?,?,?,?,?)",
                (time.time(), client_ip, host, rpm_now, rpm_base, action)
            )
            conn.commit()
            conn.close()
    except sqlite3.Error as e:
        print(f"[VIGILANT] Database error in log_throttle: {e}")
    except Exception as e:
        print(f"[VIGILANT] Unexpected error in log_throttle: {e}")

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

def should_throttle(client_ip, host, path=""):
    config = load_proxy_config()
    network_velocity_threshold = config['network_velocity_threshold']
    physical_scroll_threshold = config['physical_scroll_threshold']
    social_domains = load_social_domains()

    # Include youtube.com back into social_domains in DB or default set
    clean_host = host.lstrip("www.")
    base = ".".join(clean_host.split(".")[-2:])
    
    if not any(base in d for d in social_domains):
        return False, 0, 0

    # Optional: Short-form video detection filter for YouTube / IG
    is_youtube = "youtube.com" in clean_host or "googlevideo.com" in clean_host
    if is_youtube and not ("/shorts/" in path or "shorts" in path):
        # Allow standard long-form videos without aggressive throttling
        return False, 0, 0

    rpm_now, rpm_base = compute_velocity(client_ip)
    if session_totals[client_ip] < MIN_REQUESTS_BASELINE:
        return False, rpm_now, rpm_base

    flagged = (rpm_now > (rpm_base * network_velocity_threshold)) or (rpm_now > physical_scroll_threshold)
    return flagged, rpm_now, rpm_base

def websocket_message(self, flow: http.HTTPFlow):
    message = flow.websocket.messages[-1]
    client_ip = flow.client_conn.peername[0]
    
    # Extract textual content from web-socket frame payload
    payload_text = message.text if message.is_text else message.content.decode("utf-8", errors="ignore")
    
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
        keywords = [row[0] for row in cursor.fetchall()]
        conn.close()

    matched = scan_text_for_keywords(payload_text, keywords)
    if matched:
        print(f"[VIGILANT] WEBSOCKET KEYWORD BLOCKED: {matched} from {client_ip}")
        # Drop the websocket frame / close connection
        flow.websocket.close(1008, "Blocked keyword detected")

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
    clean = host.lstrip("www.")
    for category, domains in category_hints.items():
        if any(clean == d or clean.endswith("." + d) for d in domains):
            return category, 3
    return None, 0


def categorize_content(text, host=""):
    if not text:
        text = ""

    hint_category, hint_score = get_domain_hint(host)
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
            if ent.label_ in ["LAW", "WORK_OF_ART", "EVENT", "ORG", "PERSON", "GPE"]:
                if category == "Uncategorized":
                    category = "Educational"
            elif ent.label_ in ["DATE", "TIME", "CARDINAL", "ORDINAL"]:
                if category == "Uncategorized":
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
    """Get the distribution interface from database config or use default"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("SELECT value FROM config_settings WHERE key = 'distribution_interface'")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "eth1"
    except Exception:
        return "eth1"

def apply_throttle(client_ip):
    """Apply Linux tc traffic control to throttle client bandwidth"""
    config = load_proxy_config()
    throttle_rate = config['throttle_rate']
    interface = get_distribution_interface()

    try:
        subprocess.run(
            ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb"],
            check=False, capture_output=True
        )

        subprocess.run(
            ["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:10",
             "htb", "rate", throttle_rate, "ceil", throttle_rate],
            check=False, capture_output=True
        )

        subprocess.run(
            ["tc", "filter", "add", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", "1", "u32", "match", "ip", "src", client_ip, "flowid", "1:10"],
            check=False, capture_output=True
        )
        print(f"[VIGILANT] Throttling applied to {client_ip} on {interface} at {throttle_rate}")
        return True
    except Exception as e:
        print(f"[VIGILANT] Throttling failed for {client_ip}: {e}")
        return False

def remove_throttle(client_ip):
    """Remove traffic control throttling for client IP"""
    interface = get_distribution_interface()
    try:
        subprocess.run(
            ["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:0",
             "prio", "1", "u32", "match", "ip", "src", client_ip, "flowid", "1:10"],
            check=False, capture_output=True
        )
        print(f"[VIGILANT] Throttling removed for {client_ip} on {interface}")
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
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    if "query[" in line and " from " in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith("query["):
                                if i + 2 < len(parts):
                                    domain = parts[i + 1]
                                    client_ip = parts[i + 3]

                                    flagged, rpm_now, rpm_base = should_throttle(client_ip, domain)
                                    if flagged and client_ip not in throttled_clients:
                                        throttled_clients.add(client_ip)
                                        log_throttle(client_ip, domain, rpm_now, rpm_base, "DNS_THROTTLE_APPLIED")
                                        apply_throttle(client_ip)
                                        print(f"[VIGILANT] DNS DOOMSCROLL DETECTED {client_ip} @ {domain} "
                                              f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

                                    log_request(client_ip, domain, "(DNS_QUERY)", "DNS", "DNS_Tracked", False, [])
                                    break
        except FileNotFoundError:
            time.sleep(5)
        except Exception as e:
            print(f"[VIGILANT] DNS log tailing error: {e}")
            time.sleep(5)


# ══════════════════════════════════════════════════════════════════
# ─── FIX #4 (partial): Sampled Scanning for Oversized Payloads ─────
# ══════════════════════════════════════════════════════════════════
# Infinite-scroll / large JSON payloads used to blow past MAX_PAYLOAD_SIZE
# and get a complete pass with zero inspection. Instead, we sample a
# bounded prefix and suffix of the RAW BYTES (never touching the full
# body, so memory stays bounded regardless of total payload size) and
# run the same keyword + NLP pipeline against that sample. This is not
# perfect coverage of a huge payload, but it means large dynamic
# responses are never entirely unfiltered.
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024      # hard cap before we stop trying to fully decode
SAMPLE_PREFIX_BYTES = 512 * 1024        # ~512KB from the start (headlines/titles/first posts)
SAMPLE_SUFFIX_BYTES = 256 * 1024        # ~256KB from the end (catches trailing chunks)


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
        init_db()
        print("[VIGILANT] Addon loaded. DB initialised. NLP model ready.")

        dns_thread = threading.Thread(target=tail_dnsmasq_log, daemon=True)
        dns_thread.start()
        print("[VIGILANT] DNS log tailing thread started")

    def tls_clienthello(self, data):
        """TLS ClientHello hook for transparent SNI domain logging with full decryption capability"""
        try:
            # Check if SNI filtering is enabled
            config = load_proxy_config()
            sni_filtering_enabled = config.get('sni_filtering_enabled', 'true').lower() == 'true'
            
            if not sni_filtering_enabled:
                # SNI tracking disabled, skip behavioral analysis
                return
            
            # 1. Direct attribute access for modern mitmproxy
            sni = data.sni

            # 2. Safely bypass internal Apple ecosystem traffic to prevent device lockups
            if sni and any(domain in sni for domain in ["apple.com", "icloud.com"]):
                data.ignore_connection = True
                return

            # 3. Use the verified modern mitmproxy peername path
            client_ip = data.context.client_conn.peername[0]

            if sni:
                # Log ALL SNI domains immediately to dashboard database
                self.log_to_dashboard(client_ip, sni)

                # NOTE: Removed `data.ignore_connection = True` from here.
                # This allows mitmproxy to step forward and complete the TLS handshake
                # using the trusted certificate you installed via AirDrop.

                clean_sni = sni.lstrip("www.")
                base = ".".join(clean_sni.split(".")[-2:])

                flagged, rpm_now, rpm_base = should_throttle(client_ip, sni)

                if flagged and client_ip not in throttled_clients:
                    throttled_clients.add(client_ip)
                    log_throttle(client_ip, sni, rpm_now, rpm_base, "TLS_THROTTLE_APPLIED")
                    apply_throttle(client_ip)
                    print(f"[VIGILANT] TLS DOOMSCROLL DETECTED {client_ip} @ {sni} "
                          f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

                social_domains = load_social_domains()
                if any(base in d for d in social_domains):
                    log_request(client_ip, sni, "(TLS_SNI)", "TLS", "Mobile_Bypass", False, [])
                    print(f"[VIGILANT] TLS SNI bypass logged: {client_ip} -> {sni}")

        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] TLS ClientHello: Failed to extract client IP or data structures: {e}")
        except Exception as e:
            print(f"[VIGILANT] TLS ClientHello global framework error: {e}")

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
                tfidf_category, tfidf_scores = tfidf_classifier.classify(domain_text, threshold=domain_threshold)
                
                if tfidf_category and tfidf_category.lower() in _LOGGABLE_CATEGORIES:
                    category = tfidf_category
                else:
                    category = "Productive"  # Default category for SNI logs to ensure database logging
            
            # Log the SNI domain request
            log_request(client_ip, sni, "(TLS_SNI)", "TLS", category, False, [])
            print(f"[VIGILANT] SNI logged to dashboard: {client_ip} -> {sni} [{category}]")
        except Exception as e:
            print(f"[VIGILANT] Failed to log SNI to dashboard: {e}")

    def request(self, flow: http.HTTPFlow):
        try:
            client_ip = flow.client_conn.peername[0]
        except (AttributeError, IndexError, TypeError) as e:
            print(f"[VIGILANT] Request: Failed to extract client IP from peername: {e}")
            return
        host      = flow.request.pretty_host

        # Whitelist bypass: asset subdomains (kept ahead of everything else - these
        # are infrastructure/CDN domains, not user-navigable content).
        if is_whitelisted(host):
            log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Educational", False, [])
            print(f"[VIGILANT] WHITELIST BYPASS (request): {host} -> {client_ip}")
            return

        try:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                keywords = [row[0] for row in cursor.fetchall()]
                conn.close()

            if keywords:
                decoded_url = urllib.parse.unquote(flow.request.pretty_url)
                req_body = ""

                if flow.request.content:
                    req_body = urllib.parse.unquote(flow.request.get_text(strict=False))

                combined_search_text = f"{decoded_url} {req_body}"

                matched = scan_text_for_keywords(combined_search_text, keywords)
                if matched:
                    print(f"[VIGILANT] INSTAGRAM KEYWORD BLOCKED: {matched} from {client_ip}")
                    log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [])
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

        clean_host = host.lstrip("www.")
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
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                    keywords = [row[0] for row in cursor.fetchall()]
                    conn.close()

                if keywords:
                    try:
                        request_body = flow.request.get_text(strict=False) if flow.request.content else ""
                    except Exception:
                        request_body = ""
                    # Use efficient token intersection for keyword detection (unified approach for all domains)
                    matched = scan_text_for_keywords(request_body, keywords)
                    if matched:
                        print(f"[VIGILANT] REQUEST KEYWORD BLOCKED: {matched} in request body from {host}")
                        log_request(client_ip, host, path, method, "Harmful", True, [])
                        flow.response = http.Response.make(
                            403,
                            render_block_page(host, "Harmful"),
                            {"Content-Type": "text/html"}
                        )
                        return
            except sqlite3.Error as e:
                print(f"[VIGILANT] Request body keyword blacklist check failed: {e}")

        flagged, rpm_now, rpm_base = should_throttle(client_ip, host)
        if flagged and client_ip not in throttled_clients:
            throttled_clients.add(client_ip)
            log_throttle(client_ip, host, rpm_now, rpm_base, "HTTP_THROTTLE_APPLIED")
            apply_throttle(client_ip)
            print(f"[VIGILANT] HTTP DOOMSCROLL DETECTED {client_ip} @ {host} "
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

        if is_whitelisted(host):
            log_request(client_ip, host, path, method, "Educational", False, [])
            print(f"[VIGILANT] WHITELIST BYPASS (response): {host} -> {client_ip}")
            return

        config = load_proxy_config()
        pinned_domains = config['pinned_domains']

        clean_host = host.lstrip("www.")
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
            log_request(client_ip, host, path, method, final_category, False, [])
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
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                    keywords = [row[0] for row in cursor.fetchall()]
                    conn.close()

                if keywords:
                    if clean:
                        # Use efficient token intersection for keyword detection
                        matched = scan_text_for_keywords(clean, keywords)
                    else:
                        matched = None
                    if matched:
                        print(f"[VIGILANT] RESPONSE KEYWORD BLOCKED: {matched} in {content_type} response from {host}")
                        log_request(client_ip, host, path, method, "Harmful", True, [])
                        flow.response = http.Response.make(
                            403,
                            render_block_page(host, "Harmful"),
                            {"Content-Type": "text/html"}
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
                render_block_page(host, category),
                {"Content-Type": "text/html"}
            )

addons = [VIGILANTAddon()]