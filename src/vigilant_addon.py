import re
import time
import sqlite3
import threading
import subprocess
import urllib.parse
from collections import defaultdict, deque, Counter
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

    flagged = (rpm_now > (rpm_base * network_velocity_threshold)) or (rpm_now > physical_scroll_threshold)
    return flagged, rpm_now, rpm_base


# ══════════════════════════════════════════════════════════════════
# ─── FIX #1: Context-Aware Text Normalization & Keyword Engine ─────
# ══════════════════════════════════════════════════════════════════
#
# The old normalize_text() stripped ALL whitespace and punctuation from
# the entire text before matching, which silently glued adjacent words
# together ("shows. Some" -> "showsome"). Any keyword that happened to
# be a substring spanning that seam ("owso", etc.) or that simply
# matched a longer fused word would trigger a false block.
#
# The fix splits normalization into two independent representations:
#
#   1. normalize_words()   -> preserves word boundaries (spaces are kept
#                              as single separators). Used for real
#                              whole-word / whole-phrase matching.
#   2. collapse_stuffed()  -> targets ONLY the specific obfuscation
#                              pattern of single characters chained by
#                              one separator each (b.r.a.i.n.r.o.t,
#                              b-r-a-i-n-r-o-t, b_r_a_i_n_r_o_t). Normal
#                              prose essentially never contains 4+
#                              consecutive one-letter "words", so this
#                              pattern is a strong, low-false-positive
#                              signal of deliberate obfuscation. It does
#                              NOT touch ordinary multi-letter words, so
#                              "shows. Some" stays as two separate words.

def normalize_words(text: str) -> str:
    """
    Word-boundary-preserving normalization: lowercase, collapse all
    punctuation/whitespace runs to a single space. Adjacent real words
    remain distinct tokens (never fused), so keyword matching can use
    \b...\b (whole word/phrase) checks safely.
    """
    if not text:
        return ""
    lowered = text.lower()
    collapsed = re.sub(r'[^a-z0-9]+', ' ', lowered)
    return re.sub(r'\s+', ' ', collapsed).strip()


_STUFFED_PATTERN = re.compile(r'(?:[a-z0-9][^a-z0-9\s]){3,}[a-z0-9]', re.IGNORECASE)

def collapse_stuffed_segments(text: str):
    """
    Returns the list of joined tokens produced ONLY from character-stuffed
    bypass runs (>=4 single characters each separated by exactly one
    non-alphanumeric character), e.g. 'b.r.a.i.n.r.o.t' -> ['brainrot'].

    Deliberately narrow scope: this pattern requires 4+ single-character
    "words" chained in a row, which essentially never occurs in ordinary
    prose, HTML, or JSON. Crucially, we return ONLY the matched/collapsed
    segments (never the whole document glued together), so a later
    substring check against these segments can't accidentally match a
    short keyword that happens to appear inside an ordinary word (e.g.
    keyword "ass" inside "class" never matches here, because "class"
    isn't a stuffed run and so never enters this segment list).
    """
    if not text:
        return []
    lowered = text.lower()
    segments = []
    for match in _STUFFED_PATTERN.finditer(lowered):
        segments.append(re.sub(r'[^a-z0-9]', '', match.group(0)))
    return segments


def find_keyword_hits(raw_text: str, keyword: str):
    """
    Returns (hit_count, via_stuffed_bypass: bool) for a single keyword
    against a piece of raw (unnormalized) text.

    - Whole-word/phrase matches are counted against normalize_words()
      output using \b boundaries, so 'brainrot' does not match inside
      'nobrainrotator' but does match 'BRAIN-ROT' after normalization.
    - A separate check looks ONLY at segments produced by
      collapse_stuffed_segments() - i.e. text already identified as a
      deliberately obfuscated single-character-chained run - and checks
      whether the glued keyword appears in one of those segments.
      Restricting to actual stuffed segments (instead of the whole
      document) prevents short keywords from matching as an incidental
      substring of an unrelated, non-obfuscated word.
    """
    keyword_norm = normalize_words(keyword)
    if not keyword_norm:
        return 0, False

    words_text = normalize_words(raw_text)
    pattern = r'\b' + re.escape(keyword_norm).replace(r'\ ', r'\s+') + r'\b'
    hits = len(re.findall(pattern, words_text))

    keyword_glued = keyword_norm.replace(' ', '')
    via_stuffed = False
    if keyword_glued and hits == 0:
        segments = collapse_stuffed_segments(raw_text)
        via_stuffed = any(keyword_glued in seg for seg in segments)

    return hits, via_stuffed


# ══════════════════════════════════════════════════════════════════
# ─── FIX #2: Separate URL vs. Body Keyword Scanning Strategies ─────
# ══════════════════════════════════════════════════════════════════
#
# A keyword typed into a URL/query string is a deliberate, low-noise
# signal (short string, user- or app-authored) -> a single hit is
# sufficient to act on. A keyword buried once in a 2,000-word response
# body is comparatively weak evidence and needs corroboration (repeat
# occurrences, or a stuffed-bypass hit, which is inherently suspicious
# regardless of count).

def scan_url_keywords(url_text: str, path_text: str, keywords):
    """
    Strict scan for URL/path context: ANY whole-word hit, or ANY
    stuffed-bypass hit, is sufficient to flag - URLs are short and
    deliberately constructed, so a single match is meaningful evidence.
    Returns the first matched keyword, or None.
    """
    for keyword in keywords:
        hits, via_stuffed = find_keyword_hits(url_text, keyword)
        if hits == 0:
            hits, via_stuffed = find_keyword_hits(path_text, keyword)
        if hits > 0 or via_stuffed:
            return keyword
    return None


# Body keyword hits need corroboration before blocking outright, since
# a single passive mention deep in a long article is weak evidence.
BODY_MIN_OCCURRENCES = 2

def scan_body_keywords(body_text: str, keywords):
    """
    Lenient scan for response-body context: requires either
    BODY_MIN_OCCURRENCES+ whole-word hits, or any stuffed-bypass hit
    (obfuscation is suspicious on its own regardless of frequency).
    Returns the first matched keyword, or None.
    """
    for keyword in keywords:
        hits, via_stuffed = find_keyword_hits(body_text, keyword)
        if via_stuffed or hits >= BODY_MIN_OCCURRENCES:
            return keyword
    return None


# ══════════════════════════════════════════════════════════════════
# ─── FIX #3: Proportional Density Scoring + Override Guards ────────
# ══════════════════════════════════════════════════════════════════
MIN_DISTINCT_CATEGORY_KEYWORDS = 2   # need >=2 distinct keywords from a category...
MIN_CATEGORY_DENSITY = 0.008          # ...AND >=0.8% of all content tokens, to shift category
PROTECTED_HINT_HARMFUL_DISTINCT = 4  # stricter bar to override an Educational/Productive domain hint
PROTECTED_HINT_HARMFUL_DENSITY = 0.02


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
        tokens   = [t.lemma_.lower() for t in doc
                    if not t.is_stop and t.is_alpha] if doc else []
    else:
        doc = None
        entities = []
        tokens = normalize_words(text).split() if len(text) >= 20 else []

    total_tokens = max(len(tokens), 1)
    token_counts = Counter(tokens)

    # Density-based scoring: score = (occurrences of category keywords) / (total tokens),
    # rather than a naive set-intersection size, so a 2,000-word article that happens to
    # contain one incidental "shocking" doesn't score the same as a page saturated with
    # trigger words.
    scores = {}
    distinct_matches = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        matched_keywords = set(token_counts) & keywords
        occurrence_count = sum(token_counts[k] for k in matched_keywords)
        scores[category] = occurrence_count / total_tokens
        distinct_matches[category] = len(matched_keywords)

    # NER weighting nudges density scores slightly rather than adding large flat integers,
    # so a handful of named entities can't singlehandedly flip the category.
    if doc and doc.ents:
        for ent in doc.ents:
            if ent.label_ in ["LAW", "WORK_OF_ART", "EVENT", "ORG", "PERSON", "GPE"]:
                scores["Educational"] = scores.get("Educational", 0) + (1 / total_tokens)
            elif ent.label_ in ["DATE", "TIME", "CARDINAL", "ORDINAL"]:
                scores["Productive"] = scores.get("Productive", 0) + (1 / total_tokens)

    if hint_category:
        # A confirmed domain hint is strong, deliberate admin input - give it a
        # substantial density boost so it firmly anchors the category unless a
        # LOT of contrary evidence shows up.
        scores[hint_category] = scores.get(hint_category, 0) + (hint_score / total_tokens) + 0.05

    # ── Minimum threshold gate ──
    # A category (other than the hint category) may only "win" if it clears BOTH
    # a minimum distinct-keyword count and a minimum density. This prevents 2-3
    # rogue keyword tokens scattered through a long educational page from
    # dragging the whole page into Distracting/Harmful.
    def clears_threshold(category):
        return (distinct_matches.get(category, 0) >= MIN_DISTINCT_CATEGORY_KEYWORDS
                and scores.get(category, 0) >= MIN_CATEGORY_DENSITY)

    harmful_score = scores.get("Harmful", 0)
    if harmful_score > 0:
        utility_terms = {"git", "code", "dev", "assets", "static", "github", "google", "microsoft", "apple"}
        has_utility_context = any(term in token_counts for term in utility_terms)

        if protected_hint:
            # Strict override guard: an Educational/Productive domain hint can only be
            # overridden by Harmful if the evidence is overwhelming (many distinct
            # keywords AND high density) - a few rogue words are not enough.
            overwhelming = (distinct_matches.get("Harmful", 0) >= PROTECTED_HINT_HARMFUL_DISTINCT
                            and harmful_score >= PROTECTED_HINT_HARMFUL_DENSITY)
            if not overwhelming:
                return hint_category, entities
            if has_utility_context:
                return "Educational", entities
            return "Harmful", entities

        if not clears_threshold("Harmful"):
            # Doesn't clear the minimum bar - fall through to normal scoring below
            # instead of auto-flagging Harmful off a single stray keyword.
            scores["Harmful"] = 0
        elif has_utility_context:
            return "Educational", entities
        else:
            return "Harmful", entities

    # For non-Harmful categories, likewise require the minimum threshold before
    # leaving Uncategorized/the hinted category.
    eligible = {c: s for c, s in scores.items()
                if c == hint_category or clears_threshold(c)}

    if not eligible:
        return (hint_category if hint_category else "Uncategorized"), entities

    best = max(eligible, key=eligible.get)
    if eligible[best] <= 0:
        return (hint_category if hint_category else "Uncategorized"), entities

    return best, entities


# ─── Traffic Control Throttling ───────────────────────────────────────
def apply_throttle(client_ip):
    """Apply Linux tc traffic control to throttle client bandwidth"""
    config = load_proxy_config()
    throttle_rate = config['throttle_rate']

    try:
        subprocess.run(
            ["tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb"],
            check=False, capture_output=True
        )

        subprocess.run(
            ["tc", "class", "add", "dev", "eth0", "parent", "1:", "classid", "1:10",
             "htb", "rate", throttle_rate, "ceil", throttle_rate],
            check=False, capture_output=True
        )

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

    def tls_clienthello(self, layer):
        """TLS ClientHello hook for mobile SNI fallback tracking"""
        try:
            if hasattr(layer, "context") and hasattr(layer.context, "client_conn"):
                client_ip = layer.context.client_conn.peername[0]
            else:
                print(f"[VIGILANT] TLS ClientHello: Unable to determine client IP, skipping SNI tracking")
                return

            sni = layer.client_hello.sni if hasattr(layer, "client_hello") else None

            if sni:
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
        except AttributeError as e:
            print(f"[VIGILANT] TLS ClientHello attribute error: {e}")
        except Exception as e:
            print(f"[VIGILANT] TLS ClientHello error: {e}")

    def request(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0]
        host      = flow.request.pretty_host

        # Whitelist bypass: asset subdomains (kept ahead of everything else - these
        # are infrastructure/CDN domains, not user-navigable content).
        if is_whitelisted(host):
            log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Educational", False, [])
            print(f"[VIGILANT] WHITELIST BYPASS (request): {host} -> {client_ip}")
            return

        # ══════════════════════════════════════════════════════════════
        # FIX #3 (bypass sealing): Strict keyword blacklist now runs BEFORE
        # the pinned-domain TLS-passthrough check. Previously, any domain
        # on the pinned list (e.g. instagram.com, tiktok.com) skipped ALL
        # filtering unconditionally - which meant a blacklisted term could
        # simply be routed through query params on those apps and sail
        # through untouched. Now: if a blacklisted keyword is explicitly
        # present in the raw URL/path, the request is dropped immediately,
        # regardless of whether the domain is pinned.
        # ══════════════════════════════════════════════════════════════
        try:
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.execute("SELECT keyword FROM keyword_blacklist")
                keywords = [row[0] for row in cursor.fetchall()]
                conn.close()

            if keywords:
                try:
                    decoded_url = urllib.parse.unquote(flow.request.pretty_url)
                except Exception:
                    decoded_url = flow.request.pretty_url

                path_text = flow.request.path[:2000]

                matched = scan_url_keywords(decoded_url, path_text, keywords)
                if matched:
                    print(f"[VIGILANT] KEYWORD BLOCKED (pre-passthrough): {matched} in {decoded_url[:60]} from {client_ip}")
                    log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [])
                    flow.response = http.Response.make(
                        403,
                        render_block_page(host, "Harmful"),
                        {"Content-Type": "text/html"}
                    )
                    return
        except sqlite3.Error as e:
            print(f"[VIGILANT] Keyword blacklist check failed: {e}")

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

                    matched = scan_body_keywords(request_body, keywords)
                    if matched:
                        print(f"[VIGILANT] KEYWORD BLOCKED (request body): {matched} from {client_ip}")
                        log_request(client_ip, host, flow.request.path[:120], flow.request.method, "Harmful", True, [])
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
        client_ip    = flow.client_conn.peername[0]
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
                    try:
                        request_body = flow.request.get_text(strict=False) if flow.request.content else ""
                    except Exception:
                        request_body = ""
                    if "google.com" in host:
                        matched = scan_url_keywords(request_body, "", keywords)
                    else:
                        matched = scan_body_keywords(request_body, keywords)
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