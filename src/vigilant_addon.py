import re
import time
import sqlite3
import threading
from collections import defaultdict, deque
from mitmproxy import http
import spacy

# ─── Configuration ────────────────────────────────────────────────
DB_PATH            = "/home/vigilant_admin/vigilant/logs/vigilant.db"
VELOCITY_WINDOW    = 60
VELOCITY_THRESHOLD = 1.5
MIN_REQUESTS_BASELINE = 10
THROTTLE_RATE      = "512kbit"

SOCIAL_DOMAINS = {
    "facebook.com", "www.facebook.com",
    "twitter.com", "x.com", "www.x.com",
    "tiktok.com", "www.tiktok.com",
    "instagram.com", "www.instagram.com",
    "reddit.com", "www.reddit.com",
    "youtube.com", "www.youtube.com",
}

DOMAIN_HINTS = {
    "Educational":  {"wikipedia.org", "khanacademy.org", "coursera.org",
                     "edx.org", "scholar.google.com", "researchgate.net",
                     "academia.edu", "jstor.org", "pubmed.ncbi.nlm.nih.gov",
                     "stackoverflow.com", "docs.python.org", "arxiv.org"},
    "Productive":   {"github.com", "gitlab.com", "notion.so", "trello.com",
                     "slack.com", "linear.app", "jira.atlassian.com",
                     "drive.google.com", "docs.google.com", "sheets.google.com"},
    "Distracting":  {"reddit.com", "twitter.com", "x.com", "tiktok.com",
                     "instagram.com", "facebook.com", "youtube.com",
                     "twitch.tv", "9gag.com", "buzzfeed.com"},
    "Harmful":      set(),
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
    conn.commit()
    conn.close()

db_lock = threading.Lock()

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
    base = ".".join(host.lstrip("www.").split(".")[-2:])
    if not any(base in d for d in SOCIAL_DOMAINS):
        return False, 0, 0
    rpm_now, rpm_base = compute_velocity(client_ip)
    if session_totals[client_ip] < MIN_REQUESTS_BASELINE:
        return False, rpm_now, rpm_base
    flagged = rpm_now > (rpm_base * VELOCITY_THRESHOLD)
    return flagged, rpm_now, rpm_base

# ─── NLP Categorizer ──────────────────────────────────────────────
def get_domain_hint(host):
    clean = host.lstrip("www.")
    for category, domains in DOMAIN_HINTS.items():
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

    if scores.get("Harmful", 0) > 0:
        return "Harmful", entities

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "Uncategorized", entities

    return best, entities

# ─── mitmproxy Addon ──────────────────────────────────────────────
class VIGILANTAddon:

    def __init__(self):
        init_db()
        print("[VIGILANT] Addon loaded. DB initialised. NLP model ready.")

    def request(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0]
        host      = flow.request.pretty_host
        flagged, rpm_now, rpm_base = should_throttle(client_ip, host)
        if flagged and client_ip not in throttled_clients:
            throttled_clients.add(client_ip)
            log_throttle(client_ip, host, rpm_now, rpm_base, "THROTTLE_APPLIED")
            print(f"[VIGILANT] DOOMSCROLL DETECTED {client_ip} @ {host} "
                  f"RPM={rpm_now:.1f} baseline={rpm_base:.1f}")

    def response(self, flow: http.HTTPFlow):
        client_ip    = flow.client_conn.peername[0]
        host         = flow.request.pretty_host
        path         = flow.request.path[:120]
        method       = flow.request.method
        content_type = flow.response.headers.get("content-type", "")

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
