"""Dynamic Traffic Profiler (PFR) — sliding-window per-(client_ip, host) profiling.

Tracks a rolling 10-request window of (timestamp, payload_bytes) per
(client_ip, clean_host) and classifies each host's behavior as:

    PASSIVE_MEDIA      — long-form video/audio streaming; pause engagement timer
    INTERACTIVE_FEED   — short-form feed scrolling; tick engagement timer
    STANDARD_WEB       — normal browsing; run the standard engagement path

Classification honors per-domain policy overrides stored in the
`domain_behavior_policies` table ('auto', 'enforce_doomscroll', 'exempt_media').
"""

import time
import threading
from collections import defaultdict, deque

WINDOW_SIZE = 10
MIN_SAMPLES_FOR_CLASSIFY = 3
PASSIVE_IAT_SECONDS = 8.0
INTERACTIVE_IAT_SECONDS = 3.5
PASSIVE_MEDIAN_BYTES = 500 * 1024  # 500 KB
INTERACTIVE_REQ_IN_60S = 15
PRUNE_IDLE_SECONDS = 600  # 10 minutes

# (client_ip, clean_host) -> deque of (timestamp, payload_bytes)
TRAFFIC_WINDOWS = defaultdict(deque)
_windows_lock = threading.Lock()


def record_response(client_ip: str, clean_host: str, payload_bytes: int) -> None:
    """Push a response payload observation into the rolling window."""
    if not client_ip or not clean_host:
        return
    with _windows_lock:
        dq = TRAFFIC_WINDOWS[(client_ip, clean_host)]
        dq.append((time.time(), int(payload_bytes)))
        while len(dq) > WINDOW_SIZE:
            dq.popleft()


def _median(values) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def _average_interarrival(entries) -> float:
    """Mean gap in seconds between consecutive requests in the window."""
    if len(entries) < 2:
        return 0.0
    timestamps = [e[0] for e in entries]
    gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    if not gaps:
        return 0.0
    return sum(gaps) / len(gaps)


def _requests_in_last_60s(client_ip: str, clean_host: str, now: float) -> int:
    dq = TRAFFIC_WINDOWS.get((client_ip, clean_host))
    if not dq:
        return 0
    return sum(1 for (ts, _) in dq if now - ts <= 60.0)


def evaluate_session_behavior(client_ip: str, clean_host: str) -> str:
    """Classify the current session behavior for a (client_ip, clean_host) pair."""
    # Lazy import avoids a circular import at module-load time: vigilant_addon
    # imports profiler, and profiler needs vigilant_addon's DB helpers only at
    # runtime once the addon module is fully loaded.
    from vigilant_addon import get_domain_behavior_policy

    policy = get_domain_behavior_policy(clean_host)
    if policy == "exempt_media":
        return "PASSIVE_MEDIA"
    if policy == "enforce_doomscroll":
        return "INTERACTIVE_FEED"

    # policy == "auto" — use the sliding-window metrics.
    with _windows_lock:
        entries = list(TRAFFIC_WINDOWS.get((client_ip, clean_host), []))

    if len(entries) < MIN_SAMPLES_FOR_CLASSIFY:
        return "STANDARD_WEB"

    iat = _average_interarrival(entries)
    median_payload = _median([e[1] for e in entries])
    now = time.time()
    recent_count = _requests_in_last_60s(client_ip, clean_host, now)

    if iat > PASSIVE_IAT_SECONDS and median_payload > PASSIVE_MEDIAN_BYTES:
        return "PASSIVE_MEDIA"

    if iat < INTERACTIVE_IAT_SECONDS and recent_count > INTERACTIVE_REQ_IN_60S:
        return "INTERACTIVE_FEED"

    return "STANDARD_WEB"


def cleanup_stale_traffic_windows(now: float = None) -> None:
    """Prune window entries that have been idle beyond PRUNE_IDLE_SECONDS to
    prevent unbounded memory growth over long uptimes."""
    now = now if now is not None else time.time()
    cutoff = now - PRUNE_IDLE_SECONDS
    with _windows_lock:
        stale = [
            key
            for key, dq in TRAFFIC_WINDOWS.items()
            if not dq or dq[-1][0] < cutoff
        ]
        for key in stale:
            del TRAFFIC_WINDOWS[key]
