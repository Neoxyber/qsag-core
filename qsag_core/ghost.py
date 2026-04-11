"""
Ghost Agent Detection
Defends against OWASP ASI03 — Identity Abuse via unregistered agents.

MIT License — AIXYBER TECH LTD
"""

import hashlib
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, List, Optional, Set

# ── Thread-safe ghost log ─────────────────────────────────────────────────────
# Capped at 10,000 entries to prevent unbounded memory growth.
# For production persistence replace with Redis or database backend.

_MAX_LOG_SIZE = 10_000
_ghost_log: deque = deque(maxlen=_MAX_LOG_SIZE)
_ghost_log_lock = Lock()


def is_ghost_attempt(api_key: str, registered_keys) -> bool:
    """
    Check if an API key belongs to a registered agent.

    O(1) lookup — pass a set for best performance. Also accepts list
    (will be converted internally) for backwards compatibility.

    Args:
        api_key:         The key presented by the agent
        registered_keys: Set or list of valid registered keys

    Returns:
        True if this is a ghost (unregistered) agent attempt

    Example:
        registered = {"qsag_abc123", "qsag_def456"}
        is_ghost_attempt("qsag_unknown", registered)  # True
        is_ghost_attempt("qsag_abc123", registered)   # False
    """
    if not isinstance(registered_keys, (set, frozenset)):
        registered_keys = set(registered_keys)
    return api_key not in registered_keys


def log_ghost(api_key: str, action: str, ip: str = "unknown",
              user_agent: str = "unknown") -> Dict:
    """
    Log a ghost agent interception attempt (thread-safe).

    Args:
        api_key:    The key that was rejected
        action:     The action the ghost agent attempted
        ip:         Source IP address
        user_agent: HTTP User-Agent string

    Returns:
        Ghost attempt record with fingerprint and timestamp
    """
    fingerprint = hashlib.sha256(api_key.encode()).hexdigest()[:16]

    record = {
        # datetime.utcnow() deprecated in Python 3.12 — use timezone-aware now()
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "key_fingerprint": fingerprint,
        "action_attempted": action,
        "source_ip": ip,
        "user_agent": user_agent[:200],      # cap UA length
        "status": "INTERCEPTED",
        "owasp": "ASI03 — Identity Abuse",
    }

    with _ghost_log_lock:
        _ghost_log.append(record)  # deque(maxlen) auto-evicts oldest

    return record


def get_ghost_log() -> List[Dict]:
    """Return all logged ghost agent attempts (thread-safe snapshot)."""
    with _ghost_log_lock:
        return list(_ghost_log)


def get_ghost_stats() -> Dict:
    """Return summary statistics of ghost agent attempts (thread-safe)."""
    with _ghost_log_lock:
        log_snapshot = list(_ghost_log)

    return {
        "total_attempts": len(log_snapshot),
        "unique_ips": len({e["source_ip"] for e in log_snapshot}),
        "unique_fingerprints": len({e["key_fingerprint"] for e in log_snapshot}),
        "log_capacity": _MAX_LOG_SIZE,
        "log_utilisation_pct": round(len(log_snapshot) / _MAX_LOG_SIZE * 100, 1),
    }


def clear_ghost_log() -> int:
    """Clear the ghost log. Returns number of entries removed."""
    with _ghost_log_lock:
        count = len(_ghost_log)
        _ghost_log.clear()
    return count
