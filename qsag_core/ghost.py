"""
Ghost Agent Detection
Defends against OWASP ASI03 — Identity Abuse via unregistered agents.

MIT License — AIXYBER TECH LTD
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional

_ghost_log: List[Dict] = []


def is_ghost_attempt(api_key: str, registered_keys: List[str]) -> bool:
    """
    Check if an API key belongs to a registered agent.

    Args:
        api_key: The key presented by the agent
        registered_keys: List of valid registered keys

    Returns:
        True if this is a ghost (unregistered) agent attempt

    Example:
        registered = ["qsag_abc123", "qsag_def456"]
        is_ghost_attempt("qsag_unknown", registered)  # True
        is_ghost_attempt("qsag_abc123", registered)   # False
    """
    return api_key not in registered_keys


def log_ghost(api_key: str, action: str, ip: str = "unknown",
              user_agent: str = "unknown") -> Dict:
    """
    Log a ghost agent interception attempt.

    Args:
        api_key: The key that was rejected
        action: The action the ghost agent attempted
        ip: Source IP address
        user_agent: HTTP User-Agent string

    Returns:
        Ghost attempt record with fingerprint and timestamp
    """
    fingerprint = hashlib.sha256(api_key.encode()).hexdigest()[:16]

    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "key_fingerprint": fingerprint,
        "action_attempted": action,
        "source_ip": ip,
        "user_agent": user_agent,
        "status": "INTERCEPTED",
        "owasp": "ASI03 — Identity Abuse",
    }

    _ghost_log.append(record)
    return record


def get_ghost_log() -> List[Dict]:
    """Return all logged ghost agent attempts."""
    return list(_ghost_log)


def get_ghost_stats() -> Dict:
    """Return summary statistics of ghost agent attempts."""
    return {
        "total_attempts": len(_ghost_log),
        "unique_ips": len(set(e["source_ip"] for e in _ghost_log)),
        "unique_fingerprints": len(set(e["key_fingerprint"] for e in _ghost_log)),
    }
