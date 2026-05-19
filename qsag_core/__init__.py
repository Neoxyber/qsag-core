"""
qsag-core — early-stage AI-agent runtime detection library.

Pattern-based scanners for MCP tool poisoning, prompt injection, ghost agents,
exfiltration, jailbreaks, and memory poisoning. Coverage maps to OWASP Top 10
for Agentic Applications 2026 — ASI01, ASI03, ASI05, ASI06, ASI07.

Open research under active development by a single maintainer. Not a
production-ready security product. See README.md for the full status section
and scope boundaries.

Stewarded by AIXYBER TECH LTD (trading as Neoxyber).
Company Number: 16826340 — Registered in England and Wales.
ICO Registration: ZC071900.
Apache License, Version 2.0.
https://github.com/Neoxyber/qsag-core
"""

from .scanner import scan_tool, scan_tools, POISONING_PATTERNS
from .injection import scan_injection, INJECTION_PATTERNS
from .ghost import (
    is_ghost_attempt,
    log_ghost,
    get_ghost_log,
    get_ghost_stats,
    clear_ghost_log,
)

# Version must match setup.py exactly — checked by CI
__version__ = "0.2.2"
__author__ = "AIXYBER TECH LTD"
__license__ = "Apache-2.0"

__all__ = [
    # Scanner
    "scan_tool",
    "scan_tools",
    "POISONING_PATTERNS",
    # Injection
    "scan_injection",
    "INJECTION_PATTERNS",
    # Ghost
    "is_ghost_attempt",
    "log_ghost",
    "get_ghost_log",
    "get_ghost_stats",
    "clear_ghost_log",
]
