"""
qsag-core — Open Source AI Agent Security Toolkit
MCP Tool Poisoning Scanner | Ghost Agent Detection | Prompt Injection Patterns

OWASP Top 10 for Agentic Applications 2026 — ASI01, ASI02, ASI03, ASI04, ASI07

MIT License
AIXYBER TECH LTD (trading as Neoxyber) — London, UK
Company Number: 16826340
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
__version__ = "0.1.6"
__author__ = "AIXYBER TECH LTD"
__license__ = "MIT"

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
