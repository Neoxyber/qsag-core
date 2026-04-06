"""
qsag-core — Open Source AI Agent Security Toolkit
MCP Tool Poisoning Scanner | Ghost Agent Detection | Prompt Injection Patterns
OWASP Top 10 for Agentic Applications 2026 — ASI01, ASI03, ASI04, ASI07

MIT License
AIXYBER TECH LTD (trading as Neoxyber) — London, UK
Company Number: 16826340
https://github.com/Neoxyber/qsag-core
"""

from .scanner import scan_tool, scan_tools, POISONING_PATTERNS
from .injection import scan_injection, INJECTION_PATTERNS
from .ghost import is_ghost_attempt, log_ghost

__version__ = "0.1.0"
__author__ = "AIXYBER TECH LTD"
__license__ = "MIT"

__all__ = [
    "scan_tool",
    "scan_tools",
    "scan_injection",
    "is_ghost_attempt",
    "POISONING_PATTERNS",
    "INJECTION_PATTERNS",
]
