# Feedback and Contributions

qsag-core is an open research platform. Your feedback directly improves
AI agent security for everyone who uses this library.

---

## Report a Bypass or False Positive

If you find a payload that:
- **Gets through detection when it should be blocked** (bypass)
- **Gets blocked when it should be allowed** (false positive)

Please open a **[Bypass/False Positive Report](https://github.com/Neoxyber/qsag-core/issues/new?template=bypass_report.yml)**

Your report will:
1. Be reviewed within 7 days
2. If valid, a new pattern will be added
3. A new version will be released
4. `pip install --upgrade qsag-core` — you get the fix

---

## Add a New Attack Pattern

Found a new MCP poisoning technique, prompt injection variant, or
ghost agent pattern not covered by qsag-core?

1. Add the pattern to `POISONING_PATTERNS` in `qsag_core/scanner.py`
   or `INJECTION_PATTERNS` in `qsag_core/injection.py`
2. Include the source — CVE number, breach report URL, or research paper
3. Add a test in `tests/`
4. Open a pull request

Pattern format:
```python
(r"your_regex_pattern_here", PatternFamily.CATEGORY_NAME),
# Source: CVE-2025-XXXXX or https://link-to-breach-report
```

---

## Security Disclosures

If you find a vulnerability in qsag-core itself (not a detection gap):

**Email:** security@neoxyber.com

Please give us 90 days to fix before public disclosure.
We follow responsible disclosure.

---

## General Feedback

- **GitHub Issues:** github.com/Neoxyber/qsag-core/issues
- **Email:** contact@neoxyber.com
- **Security:** security@neoxyber.com

---

## How Patterns Are Sourced

Every pattern in qsag-core is sourced from a real breach, CVE, or
published research. We do not add patterns speculatively. If you
submit a pattern, please include the source.

Current sources include:
- Invariant Labs (2025) — WhatsApp MCP exfiltration
- GitHub MCP (2025) — private vulnerability report exposure
- Postmark (2025) — npm supply chain backdoor
- CVE-2025-6514 — mcp-remote RCE
- Anthropic mcp-server-git (2025) — triple CVE chain

---

*AIXYBER TECH LTD (trading as Neoxyber) — Company No. 16826340*
*MIT Licence — Open source for researchers, students, and developers*
