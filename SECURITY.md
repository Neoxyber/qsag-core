# Security Policy

## Reporting a Vulnerability

**Email:** security@neoxyber.com

Please do not open a public GitHub issue for security vulnerabilities.

We follow responsible disclosure:
- Report the vulnerability to security@neoxyber.com
- We will acknowledge within 48 hours
- We will investigate and respond within 14 days
- We will release a fix and credit you (unless you prefer anonymity)
- We ask for 90 days before public disclosure

## Actively Exploited Vulnerabilities

In accordance with Article 24 of the EU Cyber Resilience Act (CRA),
AIXYBER TECH LTD will notify relevant cybersecurity authorities of any
actively exploited vulnerabilities discovered in qsag-core from
11 September 2026 onwards.

## Scope

This policy covers:
- Detection bypass vulnerabilities in qsag-core pattern matching
- Security vulnerabilities in qsag-core Python code
- Supply chain issues affecting the qsag-core package on PyPI

This policy does not cover:
- False positives or false negatives in pattern detection (use GitHub Issues)
- The Neoxyber Q-SAG platform (separate disclosure: security@neoxyber.com)

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ Yes |
| < 0.1.0 | ❌ No |

## Verifying Package Authenticity

Every release of qsag-core is published using PyPI Trusted Publishing
and includes a cryptographic attestation (PEP 740) proving the package
was built from the Neoxyber/qsag-core repository via the publish.yml
workflow. No API tokens are stored anywhere in the pipeline.

**How to verify you have the authentic package:**

```bash
# Install the verification tool
pip install pypi-attestations

# Verify the package attestation
python -m pypi_attestations verify \
  --repository Neoxyber/qsag-core \
  qsag_core-0.1.0-py3-none-any.whl
```

Or check online at:
https://pypi.org/project/qsag-core/#history
Click any release → scroll to "Attestations" → verify Repository matches
`https://github.com/Neoxyber/qsag-core`

**What to look for:**
- Publisher: GitHub Actions
- Repository: Neoxyber/qsag-core
- Workflow: publish.yml

If any of these do not match, do not use the package and report to
security@neoxyber.com immediately.

## Cybersecurity Policy (CRA Article 24)

AIXYBER TECH LTD maintains the following cybersecurity practices for qsag-core:

- All releases published via PyPI Trusted Publishing (OIDC) — no stored API tokens
- All releases include cryptographic attestations (PEP 740)
- Dependencies monitored via GitHub Dependabot
- Tests run against Python 3.9, 3.10, 3.11, 3.12 on every commit
- Vulnerability reports acknowledged within 48 hours

*AIXYBER TECH LTD — Company No. 16826340 — Registered in England and Wales*
*ICO Reference: ZC071900*
