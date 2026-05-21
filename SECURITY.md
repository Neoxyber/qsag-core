# Security Policy

## Reporting a vulnerability

Email **`security@aixybertech.com`** rather than opening a public issue.

For sensitive disclosures, encrypt with the maintainer's PGP key:

```bash
gpg --keyserver keys.openpgp.org --recv-keys A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B
```

Fingerprint: `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`

We aim to acknowledge reports within a few working days. We ask for 90 days before public disclosure where possible.

## Verifying package authenticity

Releases on PyPI use Trusted Publishing (OIDC) with cryptographic attestations (PEP 740). Verify the repository and workflow at `https://pypi.org/project/qsag-core/#history` → Attestations.

If the attestation is missing or the repository does not match `https://github.com/Neoxyber/qsag-core`, do not use the package and email `security@aixybertech.com`.

## Scope

In scope:
- Vulnerabilities in `qsag-core` Python code
- Supply-chain issues affecting the PyPI package
- Detection bypasses where a documented attack class is missed

Out of scope (use regular issues instead):
- False positives or detection-coverage gaps
