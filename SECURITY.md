# Security Policy

AKHA XSS Scanner is intended for authorized security testing only. Run scans only against systems you own or where you have explicit permission.

## Supported Versions

The `main` branch and the latest tagged release receive fixes.

## Reporting Vulnerabilities

Please report security issues privately by opening a GitHub security advisory or by emailing the maintainer listed in `setup.py`.

Include:

- A clear description of the issue
- Reproduction steps
- Affected version or commit
- Impact and suggested mitigation, if known

Do not include live third-party targets unless you have permission to share them.

## Safe Testing Guidance

- Start with `--profile quick` on production targets.
- Use low `--threads` and `--rate-limit` values on WAF-protected sites.
- Avoid authenticated or destructive areas unless your authorization scope allows it.
- Prefer lab targets for heavy `--profile deep` testing.
