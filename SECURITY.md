# Security Policy

WooSecureProxy is a security boundary in front of the WooCommerce REST API.
Vulnerabilities in it expose orders and customer data — reports are treated
as high priority.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Preferred: use GitHub's private vulnerability reporting on this repository
(Security → Advisories → "Report a vulnerability").

Alternative: email the maintainer listed in `composer.json`/the plugin
header (Abdullah Alfrahi — see the Author URI in `woo-secure-proxy.php`).

Please include:

- Affected version (git tag or commit)
- A description of the vulnerability and its impact
- Minimal reproduction steps or a proof of concept
- Whether you believe the issue is exploitable pre- or post-authentication

You will receive an acknowledgment within 72 hours. We aim to ship a fix or
mitigation within 14 days for critical issues and 30 days otherwise, and we
will credit reporters in the release notes unless you prefer to stay
anonymous.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x (main branch) | Yes |
| Anything older | No |

## Security Model Summary

- The consumer key/secret never leave the server; clients authenticate with
  `HMAC-SHA256(timestamp + nonce + body)` under `PROXY_SECRET`, plus replay
  protection and per-action rate limits.
- Customer sessions are short-lived JWTs (60 min, `aud = woosecureproxy`,
  revocable via `jti` transients), refreshable via 30-day refresh tokens.
- All third-party code is pinned via `composer.lock`; CI runs
  `composer audit --locked`, PHPStan (level 6) and WPCS on every change.
- Release zips prefix the vendored dependency tree with php-scoper
  (see `docs/DEPENDENCIES.md`).

## Secret Handling Rules for Contributors

- Never commit `PROXY_SECRET`, consumer credentials, tokens, or access
  tokens — in code, tests, fixtures, logs, or documentation.
- `Logger` output must contain only hashes/IDs, never raw secrets or JWTs.
- The settings page must never render a usable generated secret.
