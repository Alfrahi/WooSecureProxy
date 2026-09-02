# Dependency & Supply-Chain Policy

## Runtime dependency surface

Exactly one production dependency: `firebase/php-jwt` (pinned `^7.0`).
Everything else in `composer.json` is dev-only.

- **Lock file is law.** `composer.lock` is committed; installs use the lock
  (`composer install`), CI runs `composer audit --locked`. Update PRs come
  from Dependabot (`.github/dependabot.yml`, weekly, dev tooling grouped).
- **PHP floor is 8.0** (matching `firebase/php-jwt`, the README badge, and
  the plugin header). The CI matrix covers 8.0–8.3.
- **CVE triage history:** CVE-2025-45769 (php-jwt < 7.0.0, weak-key
  acceptance, low severity) was fixed by upgrading to v7. Note that even on
  v6 the plugin was not exploitable through this advisory: `PROXY_SECRET` is
  enforced at ≥ 32 characters before any JWT is issued or validated.

## Vendor bundling in release zips (prefixing decision)

**Decision: ship `vendor/` (production-only) prefixed by php-scoper.**
Reasoning:

1. WordPress has no dependency isolation. If any other active plugin bundles
   `firebase/php-jwt`, whichever version loads first wins, and the other
   plugin (or this one) executes on an API it was never tested against —
   including a v6/v7 mismatch after this pin.
2. php-scoper rewrites `Firebase\JWT\*` to `WooSecureProxy\Vendor\Firebase\JWT\*`
   inside the shipped `vendor/`, eliminating the collision class entirely.
3. The plugin's own classes keep their `WooSecureProxy\` namespace untouched
   (only the vendored dependency tree is prefixed).
4. A pre-scoped `vendor/` is committed into the *release zip* shape, not into
   the git repo — git keeps the unprefixed `vendor/` on the standard
   autoloader so tests, PHPStan and PHPCS analyse the real dependency code.

### Build procedure

```bash
# One-time tool fetch (CI does this too)
curl -fsSL -o tools/php-scoper.phar \
  https://github.com/humbug/php-scoper/releases/latest/download/php-scoper.phar

# Produce installable plugin zip at dist/woo-secure-proxy.zip
bin/build-release.sh
```

`bin/build-release.sh` performs:
`composer install --no-dev` in a clean copy → php-scoper add-prefix → dump
autoloader in the scoped tree → zip only the runtime files
(`woo-secure-proxy.php`, `uninstall.php`, `src/`, `vendor/`, `README.md`,
`LICENSE`).

**Reversal path:** if prefixing proves unnecessary (WooCommerce core began
isolating deps, or this plugin is the only consumer on target sites), drop
the scoping steps from the build script — the unprefixed tree in git stays
the canonical source of truth.

## Disclosure

Security reports follow `SECURITY.md`.
