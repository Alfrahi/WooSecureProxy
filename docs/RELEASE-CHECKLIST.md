# Pre-Release Checklist — WooSecureProxy

Executed 2026-09-02 on commit range through Prompt 19. Items marked
✅ were verified locally with recorded evidence; ⚠️ items require a
staging/production-like environment that is not available in this
repository and **must be completed before tagging a release**.

| # | Gate | Result | Evidence / Notes |
|---|------|--------|------------------|
| 1 | PHPUnit suite green | ✅ | `composer test` — **92 tests, 248 assertions, OK** (0.12 s) |
| 2 | PHPStan clean | ✅ | `composer phpstan` — level per `phpstan.neon.dist`, **no errors** (14 files) |
| 3 | PHPCS clean (WPCS) | ✅ | `composer phpcs` — **no findings** (15 files, 777 ms) |
| 4 | `composer audit` clean | ✅ | **No security vulnerability advisories found** |
| 5 | Settings-page a11y | ✅ (static) | Labels/`scope="row"` everywhere; added `scope="col"` to metrics counter table headers this pass. Full screen-reader pass belongs to the staging smoke test (item 8). |
| 6 | i18n completeness | ✅ (static) | Single text domain `woo-secure-proxy` used consistently; `load_plugin_textdomain()` wired in bootstrap. ⚠️ `wp i18n make-pot` not run — wp-cli unavailable here; run it in CI or locally before tagging. |
| 7 | Uninstall leaves zero residue | ✅ (code-verified) | `uninstall.php` is multisite-aware and removes: `wsp_allowed_tokens_json`, `wsp_rate_limits_json`, `wsp_metrics_daily` options; `wsp_nonces` table; `wsp_nonces`/`wsp_rl` cache groups. **Gap found & fixed this pass:** DB-backed `wsp_jwt_revoked_`, `wsp_lock_`, `wsp_lfails_` transients now bulk-deleted on uninstall. |
| 8 | WP + WC version smoke test on clean install | ⚠️ pending | Requires a disposable WordPress + WooCommerce install; verify activation, settings page render, one signed `getProducts` call on declared minimums (WP 6.0 / WC 7.0) and latest. |
| 9 | Load test execution | ⚠️ pending | Script + plan committed in Prompt 17 (`tests/load/proxy-load.js`, `docs/LOAD-TEST.md`); results table unfilled until a staging site exists. |

## Changes made during this pass

1. `uninstall.php` — bulk-delete `wsp_jwt_revoked_`/`wsp_lock_`/`wsp_lfails_`
   transient rows (object-cache copies expire on their own, ≤ 30 days).
2. `src/Admin/views/settings-page.php` — `scope="col"` on the request-counter
   widget table headers (screen-reader column association).

Re-verified after both edits: `composer test` ✅ · `composer phpstan` ✅ ·
`composer phpcs` ✅.

## Sign-off

- [ ] Items 8–9 executed against staging and recorded in `docs/LOAD-TEST.md`.
- [ ] POT file regenerated and committed.
- [ ] Release tagged.

**Not eligible for release until all boxes above are checked.**
