# Load & Resilience Test Plan (Prompt 17)

Load test assets for validating the proxy under 50/200/500 rps before
production. Script: [`tests/load/proxy-load.js`](../tests/load/proxy-load.js) (k6).

## Prereqs

1. Staging WooCommerce site with the plugin active and same tuning as prod
   (persistent object cache enabled or intentionally disabled to test
   degraded mode).
2. `PROXY_SECRET`, `WC_CONSUMER_KEY`, `WC_CONSUMER_SECRET` defined.
3. A valid `X-App-Token` from **Settings → WooSecureProxy**.
4. [k6](https://k6.io/) ≥ 0.45 installed locally.

## Run

```bash
k6 run \
  -e BASE_URL=https://staging.example.com \
  -e PROXY_SECRET='...' \
  -e APP_TOKEN='...' \
  tests/load/proxy-load.js
```

Stages: 50 rps for 2 m → 200 rps for 2 m → 500 rps for 2 m (`getProducts`),
plus a 10 rps `customerLogin` stream.

Rate-limiter validation pass (429 threshold proof):

```bash
k6 run -e LOGIN_MODE=burst ... tests/load/proxy-load.js
```

This ramps login traffic past the configured `customerLogin` limit
(default 10 req/IP/min) — the `wsp_rate_limited_total` counter must climb
and thresholds must still pass.

## Metrics to capture

| Source | What |
|---|---|
| k6 summary | p95/p99 via `wsp_latency_*` trends; error rate via `wsp_errors` |
| WP options | `SELECT LENGTH(option_value) FROM wp_options WHERE option_name='wsp_metrics_daily'` before/after — must stay bounded (2-day retention, `Metrics::KEEP_DAYS`) |
| Nonce store | Without persistent cache: `SELECT COUNT(*) FROM wp_wsp_nonces` — must stay near-zero thanks to the amortized purge in `NonceStore`; rows expire with `PROXY_NONCE_TTL` |
| Redis `INFO stats` / slowlog | Command count rate during the run — expect 1 `wp_cache_add` (nonce) + 2 counters (rate limit IP/app) per request, nothing more |
| Query Monitor / New Relic | DB queries per request — watch for per-request writes other than the (rare) metrics option update |
| PHP-FPM / container memory | RSS across the run — flat; no per-request growth |

## Pass criteria

- p95 < 500 ms and p99 < 1500 ms at all stages (k6 thresholds enforce).
- Global error rate < 1 % (excluding intentional 429s in burst mode).
- `wsp_metrics_daily` option size bounded; old buckets pruned.
- Nonce table/counters do not grow beyond TTL window × peak rps.
- Rate limiters return 429 with `X-RateLimit-*` headers at thresholds.

## Known resource behavior (by design)

- **Metrics write per request:** `Metrics::record()` updates one
  non-autoloaded option per request. Under load this is the main DB write
  path without an external object cache; if contention shows up, move
  counters to a cache multi-get or drop in favor of an edge-level metric.
- **Nonce purge is amortized** (~1 % of requests) in degraded DB mode —
  no scheduled cron dependence.
- **No unbounded transients:** rate-limit counters and nonces all carry
  TTLs; metrics are day-bucketed with 2-day retention.

## Results log

Fill in per run, commit alongside this doc.

| Date | Env | Cache backend | Top rps | p95 (ms) | p99 (ms) | Err % | 429s | Notes |
|------|-----|---------------|---------|----------|----------|-------|------|-------|
| _PENDING_ — run against staging | | | | | | | | |
