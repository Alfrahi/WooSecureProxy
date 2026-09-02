# WooSecureProxy — Security Model

Threat model, key management, and incident-response documentation for the
WooSecureProxy plugin. Read this before deploying anywhere real.

## 1. What the proxy is for

Mobile apps and headless frontends need WooCommerce store data without
holding the store's `consumer_key` / `consumer_secret`. Those credentials
grant full read/write access to the store and must never ship in a
distributable binary. WooSecureProxy sits in front of the WooCommerce REST
API: clients authenticate to the *proxy*, the proxy attaches the real
credentials server-side and forwards to the allowlisted WooCommerce
endpoint.

The proxy's job is to make a leaked client binary unable to compromise the
store — the worst case becomes "attacker can do what the app can do",
rate-limited and auditable, never "attacker owns the store API".

## 2. Trust boundaries

```
┌─────────────┐   TLS    ┌─────────────────────┐   internal loopback  ┌──────────────┐
│ Client app  │ ───────► │ WooSecureProxy      │ ───────────────────► │ WooCommerce  │
│ (untrusted) │          │ (WordPress + plugin)│   server-side Basic  │ REST API     │
└─────────────┘          │                     │   Auth (ck/cs)       └──────────────┘
                         │  guards: HMAC,      │
                         │  nonce, timestamp,  │
                         │  rate limit, JWT,   │
                         │  schema             │
                         └─────────────────────┘
```

| Boundary | Crossing | Defense |
|---|---|---|
| Client → Proxy | `POST /wp-json/woosecureproxy/v3/proxy` | HMAC-SHA256 signature over `timestamp + nonce + body`, app token, replay protection, timestamp skew window, body-size cap, action allowlist, per-IP/per-app rate limits, JSON schema validation |
| Proxy → WooCommerce | internal REST dispatch | server-side Basic Auth with `WC_CONSUMER_KEY` / `WC_CONSUMER_SECRET`; never reflected to the client |
| End user → data | `X-Customer-JWT` header | HS256 JWT, 60-min access tokens, audience check, per-token (jti) revocation, scope/ownership checks per action |

## 3. `PROXY_SECRET` authenticates the app build, not a user

`PROXY_SECRET` is a shared symmetric secret embedded in the shipped app.
Understand exactly what a signature proves:

> A valid HMAC proves the request was produced by **some copy of the app
> build** — nothing more. It does not identify a user, cannot be revoked
> per-device, and cannot distinguish a customer from someone who extracted
> the secret from the APK/IPA/bundle.

A determined attacker **will** extract `PROXY_SECRET` from any distributed
binary. That is expected and is why the defense-in-depth layers exist:
rate limits, replay protection, schema validation, login throttling, and
the action allowlist all continue to apply to a secret-holder. What an
extracted secret does **not** buy: store API credentials (never present in
the client), other users' JWTs (issued only via throttled login), or
access beyond the eight allowlisted actions.

**Client-side storage guidance (buy time, don't pretend it's safe):**

- Derive/obfuscate the secret — split it across constants, assemble at
  runtime, store parts in the platform keystore (Android Keystore /
  iOS Keychain) where possible. Raise the extraction cost from "strings"
  to "dynamic analysis".
- Ship a **different `PROXY_SECRET` per release channel** (debug vs.
  production) so a leak from a beta build doesn't touch production users.
- Never log the secret, the canonical string-to-sign, or signatures in
  client telemetry.

Deployments where secret extraction is unacceptable need a
per-device attestation scheme (e.g., Play Integrity / App Attest) in front
of this plugin — out of scope here.

## 4. TLS is mandatory

All proxy traffic must be HTTPS with modern TLS. The HMAC scheme
authenticates requests but does **not** encrypt them: an on-path attacker
on plaintext HTTP can read order/customer data and customer credentials in
transit. Terminate TLS with HSTS at the edge; the plugin does not attempt
to detect plaintext (a reverse proxy can make `is_ssl()` unreliable).

## 5. Key rotation

`PROXY_SECRET` lives in `wp-config.php`. The plugin currently accepts
**one** secret — there is no dual-secret acceptance window, so rotation is
a hard cutover for request signing. JWT validation uses the **same**
secret (`JwtHelper` signs HS256 with `Config::proxy_secret()`), which
means rotating the secret also revokes every outstanding customer JWT.

Because access tokens live only 60 minutes, this coupling is intentional:
rotation doubles as the "revoke everything" action.

### Planned rotation procedure

1. Announce a customer-impact window: all users will be signed out
   (refresh tokens die with access tokens).
2. Generate a new secret: `wp_generate_password(64, true, true)` or
   `openssl rand -hex 32`.
3. Ship a new app build embedding the new secret **before** the server
   cutover if you can tolerate old-build downtime; otherwise accept that
   old builds fail with `invalid_signature` (403) until users update.
4. Update `PROXY_SECRET` in `wp-config.php` (or the host's env
   injection) at the cutover time. The change is effective immediately —
   no cache flush needed; the constant is read per request.
5. Verify: a signed request with the new secret returns 2xx; the old
   secret returns 403.
6. Rotate `WC_CONSUMER_KEY` / `WC_CONSUMER_SECRET` too if the incident
   scope included server filesystem access (see §8).

> If zero-downtime signing is ever required, add a `PROXY_SECRET_PREVIOUS`
> fallback secret checked after the primary for a bounded overlap window
> (≤ 24 h), then remove it. Not implemented today — do not assume it.

### `WC_CONSUMER_KEY` / `WC_CONSUMER_SECRET` rotation

These are WooCommerce REST API keys (WooCommerce → Settings → Advanced →
REST API). Rotation is a normal hard cutover: create a new key pair,
update the constants, delete the old keys. Since clients never see them,
there is no user impact as long as the constants are updated atomically
with the key deletion.

## 6. Token lifecycle & revocation semantics

| Token | Scope | TTL | Issued by | Revocation |
|---|---|---|---|---|
| Access | `customer` | 60 min | `customerLogin` / `customerRegister` / `refreshToken` | per-token via `jti` transient; enforced inside `validate()` |
| Refresh | `refresh` | 30 days | `customerLogin` / `customerRegister` | per-token; also accepted only by `refreshToken` |

- **Scopes are enforced:** a `refresh`-scoped token is rejected on every
  action except `refreshToken`, and `refreshToken` rejects
  `customer`-scoped tokens.
- **Audience check:** all tokens carry `aud = woosecureproxy`; tokens from
  any other issuer or a misconfigured clone fail validation.
- **`customerLogout`** revokes the presented access token (jti denylist,
  30-day transient so validation stays cheap).
- **Per-token revocation** covers "this device is lost". **Global
  revocation** ("all sessions must die now") = rotate `PROXY_SECRET` —
  every JWT becomes unverifiable at once.

### Ownership & authorization

Actions declare an auth level (`none`, `optional`, `customer`,
`customer_self`, `customer_owner`). `customer` actions need any valid
access token; `customer_self` / `customer_owner` additionally verify the
JWT's `sub` matches the target customer / owns the target order before
dispatch. A token can never escalate: the plugin maps JWT identity to
WooCommerce user capabilities; anonymous and mismatched-identity requests
get 403.

## 7. Deployment requirements

1. **TLS everywhere** (§4), HSTS at the edge.
2. **Persistent object cache** (Redis/Memcached drop-in). Without it:
   - nonce replay protection falls back to the DB table (`wsp_nonces`,
     created by `dbDelta` on activation) — works, but adds a write per
     request and an amortized purge;
   - rate-limit counters transact through MySQL instead of Redis —
     slower and weaker under load;
   - an admin notice warns that enforcement is degraded.
   Treat the degraded path as a stopgap, not a supported steady state.
3. **Real client IPs.** `IpDetector` trusts forwarding headers
   **only** when `REMOTE_ADDR` is in the `WSP_TRUSTED_PROXIES` constant.
   If the site sits behind Cloudflare or any reverse proxy, populate it:

   ```php
   define( 'WSP_TRUSTED_PROXIES', array(
       '103.21.244.0/22',   // Cloudflare — publish the ranges you actually use,
       '103.22.200.0/22',   // see https://www.cloudflare.com/ips/
       // ...
   ) );
   ```

   Without this, every proxied client appears as the proxy's IP and
   **rate limiting degenerates to a global limit** — a mild attacker can
   DoS every user, and a single heavy user burns everyone's budget.

## 8. Incident response playbook

### 8.1 Suspected `PROXY_SECRET` extraction / abuse

Signs: validly signed requests with unusual patterns, bursts that respect
rate limits, downloads of the allowlisted read actions at scale.

1. **Rotate `PROXY_SECRET` immediately** (§5 procedure). This invalidates
   all JWTs too — every user is signed out once.
2. Review the `wsp_metrics_daily` counters and the
   `woosecureproxy` WooCommerce log channel for the abuse window
   (actions, status codes, request IDs — no secrets or tokens are ever
   logged, so correlate by request ID with your edge logs).
3. Ship an app release with the new secret; use store update nudges /
   force-update floor if the leak was passive scraping you want to shed.
4. Post-incident: consider per-channel secrets (§3) so the next leak has
   a smaller blast radius.

### 8.2 Server compromise (filesystem / DB read access)

The attacker now has `PROXY_SECRET` **and** `WC_CONSUMER_KEY/SECRET`.

1. Take the store's public API offline or emergency-rotate: revoke the
   WooCommerce REST keys in wp-admin first (kills store API access
   through the proxy), then rotate `PROXY_SECRET`.
2. Issue new WooCommerce keys, update constants, redeploy.
3. Assume all JWTs and logged-in sessions are forgeable — they are, until
   step 1 completes — and audit orders created/modified during the
   exposure window against WooCommerce order notes and customer
   confirmation emails.
4. Follow your hosting/regulatory breach-notification obligations; the
   proxy itself stores no customer PII beyond what WooCommerce already
   holds.

### 8.3 Abuse of a single customer account

1. That account's tokens: revoke individually only if you hold the token
   (`JwtHelper::revoke($token)`); otherwise reset the WP password — the
   next `refreshToken` call binds to the new credentials on re-login.
   (A per-user "revoke all my tokens" endpoint is not yet implemented.)
2. Password reset + notify the customer out of band.
3. Check `LoginThrottle` behavior in logs — brute-forced accounts show
   repeated `invalid_credentials` responses from a narrow IP set.

### 8.4 Fail-closed guarantees to rely on under fire

- Missing/short `PROXY_SECRET` (< 32 chars) → plugin refuses to serve.
- Replay of any signed request → rejected by the atomic nonce store.
- Login brute force → per-IP rate limit (10/min), per-account lockout
  (5 failures → 15 min), uniform error responses (no user enumeration).
- Unknown/allowlist-absent actions → 404 before any upstream call.
- Any unhandled exception inside the handler → JSON 500 with request ID,
  logged with stack trace, never a leaked message to the client.

