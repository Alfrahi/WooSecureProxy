# WooSecureProxy – Secure WooCommerce REST API Proxy

**WooSecureProxy** is an experimental solution to help secure your WooCommerce store's REST API by protecting it from bots, scraping, and potential abuse. It aims to provide a secure way for mobile apps and headless frontends to access your store with authenticated, rate-limited requests — without exposing sensitive consumer keys.

Please note that this project is still in early stages and may have some rough edges. It’s my first attempt at working with WooCommerce, so any feedback or suggestions are greatly appreciated!

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![WordPress](https://img.shields.io/badge/WordPress-%E2%89%A56.0-0a4b6f.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-%E2%89%A58.0-777bb4.svg)](https://php.net)
[![WooCommerce](https://img.shields.io/badge/WooCommerce-%E2%89%A57.0-brightgreen.svg)](https://woocommerce.com)

## Features

| Feature                                   | Status | Description                                                                            |
| ----------------------------------------- | ------ | -------------------------------------------------------------------------------------- |
| **HMAC-SHA256 Signed Requests**           | Done   | Every request is cryptographically signed with `PROXY_SECRET` to ensure authenticity.  |
| **Replay Attack Protection**              | Done   | Uses one-time nonces with a TTL to prevent replay attacks.                             |
| **Per-App + Per-IP Rate Limiting**        | Done   | Configurable rate limits via JSON for better control.                                  |
| **Stateless Customer JWT Auth**           | Done   | Secure JWT authentication after customer login.                                        |
| **Zero Trust Model**                      | Done   | If secrets are missing or incorrect, the system will fail closed to protect your data. |
| **JSON Schema Validation**                | Done   | Ensures payloads are correctly structured and free from malicious content.             |
| **Cloudflare / Proxy Aware IP Detection** | Done   | Accurately detects the real client IP, even behind proxies or Cloudflare.              |

## Why WooSecureProxy?

This project is designed to provide a secure proxy layer for WooCommerce's REST API. It solves the problem of exposing WooCommerce consumer keys on mobile apps, making them vulnerable to reverse engineering and misuse.

**WooSecureProxy** ensures that:

* Your real `consumer_key` and `consumer_secret` never leave the server.
* Mobile apps only communicate with `/wp-json/woosecureproxy/v3/proxy`.
* All requests are cryptographically signed, time-stamped, nonce-protected, and rate-limited.
* Customers log in once, receive a JWT, and can then access their data securely.

## Installation

1. Upload the plugin files to `/wp-content/plugins/woo-secure-proxy`.
2. Activate the plugin through the WordPress admin dashboard.
3. Add the following lines to your `wp-config.php`:

```php
// 1. Your ultra-strong shared secret (256+ bits recommended)
define('PROXY_SECRET', 'yoursecretgoeshere-reallylongrandomstring-64chars+');

// 2. Internal WooCommerce API credentials (generate via WooCommerce → Settings → Advanced → REST API)
define('WC_CONSUMER_KEY', 'ck_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
define('WC_CONSUMER_SECRET', 'cs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');

// Optional: Adjust limits
define('PROXY_MAX_BODY_SIZE', 1024 * 1024); // 1MB
define('PROXY_TIMESTAMP_SKEW', 300);        // 5 minutes
define('PROXY_NONCE_TTL', 600);             // 10 minutes
```

## Settings

Visit **Settings → WooSecureProxy** to:

* Manage allowed app tokens.
* View security status (green = safe).
* Customize rate limits.
* View live request activity (**coming soon**).

## Mobile App Usage Example (JavaScript / React Native)

```js
const PROXY_URL = 'https://yoursite.com/wp-json/woosecureproxy/v3/proxy';
const APP_TOKEN = 'mobile-v2';
const SECRET = 'yoursecretgoeshere-reallylongrandomstring-64chars+';

async function proxyRequest(action, data = {}, method = 'GET', jwt = null) {
  const timestamp = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');

  const body = JSON.stringify({ action, data, method });
  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(timestamp + nonce + body)
    .digest('hex');

  const res = await fetch(PROXY_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-App-Token': APP_TOKEN,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      ...(jwt && { 'X-Customer-JWT': jwt }),
    },
    body,
  });

  return res.json();
}

// Login
const login = await proxyRequest('customerLogin', {
  username_or_email: 'customer@example.com',
  password: 'supersecret'
});

if (login.success) {
  const jwt = login.jwt;
  // Now fetch orders securely
  const orders = await proxyRequest('getOrders', {}, 'GET', jwt);
}
```

## License

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.