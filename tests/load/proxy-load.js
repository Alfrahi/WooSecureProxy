/**
 * k6 load test for the WooSecureProxy REST proxy.
 *
 * Signs each request with HMAC-SHA256 over timestamp + nonce + body,
 * matching \WooSecureProxy\Proxy\RequestHandler::verify_signature().
 *
 * Run:
 *   k6 run \
 *     -e BASE_URL=https://staging.example.com \
 *     -e PROXY_SECRET='your-32+-char-secret' \
 *     -e APP_TOKEN='your-app-token' \
 *     tests/load/proxy-load.js
 *
 * Optional:
 *   -e RPS_STAGE_3=500   (override top stage)
 *   -e LOGIN_MODE=burst  (extra 429-threshold probe instead of steady login)
 */

import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const BASE_URL     = __ENV.BASE_URL || 'http://localhost';
const PROXY_SECRET = __ENV.PROXY_SECRET;
const APP_TOKEN    = __ENV.APP_TOKEN || '';
const LOGIN_MODE   = __ENV.LOGIN_MODE || 'steady';
const TOP_RPS      = parseInt(__ENV.RPS_STAGE_3 || '500', 10);

if (!PROXY_SECRET) {
  throw new Error('PROXY_SECRET env var is required');
}

const PROXY_URL = `${BASE_URL}/wp-json/woosecureproxy/v3/proxy`;

// Custom metrics: latency per action, error rate, rate-limiter engagement.
const latencyProducts = new Trend('wsp_latency_getproducts', true);
const latencyLogin    = new Trend('wsp_latency_customerlogin', true);
const errorRate       = new Rate('wsp_errors');
const limitedCount    = new Counter('wsp_rate_limited_total');

export const options = {
  scenarios: {
    products: {
      executor: 'ramping-arrival-rate',
      exec: 'getProducts',
      startRate: 50,
      timeUnit: '1s',
      stages: [
        { target: 50,      duration: '2m' },
        { target: 200,     duration: '2m' },
        { target: TOP_RPS, duration: '2m' },
        { target: 0,       duration: '30s' },
      ],
      preAllocatedVUs: 50,
      maxVUs: 2000,
    },
    login: {
      executor: LOGIN_MODE === 'burst' ? 'ramping-arrival-rate' : 'constant-arrival-rate',
      exec: 'customerLogin',
      rate: LOGIN_MODE === 'burst' ? 5 : 10,
      timeUnit: '1s',
      duration: '4m',
      preAllocatedVUs: 20,
      maxVUs: 200,
      // Burst mode ramps past the 10 req/IP/min login limit to prove 429s engage.
      ...(LOGIN_MODE === 'burst' ? { stages: [ { target: 5, duration: '1m' }, { target: 30, duration: '2m' }, { target: 0, duration: '1m' } ] } : {}),
    },
  },
  thresholds: {
    'wsp_latency_getproducts':   ['p(95)<500', 'p(99)<1500'],
    'wsp_latency_customerlogin': ['p(95)<1000'],
    'wsp_errors':                ['rate<0.01'],
  },
};

/**
 * Builds a signed proxy request body + headers for an action.
 *
 * @param {string} action Whitelisted action name.
 * @param {object} data   Action payload.
 * @returns {{body: string, headers: object}}
 */
function signedRequest(action, data) {
  const body      = JSON.stringify({ action, method: 'POST', data });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomBytes(16).hex; // unique per request (replay protection)
  const signature = crypto.hmac('sha256', PROXY_SECRET, timestamp + nonce + body, 'hex');

  return {
    body,
    headers: {
      'Content-Type': 'application/json',
      'X-App-Token': APP_TOKEN,
      'X-Timestamp': timestamp,
      'X-Nonce':     nonce,
      'X-Signature': signature,
    },
  };
}

function postProxy(action, data, latency) {
  const { body, headers } = signedRequest(action, data);
  const res = http.post(PROXY_URL, body, { headers, tags: { action } });

  latency.add(res.timings.duration);

  const limited = res.status === 429;
  if (limited) limitedCount.add(1);

  const ok = check(res, {
    'status 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
  errorRate.add(!ok);

  return res;
}

export function getProducts() {
  postProxy('getProducts', { per_page: 10 }, latencyProducts);
}

export function customerLogin() {
  const user = `k6user${Math.floor(Math.random() * 100)}@example.com`;
  postProxy('customerLogin', { username: user, password: 'k6-test-pass-nope' }, latencyLogin);
}
