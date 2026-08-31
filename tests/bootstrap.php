<?php
/**
 * Test bootstrap: autoloader + Brain Monkey (WP function mocking, no WP install needed).
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

define('WSP_TESTS', true);

if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . '/wsp-fake-wp/');
}

// Plugin constants normally defined in woo-secure-proxy.php. RequestHandler
// resolves PROXY_MAX_BODY_SIZE into a class constant at class-definition time,
// so these must exist before any src/ class is autoloaded.
define('PROXY_SECRET', 'test-secret-key-with-at-least-32-characters');
define('PROXY_TIMESTAMP_SKEW', 300);
define('PROXY_NONCE_TTL', 600);
define('PROXY_MAX_BODY_SIZE', 512 * 1024);
define('WSP_VERSION', '1.0.0-tests');
define('WC_CONSUMER_KEY', 'ck_test_key');
define('WC_CONSUMER_SECRET', 'cs_test_secret_with_at_least_32_chars_xxxxxxxx');

// Minimal WP/WooCommerce class stubs used by production code under test.
require_once __DIR__ . '/Stubs/wp-classes.php';
