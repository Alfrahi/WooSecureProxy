<?php
/**
 * Plugin Name: WooSecureProxy
 * Plugin URI: https://github.com/Alfrahi/woosecureproxy
 * Description: Secure API proxy for WooCommerce with HMAC authentication, replay attack protection (nonce + timestamp), per-endpoint rate limiting, request size limits, and strict JSON schema validation.
 * Version: 1.0.0
 * Author: Abdullah Alfrahi
 * Author URI: https://alfrahi.com
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: woo-secure-proxy
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 6.0
 * Tested up to: 6.7
 * WC requires at least: 8.0
 * WC tested up to: 10.3
 *
 * @package WooSecureProxy
 * @copyright 2025 Abdullah Alfrahi
 * @license GPL-3.0-or-later
 */

/**
 * Main plugin bootstrap file.
 *
 * This file serves as the entry point for the WooSecureProxy plugin.
 * It performs security checks, defines essential constants, sets up autoloading,
 * declares WooCommerce compatibility, and initializes the main plugin instance.
 *
 * @package WooSecureProxy
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Ensures the plugin is completely disabled if a strong PROXY_SECRET is not defined.
 * A minimum of 32 characters is enforced for cryptographic security.
 */
if (! defined('PROXY_SECRET') || strlen((string) PROXY_SECRET) < 32) {
    define('WSP_DISABLED', true);

    /**
     * Displays an admin notice explaining why the plugin is disabled and how to fix it.
     */
    add_action('admin_notices', function () {
        if (! current_user_can('manage_options')) {
            return;
        }
        echo '<div class="notice notice-error is-dismissible"><p>
        <strong>WooSecureProxy: PLUGIN DISABLED</strong><br>
        You <strong>must</strong> define a strong <code>PROXY_SECRET</code> (min 32 chars) in wp-config.php<br>
        Example: <code>define("PROXY_SECRET", "' . substr(bin2hex(random_bytes(32)), 0, 64) . '");</code><br>
        Also it is recommended to add WooCommerce consumer key and secret like this examples:<br>
        <code>define("WC_CONSUMER_KEY", "ck_...");</code><br>
        <code>define("WC_CONSUMER_SECRET", "cs_...");</code>
        </p></div>';
    });

    return;
}

/** Absolute path to the main plugin file */
define('WSP_PLUGIN_FILE', __FILE__);

/** Plugin basename (used for assets, hooks, etc.) */
define('WSP_PLUGIN_BASENAME', plugin_basename(__FILE__));

/** Current plugin version */
define('WSP_VERSION', '1.0.0');

/** Filesystem path to the plugin directory */
define('WSP_PATH', plugin_dir_path(__FILE__));

/** URL to the plugin directory */
define('WSP_URL', plugin_dir_url(__FILE__));

/** Allowed clock skew for timestamp validation (seconds) */
define('PROXY_TIMESTAMP_SKEW', defined('PROXY_TIMESTAMP_SKEW') ? PROXY_TIMESTAMP_SKEW : 300);

/** Maximum allowed request body size in bytes (default 512 KB) */
define('PROXY_MAX_BODY_SIZE', defined('PROXY_MAX_BODY_SIZE') ? PROXY_MAX_BODY_SIZE : 512 * 1024);

/** Time-to-live for used nonces (prevents replay attacks) */
define('PROXY_NONCE_TTL', defined('PROXY_NONCE_TTL') ? PROXY_NONCE_TTL : 600);

/**
 * Default rate limit configuration per endpoint.
 *
 * Structure:
 *  - 'ip'  : requests per IP per window
 *  - 'app' : requests per authenticated app per window
 *  - 'win' : time window in seconds
 */
global $wsp_default_rate_limits;
$wsp_default_rate_limits = [
    'default'     => [ 'ip' => 120,   'app' => 5000, 'win' => 60 ],
'createOrder' => [ 'ip' => 15,    'app' => 300,  'win' => 60 ],
'updateOrder' => [ 'ip' => 30,    'app' => 600,  'win' => 60 ],
'getProducts' => [ 'ip' => 200,   'app' => 10000,'win' => 60 ],
];

/**
 * Declares compatibility with WooCommerce Custom Order Tables (HPOS).
 */
add_action('before_woocommerce_init', function () {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});

/**
 * Sets up Composer autoloading if available; falls back to a simple PSR-4-style autoloader.
 */
if (file_exists(WSP_PATH . 'vendor/autoload.php')) {
    require_once WSP_PATH . 'vendor/autoload.php';
} else {
    spl_autoload_register(function ($class) {
        if (strpos($class, 'WooSecureProxy\\') !== 0) {
            return;
        }
        $file = WSP_PATH . 'src/' . str_replace('\\', '/', substr($class, 15)) . '.php';
        if (file_exists($file)) {
            require $file;
        }
    });
}

/**
 * Warns administrators if the required firebase/php-jwt library is missing.
 */
add_action('admin_notices', function () {
    if (! class_exists('Firebase\JWT\JWT')) {
        echo '<div class="notice notice-error is-dismissible"><p>
        <strong>WooSecureProxy:</strong> Missing required dependency
        <code>firebase/php-jwt</code>.
        Please run <code>composer install</code> in the plugin directory
        or install the library via Composer.
        </p></div>';
    }
});

/**
 * Initializes the plugin after all plugins are loaded.
 *
 * - Checks for WooCommerce
 * - Sets up non-persistent cache groups for nonces and rate limiting
 * - Loads text domain
 * - Starts the main plugin singleton
 */
add_action('plugins_loaded', function () {
    if (! class_exists('WooCommerce')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>'
            . esc_html__('WooSecureProxy requires WooCommerce to be active.', 'woo-secure-proxy')
            . '</p></div>';
        });
        return;
    }

    if (wp_cache_supports('add_non_persistent_groups')) {
        wp_cache_add_non_persistent_groups([ 'wsp_nonces', 'wsp_rl' ]);
    }

    load_plugin_textdomain('woo-secure-proxy', false, dirname(WSP_PLUGIN_BASENAME) . '/languages');

    \WooSecureProxy\WooSecureProxy::instance();
});

/** Runs on plugin activation */
register_activation_hook(__FILE__, [ \WooSecureProxy\WooSecureProxy::class, 'activate' ]);

/** Runs on plugin deactivation */
register_deactivation_hook(__FILE__, [ \WooSecureProxy\WooSecureProxy::class, 'deactivate' ]);
