<?php
/**
 * Uninstall script for WooSecureProxy.
 *
 * This file is executed when the plugin is deleted via the WordPress admin.
 * It performs complete cleanup of all plugin data:
 * - Deletes stored settings/options
 * - Clears non-persistent cache groups used for nonce and rate-limit tracking
 *
 * @package WooSecureProxy
 * @since   1.0.0
 */

if (! defined('WP_UNINSTALL_PLUGIN')) {
    // Prevent direct access – only run when WordPress is uninstalling the plugin
    exit;
}

/**
 * Remove all plugin options from the database.
 */
delete_option('wsp_allowed_tokens_json');
delete_option('wsp_rate_limits_json');

/**
 * Clear non-persistent cache groups used by the proxy.
 *
 * These groups ('wsp_nonces' and 'wsp_rl') are registered as non-persistent
 * during plugin initialization, but some object cache backends may still retain
 * data. We flush them here for complete cleanup.
 */
foreach ([ 'wsp_nonces', 'wsp_rl' ] as $group) {
    if (function_exists('wp_cache_flush_group')) {
        // Preferred method in WordPress 6.1+
        wp_cache_flush_group($group);
    } else {
        // Fallback for older WordPress versions
        wp_cache_delete_multiple(array_keys(wp_cache_get_multiple([], $group)), $group);
    }
}
