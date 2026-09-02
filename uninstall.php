<?php
/**
 * Uninstall script for WooSecureProxy.
 *
 * Executes when the plugin is deleted via the WordPress admin. Removes every
 * trace of the plugin:
 * - Per-site options (settings)
 * - The wsp_nonces replay-protection table
 * - Non-persistent cache groups used for rate limiting
 *
 * Multisite-aware: iterates all sites and cleans each blog's options and
 * prefixed nonce table.
 *
 * @package WooSecureProxy
 * @since   1.0.0
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	// Prevent direct access – only run when WordPress is uninstalling the plugin.
	exit;
}

require_once __DIR__ . '/src/Helpers/Metrics.php';

/**
 * Removes all plugin data for the current blog context.
 *
 * @since 1.0.0
 */
function wsp_uninstall_site(): void {
	global $wpdb;

	delete_option( 'wsp_allowed_tokens_json' );
	delete_option( 'wsp_rate_limits_json' );
	delete_option( \WooSecureProxy\Helpers\Metrics::OPTION );

	// Drop the replay-protection nonce table for this blog.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Intentional cleanup on uninstall.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wsp_nonces" );

	// Purge leftover JWT-revocation and login-throttle transients.
	// Only DB-transients can be cleaned; object-cache copies expire on their own (≤ 30 days).
	foreach ( array( 'wsp_jwt_revoked_', 'wsp_lock_', 'wsp_lfails_' ) as $wsp_prefix ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Transient cleanup on uninstall; no caching applies.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
				$wpdb->esc_like( '_transient_' . $wsp_prefix ) . '%'
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Transient cleanup on uninstall; no caching applies.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
				$wpdb->esc_like( '_transient_timeout_' . $wsp_prefix ) . '%'
			)
		);
	}

	// Flush the non-persistent cache groups used for nonces and rate limiting.
	if ( function_exists( 'wp_cache_flush_group' ) ) {
		wp_cache_flush_group( 'wsp_nonces' );
		wp_cache_flush_group( 'wsp_rl' );
	}
}

if ( is_multisite() ) {
	$wsp_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);

	foreach ( $wsp_site_ids as $wsp_blog_id ) {
		switch_to_blog( (int) $wsp_blog_id );
		wsp_uninstall_site();
		restore_current_blog();
	}
} else {
	wsp_uninstall_site();
}
