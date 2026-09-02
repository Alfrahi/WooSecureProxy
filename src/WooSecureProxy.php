<?php
/**
 * Main plugin class.
 *
 * Central entry point and orchestrator for the WooSecureProxy plugin.
 * Instantiated once by the plugin bootstrap.
 *
 * Responsibilities:
 * - Bootstrap admin settings page (only in admin context)
 * - Register the secure proxy REST routes
 * - Handle activation/deactivation tasks (flush rewrite rules)
 *
 * @package WooSecureProxy
 * @since   1.0.0
 */

namespace WooSecureProxy;

/**
 * Plugin orchestrator singleton instance, created once by the bootstrap.
 *
 * @since 1.0.0
 */
final class WooSecureProxy {

	/**
	 * Sets up the primary initialization hook.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Initializes the plugin components.
	 *
	 * - Loads the admin settings page when in the WordPress admin area.
	 * - Registers the secure proxy REST API routes.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function init(): void {
		if ( is_admin() ) {
			new Admin\SettingsPage();
		}

		add_action( 'rest_api_init', array( new Proxy\RequestHandler(), 'register_routes' ) );
	}

	/**
	 * Runs on plugin activation.
	 *
	 * Flushes rewrite rules and ensures the nonce table exists for
	 * degraded-mode (no persistent object cache) replay protection.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public static function activate(): void {
		Helpers\NonceStore::create_table();
		flush_rewrite_rules();
	}

	/**
	 * Runs on plugin deactivation.
	 *
	 * Flushes rewrite rules to clean up any custom permalinks/endpoint registrations.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public static function deactivate(): void {
		flush_rewrite_rules();
	}
}
