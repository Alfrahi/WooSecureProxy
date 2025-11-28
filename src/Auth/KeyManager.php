<?php
/**
 * Handles internal authentication to WooCommerce REST API.
 *
 * Provides utilities to:
 * - Validate that manual consumer key/secret (or future Application Passwords) are properly configured
 * - Generate the Basic Auth header for internal proxy requests
 * - Show admin warnings when authentication is missing
 * - Return a standardized 503 response when the proxy cannot function
 *
 * @package WooSecureProxy\Auth
 * @since   1.0.0
 */

declare(strict_types=1);

namespace WooSecureProxy\Auth;

use WP_REST_Response;

/**
 * Class KeyManager
 */
class KeyManager {

	/**
	 * Prevents multiple identical admin notices from being displayed.
	 *
	 * @var bool
	 */
	private static bool $warning_shown = false;

	/**
	 * Displays an admin notice when internal WooCommerce authentication is missing or invalid.
	 *
	 * Only shown once per request and only to users with manage_options capability.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public static function show_auth_warning(): void {
		if ( self::$warning_shown || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		echo '<div class="notice notice-error">
        <p>
        <strong>' . esc_html__( 'WooSecureProxy: Internal Authentication Missing', 'woo-secure-proxy' ) . '</strong><br>
        ' . esc_html__( 'The proxy cannot forward requests because WC_CONSUMER_KEY and/or WC_CONSUMER_SECRET are not configured properly.', 'woo-secure-proxy' ) . '<br>
        ' . esc_html__( 'Add them to wp-config.php or enable Application Passwords for a dedicated proxy user.', 'woo-secure-proxy' ) . '
        </p>
        </div>';

		self::$warning_shown = true;
	}

	/**
	 * Returns the Basic Authentication header for internal requests to WooCommerce REST API.
	 *
	 * If credentials are missing or invalid, triggers an admin warning and returns an empty array.
	 *
	 * @return array<string, string> Authorization header or empty array if not configured.
	 * @since  1.0.0
	 */
	public static function get_auth_header(): array {
		$valid = defined( 'WC_CONSUMER_KEY' )
		&& defined( 'WC_CONSUMER_SECRET' )
		&& WC_CONSUMER_KEY !== ''
		&& (string) WC_CONSUMER_SECRET !== ''
		&& strlen( (string) WC_CONSUMER_SECRET ) >= 32;

		if ( ! $valid ) {
			add_action( 'admin_notices', array( __CLASS__, 'show_auth_warning' ) );
			return array();
		}
		
		return array(
			'Authorization' => 'Basic ' . base64_encode( WC_CONSUMER_KEY . ':' . WC_CONSUMER_SECRET ),
		);
	}

	/**
	 * Checks whether internal WooCommerce authentication is properly configured.
	 *
	 * @return bool True if credentials are valid and ready to use.
	 * @since  1.0.0
	 */
	public static function is_configured(): bool {
		return array() !== self::get_auth_header();
	}

	/**
	 * Returns a standardized 503 Service Unavailable response when the proxy cannot function.
	 *
	 * Used when internal authentication is missing or misconfigured.
	 *
	 * @return WP_REST_Response
	 * @since  1.0.0
	 */
	public static function get_disabled_response(): WP_REST_Response {
		return new WP_REST_Response(
			array(
				'success' => false,
				'error'   => array(
					'code'    => 'auth_missing',
					'message' => 'Internal WooCommerce authentication not configured. Proxy disabled.',
				),
			),
			503
		);
	}
}
