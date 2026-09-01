<?php
/**
 * Centralized configuration access.
 *
 * Single owner for all wp-config constants (with sane defaults) and
 * options-backed settings. Every constant/option read in the plugin
 * goes through this class.
 *
 * @package WooSecureProxy
 * @since   1.0.0
 */

namespace WooSecureProxy;

/**
 * Configuration facade.
 */
class Config {

	/** Minimum acceptable PROXY_SECRET length. */
	public const SECRET_MIN_LENGTH = 32;

	/**
	 * Returns the HMAC shared secret, or '' when missing/too weak.
	 *
	 * @return string
	 * @since  1.0.0
	 */
	public static function proxy_secret(): string {
		if ( ! defined( 'PROXY_SECRET' ) || ! is_string( PROXY_SECRET ) ) {
			return '';
		}

		return strlen( PROXY_SECRET ) >= self::SECRET_MIN_LENGTH ? PROXY_SECRET : '';
	}

	/**
	 * Allowed clock skew for request timestamps (seconds).
	 *
	 * @return int
	 * @since  1.0.0
	 */
	public static function timestamp_skew(): int {
		return defined( 'PROXY_TIMESTAMP_SKEW' ) ? (int) PROXY_TIMESTAMP_SKEW : 300;
	}

	/**
	 * Nonce time-to-live for replay protection (seconds).
	 *
	 * @return int
	 * @since  1.0.0
	 */
	public static function nonce_ttl(): int {
		return defined( 'PROXY_NONCE_TTL' ) ? (int) PROXY_NONCE_TTL : 600;
	}

	/**
	 * Maximum request body size in bytes.
	 *
	 * @return int
	 * @since  1.0.0
	 */
	public static function max_body_size(): int {
		return defined( 'PROXY_MAX_BODY_SIZE' ) ? (int) PROXY_MAX_BODY_SIZE : 524288;
	}

	/**
	 * WooCommerce consumer key, or '' when not configured.
	 *
	 * @return string
	 * @since  1.0.0
	 */
	public static function wc_consumer_key(): string {
		return defined( 'WC_CONSUMER_KEY' ) && is_string( WC_CONSUMER_KEY ) ? trim( WC_CONSUMER_KEY ) : '';
	}

	/**
	 * WooCommerce consumer secret, or '' when not configured/too short.
	 *
	 * @return string
	 * @since  1.0.0
	 */
	public static function wc_consumer_secret(): string {
		if ( ! defined( 'WC_CONSUMER_SECRET' ) || ! is_string( WC_CONSUMER_SECRET ) ) {
			return '';
		}

		$secret = trim( WC_CONSUMER_SECRET );
		return strlen( $secret ) >= 32 ? $secret : '';
	}

	/**
	 * Returns true when both WooCommerce consumer credentials are usable.
	 *
	 * @return bool
	 * @since  1.0.0
	 */
	public static function has_wc_credentials(): bool {
		return self::wc_consumer_key() !== '' && self::wc_consumer_secret() !== '';
	}

	/**
	 * Returns the configured trusted proxy list (exact IPs and/or CIDRs).
	 *
	 * Accepts either an array or a comma-separated string in
	 * WSP_TRUSTED_PROXIES. Returns an empty array when not defined.
	 *
	 * @return array<int, string> Normalized proxy list, never empty strings.
	 * @since  1.0.0
	 */
	public static function trusted_proxies(): array {
		if ( ! defined( 'WSP_TRUSTED_PROXIES' ) ) {
			return array();
		}

		$proxies = constant( 'WSP_TRUSTED_PROXIES' );

		if ( is_string( $proxies ) ) {
			$proxies = explode( ',', $proxies );
		}

		if ( ! is_array( $proxies ) ) {
			return array();
		}

		return array_values( array_filter( array_map( 'trim', $proxies ) ) );
	}

	/**
	 * Allowed X-App-Token values from the plugin options.
	 *
	 * @return array<int, string>
	 * @since  1.0.0
	 */
	public static function allowed_tokens(): array {
		$json   = get_option( 'wsp_allowed_tokens_json', '["mobile-v2","app-v3"]' );
		$tokens = json_decode( (string) $json, true );
		$tokens = is_array( $tokens ) ? array_values( array_unique( array_filter( $tokens ) ) ) : array( 'mobile-v2' );
		return array_slice( $tokens, 0, 50 );
	}

	/**
	 * Rate-limit configuration (merged defaults + custom JSON overrides).
	 *
	 * @return array<string, array<string, int>>
	 * @since  1.0.0
	 */
	public static function rate_limits(): array {
		global $wsp_default_rate_limits;

		$defaults = is_array( $wsp_default_rate_limits ) ? $wsp_default_rate_limits : array();

		$json = get_option( 'wsp_rate_limits_json', '' );

		if ( (string) $json !== '' ) {
			$custom = json_decode( (string) $json, true );
			if ( is_array( $custom ) ) {
				return array_replace_recursive( $defaults, $custom );
			}
		}

		return $defaults;
	}
}
