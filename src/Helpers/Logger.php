<?php
/**
 * Structured logging for WooSecureProxy.
 *
 * Primary sink is the WooCommerce logger (wc_get_logger(), source
 * 'woosecureproxy') carrying a JSON-structured message. When WooCommerce is
 * unavailable, falls back to error_log(). Gating semantics preserved:
 * - WP_DEBUG on  → INFO, WARN, ERROR
 * - WP_DEBUG off → WARN and ERROR only (INFO is dropped)
 *
 * Security invariant: never log secrets, passwords, tokens or JWTs — only
 * hashes, IDs, actions, IPs and status codes. Tested in
 * tests/Integration/ObservabilityTest.php.
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Severity-aware structured logger; INFO is silenced unless WP_DEBUG is on.
 *
 * @since 1.0.0
 */
class Logger {

	/**
	 * Logs an informational message (only when WP_DEBUG is enabled).
	 *
	 * @param string               $msg Log message (must not contain secrets).
	 * @param array<string, mixed> $ctx Optional structured context (meshes into JSON).
	 * @return void
	 * @since  1.0.0
	 */
	public static function info( string $msg, array $ctx = array() ): void {
		self::write( $msg, 'NOTICE', $ctx );
	}

	/**
	 * Logs a warning. Always logged, regardless of WP_DEBUG.
	 *
	 * @param string               $msg Log message (must not contain secrets).
	 * @param array<string, mixed> $ctx Optional structured context.
	 * @return void
	 * @since  1.0.0
	 */
	public static function warning( string $msg, array $ctx = array() ): void {
		self::write( $msg, 'WARNING', $ctx );
	}

	/**
	 * Logs an error. Always logged, regardless of WP_DEBUG.
	 *
	 * @param string               $msg Log message (must not contain secrets).
	 * @param array<string, mixed> $ctx Optional structured context.
	 * @return void
	 * @since  1.0.0
	 */
	public static function error( string $msg, array $ctx = array() ): void {
		self::write( $msg, 'ERROR', $ctx );
	}

	/**
	 * Maps internal severities to WC log level and WC PSR-3 level names.
	 *
	 * @param string $level Internal severity.
	 * @return string WC_Logger level string.
	 * @since  1.0.0
	 */
	private static function wc_level( string $level ): string {
		return 'NOTICE' === $level ? 'info' : strtolower( $level );
	}

	/**
	 * Internal writer.
	 *
	 * Builds a JSON-lines record, then hands it to wc_get_logger() when
	 * WooCommerce is active, or to error_log() otherwise.
	 *
	 * @param string               $msg   Log message.
	 * @param string               $level One of 'NOTICE', 'WARNING', 'ERROR'.
	 * @param array<string, mixed> $ctx   Structured context.
	 * @return void
	 * @since  1.0.0
	 */
	private static function write( string $msg, string $level, array $ctx = array() ): void {
		if ( 'NOTICE' === $level && ! ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) {
			return; // Production drops INFO entirely.
		}

		$record = array(
			'level'     => $level,
			'message'   => self::sanitize( $msg ),
			'context'   => $ctx,
			'timestamp' => gmdate( 'c' ),
		);
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Fallback only when WordPress is unavailable (tests/early boot).
		$json = function_exists( 'wp_json_encode' ) ? (string) wp_json_encode( $record ) : (string) json_encode( $record );

		if ( function_exists( 'wc_get_logger' ) ) {
			$logger = wc_get_logger();
			$logger->log(
				self::wc_level( $level ),
				$json,
				array( 'source' => 'woosecureproxy' )
			);
			return;
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Fallback sink when WooCommerce is unavailable.
		error_log( $json );
	}

	/**
	 * Strips control characters from log messages (log-injection hygiene).
	 *
	 * @param string $msg Raw message.
	 * @return string Sanitized message.
	 * @since  1.0.0
	 */
	private static function sanitize( string $msg ): string {
		return strtr(
			$msg,
			array(
				"\r" => ' ',
				"\n" => ' ',
				"\0" => '',
			)
		);
	}
}
