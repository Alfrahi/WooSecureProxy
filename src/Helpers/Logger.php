<?php
/**
 * Simple, lightweight logging utility for WooSecureProxy.
 *
 * Writes structured log messages to PHP's error log with appropriate severity levels.
 * Respects WordPress debug settings:
 * - When WP_DEBUG is true → all messages (INFO, WARN, ERROR) are logged with timestamp
 * - When WP_DEBUG is false → only WARN and ERROR are logged (INFO is silenced)
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Severity-aware error_log writer; INFO is silenced unless WP_DEBUG is on.
 *
 * @since 1.0.0
 */
class Logger {

	/**
	 * Logs an informational message.
	 *
	 * Visible only when WP_DEBUG is enabled.
	 *
	 * @param string $msg Log message.
	 * @return void
	 * @since  1.0.0
	 */
	public static function info( string $msg ): void {
		self::write( $msg, 'INFO' );
	}

	/**
	 * Logs a warning message.
	 *
	 * Always logged, regardless of WP_DEBUG setting.
	 *
	 * @param string $msg Log message.
	 * @return void
	 * @since  1.0.0
	 */
	public static function warning( string $msg ): void {
		self::write( $msg, 'WARN' );
	}

	/**
	 * Logs an error message.
	 *
	 * Always logged, regardless of WP_DEBUG setting.
	 *
	 * @param string $msg Log message.
	 * @return void
	 * @since  1.0.0
	 */
	public static function error( string $msg ): void {
		self::write( $msg, 'ERROR' );
	}

	/**
	 * Internal writer – outputs to PHP error log with consistent formatting.
	 *
	 * @param string $msg   Log message.
	 * @param string $level One of 'INFO', 'WARN', or 'ERROR'.
	 * @return void
	 * @since  1.0.0
	 */
	private static function write( string $msg, string $level ): void {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// Full debug mode: include ISO 8601 timestamp.
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- This class IS the plugin's logging facility.
			error_log( "[WooSecureProxy] [{$level}] " . gmdate( 'c' ) . " – {$msg}" );
		} elseif ( in_array( $level, array( 'ERROR', 'WARN' ), true ) ) {
			// Production: only warnings and errors, no timestamp.
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- This class IS the plugin's logging facility.
			error_log( "[WooSecureProxy] [{$level}] {$msg}" );
		}
		// INFO messages are silently dropped in production.
	}
}
