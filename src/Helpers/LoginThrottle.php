<?php
/**
 * Per-account login throttling: tracks consecutive failures and enforces
 * temporary lockouts to slow brute-force attacks.
 *
 * Failure count is keyed by a normalized identifier (lowercased, trimmed
 * email or username) so it survives IP rotation. When the failure threshold
 * is reached the account is locked out for a fixed cooldown. A successful
 * login resets the counter.
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Account lockout tracker.
 */
class LoginThrottle {

	/** Number of consecutive failures before lockout. */
	public const MAX_FAILURES = 5;

	/** Lockout duration in seconds (15 minutes). */
	public const LOCKOUT_SECONDS = 900;

	/**
	 * Returns the normalized identifier used as the throttle key.
	 *
	 * @param string $identifier Raw email or username.
	 * @return string Normalized, lowercased key.
	 * @since  1.0.0
	 */
	public static function normalize( string $identifier ): string {
		return strtolower( trim( $identifier ) );
	}

	/**
	 * Checks whether the given identifier is currently locked out.
	 *
	 * @param string $identifier Normalized identifier.
	 * @return bool True if locked out.
	 * @since  1.0.0
	 */
	public static function is_locked_out( string $identifier ): bool {
		$lock_key = self::transient_key( $identifier );

		return (bool) get_transient( $lock_key );
	}

	/**
	 * Records a failed login attempt. When the failure count reaches
	 * MAX_FAILURES the account is locked out for LOCKOUT_SECONDS.
	 *
	 * @param string $identifier Normalized identifier.
	 * @since  1.0.0
	 */
	public static function record_failure( string $identifier ): void {
		$count_key = self::count_key( $identifier );
		$failures  = (int) get_transient( $count_key ) + 1;

		if ( $failures >= self::MAX_FAILURES ) {
			set_transient( self::transient_key( $identifier ), true, self::LOCKOUT_SECONDS );
			delete_transient( $count_key );
			return;
		}

		set_transient( $count_key, $failures, self::LOCKOUT_SECONDS );
	}

	/**
	 * Clears the failure counter and any lockout on successful login.
	 *
	 * @param string $identifier Normalized identifier.
	 * @since  1.0.0
	 */
	public static function clear( string $identifier ): void {
		delete_transient( self::transient_key( $identifier ) );
		delete_transient( self::count_key( $identifier ) );
	}

	/**
	 * Transient key for the lockout flag.
	 *
	 * @param string $identifier Normalized identifier.
	 * @return string
	 */
	private static function transient_key( string $identifier ): string {
		return 'wsp_lock_' . md5( $identifier );
	}

	/**
	 * Transient key for the failure counter.
	 *
	 * @param string $identifier Normalized identifier.
	 * @return string
	 */
	private static function count_key( string $identifier ): string {
		return 'wsp_lfails_' . md5( $identifier );
	}
}
