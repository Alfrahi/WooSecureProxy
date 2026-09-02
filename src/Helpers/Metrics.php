<?php
/**
 * Lightweight request counters for the admin status widget.
 *
 * Per action and HTTP-status-class counters, bucketed by UTC day, stored in
 * a single non-autoloaded option. Old days are pruned so the option stays
 * bounded — this is operability telemetry, not analytics.
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Daily-bucketed request counters.
 *
 * @since 1.0.0
 */
class Metrics {

	/** Option name holding the daily counter buckets. */
	public const OPTION = 'wsp_metrics_daily';

	/** Days of history to keep. */
	public const KEEP_DAYS = 2;

	/**
	 * Records one proxied request.
	 *
	 * @param string $action Action name ('unknown' when parsing failed).
	 * @param int    $status HTTP status returned to the client.
	 * @return void
	 * @since  1.0.0
	 */
	public static function record( string $action, int $status ): void {
		$all = self::load();
		$day = gmdate( 'Y-m-d' );

		// Prune old days (rare write path, so the shrink is cheap).
		foreach ( array_keys( $all ) as $d ) {
			if ( $d < gmdate( 'Y-m-d', time() - self::KEEP_DAYS * DAY_IN_SECONDS ) ) {
				unset( $all[ $d ] );
			}
		}

		$bucket = sprintf( '%dxx', (int) floor( $status / 100 ) );

		$all[ $day ][ $action ][ $bucket ] = ( $all[ $day ][ $action ][ $bucket ] ?? 0 ) + 1;
		$all[ $day ]['_total'][ $bucket ]  = ( $all[ $day ]['_total'][ $bucket ] ?? 0 ) + 1;

		update_option( self::OPTION, $all, false );
	}

	/**
	 * Returns the full stored counter map (day → action → bucket → count).
	 *
	 * @return array<string, array<string, array<string, int>>>
	 * @since  1.0.0
	 */
	public static function summary(): array {
		return self::load();
	}

	/**
	 * Loads the option, tolerating absent or malformed data.
	 *
	 * @return array<string, array<string, array<string, int>>>
	 */
	private static function load(): array {
		$raw = get_option( self::OPTION, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Removes the counter option (used by uninstall).
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public static function wipe(): void {
		delete_option( self::OPTION );
	}
}
