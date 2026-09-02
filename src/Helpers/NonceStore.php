<?php
/**
 * Durable, atomic nonce storage for replay-attack protection.
 *
 * Two backends:
 * 1. Persistent object cache (Redis, Memcached, etc.) — atomic wp_cache_add().
 * 2. Degraded mode: custom DB table via $wpdb, with an atomic INSERT that
 *    fails on duplicate primary key. Used when no persistent object cache is
 *    detected. An admin notice warns that rate limiting is also degraded.
 *
 * The claim operation is atomic in both backends — a nonce can never be
 * claimed twice concurrently.
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Atomic nonce claim store.
 */
class NonceStore {

	/**
	 * Returns whether a persistent object cache backend is active.
	 *
	 * @return bool
	 * @since  1.0.0
	 */
	public static function has_persistent_cache(): bool {
		return function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache();
	}

	/**
	 * Attempts to claim a nonce. Returns true if this is the first use,
	 * false if the nonce was already claimed (replay).
	 *
	 * The check-and-set is atomic in both backends.
	 *
	 * @param string $nonce Client-provided nonce.
	 * @param int    $ttl   Seconds the nonce remains claimed.
	 * @return bool True on first claim, false on replay.
	 * @since  1.0.0
	 */
	public static function claim( string $nonce, int $ttl ): bool {
		if ( self::has_persistent_cache() ) {
			// wp_cache_add() is atomic: returns false if the key already exists.
			return (bool) wp_cache_add( "wsp_nonce_{$nonce}", 1, 'wsp_nonces', $ttl );
		}

		return self::claim_via_db( $nonce, $ttl );
	}

	/**
	 * DB-backed degraded-mode claim using INSERT IGNORE into a dedicated table.
	 *
	 * The nonce column is the PRIMARY KEY, so the INSERT is atomic: a
	 * duplicate silently affects 0 rows.
	 *
	 * @param string $nonce Nonce to claim.
	 * @param int    $ttl   Seconds the nonce remains claimed.
	 * @return bool True on first claim, false on replay.
	 * @since  1.0.0
	 */
	private static function claim_via_db( string $nonce, int $ttl ): bool {
		global $wpdb;

		$table = self::table_name();

		// Lazy purge of expired nonces — amortized, ~1% of requests.
		if ( 1 === random_int( 1, 100 ) ) {
			self::purge_expired();
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching -- Nonce durability requires direct writes.
		$affected = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is derived internally, never from user input.
				"INSERT IGNORE INTO {$table} (nonce, expires) VALUES (%s, %d)",
				$nonce,
				time() + $ttl
			)
		);

		return 1 === (int) $affected;
	}

	/**
	 * Removes expired nonce rows.
	 *
	 * @since  1.0.0
	 */
	private static function purge_expired(): void {
		global $wpdb;

		$table = self::table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance query, not hot-path.
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is derived internally.
				"DELETE FROM {$table} WHERE expires < %d",
				time()
			)
		);
	}

	/**
	 * Returns the nonce table name with the WP prefix.
	 *
	 * @return string
	 * @since  1.0.0
	 */
	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . 'wsp_nonces';
	}

	/**
	 * Creates the nonce table via dbDelta. Called on activation/upgrade.
	 *
	 * @since  1.0.0
	 */
	public static function create_table(): void {
		global $wpdb;

		$table           = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			nonce varchar(64) NOT NULL,
			expires bigint(20) unsigned NOT NULL,
			PRIMARY KEY  (nonce),
			KEY expires (expires)
		) {$charset_collate};";

		// @phpstan-ignore-next-line (upgrade.php only exists on a real WordPress install; this runs exclusively in that context.)
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
