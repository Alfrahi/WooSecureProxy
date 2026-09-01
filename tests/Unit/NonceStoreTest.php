<?php
/**
 * Unit tests for atomic nonce storage (persistent cache + degraded DB mode).
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use WooSecureProxy\Helpers\NonceStore;

/**
 * @covers \WooSecureProxy\Helpers\NonceStore
 */
class NonceStoreTest extends TestCase {

	/** @var array<string, mixed> Fake wp_cache store. */
	private array $cache = array();

	/** @var array<string, int> Fake DB rows: nonce => expires. */
	private array $db = array();

	protected function setUp(): void {
		parent::setUp();

		$this->cache = array();
		$this->db    = array();

		$cache = &$this->cache;
		$db    = &$this->db;

		Functions\when( 'wp_cache_add' )->alias(
			static function ( string $key, $value = 1, string $group = '', int $ttl = 0 ) use ( &$cache ) {
				if ( isset( $cache[ $key ] ) ) {
					return false;
				}
				$cache[ $key ] = $value;
				return true;
			}
		);

		// Fake $wpdb for degraded-mode tests.
		$wpdb = new class( $db ) {
			/** @var array<string, int> */
			public array $rows;
			public string $prefix = 'wp_';

			/**
			 * @param array<string, int> $db Reference-free copy; methods mutate the real DB via closure below.
			 */
			public function __construct( array &$db ) {
				$this->rows = &$db;
			}

			public function prepare( string $query, ...$args ): string {
				return vsprintf( str_replace( array( '%s', '%d' ), array( "'%s'", '%d' ), $query ), $args );
			}

			public function query( string $sql ): int {
				if ( preg_match( "/INSERT IGNORE INTO \S+ \(nonce, expires\) VALUES \('([^']+)', (\d+)\)/", $sql, $m ) ) {
					if ( isset( $this->rows[ $m[1] ] ) ) {
						return 0; // Duplicate primary key.
					}
					$this->rows[ $m[1] ] = (int) $m[2];
					return 1;
				}

				if ( preg_match( '/DELETE FROM \S+ WHERE expires < (\d+)/', $sql, $m ) ) {
					$cutoff = (int) $m[1];
					$before = count( $this->rows );
					foreach ( $this->rows as $nonce => $expires ) {
						if ( $expires < $cutoff ) {
							unset( $this->rows[ $nonce ] );
						}
					}
					return $before - count( $this->rows );
				}

				return 0;
			}
		};

		$GLOBALS['wpdb'] = $wpdb;
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wpdb'] );
		parent::tearDown();
	}

	public function test_persistent_cache_atomic_claim_and_replay(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );

		self::assertTrue( NonceStore::claim( 'nonce-abc', 600 ) );
		self::assertFalse( NonceStore::claim( 'nonce-abc', 600 ) );
	}

	public function test_persistent_cache_uses_cache_add_not_transient(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );

		NonceStore::claim( 'nonce-xyz', 600 );

		self::assertArrayHasKey( 'wsp_nonce_nonce-xyz', $this->cache );
		self::assertSame( array(), $this->db );
	}

	public function test_degraded_db_mode_atomic_claim_and_replay(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		// Force purge to a no-op 100% of the time by seeding zero probability.
		// random_int can't be mocked with Brain Monkey, but the fake db handles any query.
		self::assertTrue( NonceStore::claim( 'nonce-db1', 600 ) );
		self::assertFalse( NonceStore::claim( 'nonce-db1', 600 ) );
	}

	public function test_degraded_mode_does_not_touch_object_cache(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );

		NonceStore::claim( 'nonce-db2', 600 );

		self::assertSame( array(), $this->cache );
		self::assertArrayHasKey( 'nonce-db2', $this->db );
	}

	public function test_behavior_identical_across_backends(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		$persistent_first  = NonceStore::claim( 'same-nonce', 600 );
		$persistent_replay = NonceStore::claim( 'same-nonce', 600 );

		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		$db_first  = NonceStore::claim( 'same-nonce', 600 );
		$db_replay = NonceStore::claim( 'same-nonce', 600 );

		self::assertSame( array( $persistent_first, $persistent_replay ), array( $db_first, $db_replay ) );
		self::assertTrue( $db_first );
		self::assertFalse( $db_replay );
	}

	public function test_has_persistent_cache_detection(): void {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		self::assertTrue( NonceStore::has_persistent_cache() );

		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		self::assertFalse( NonceStore::has_persistent_cache() );
	}
}
