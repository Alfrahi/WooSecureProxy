<?php
/**
 * Unit tests for per-account login throttling.
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use WooSecureProxy\Helpers\LoginThrottle;

/**
 * @covers \WooSecureProxy\Helpers\LoginThrottle
 */
class LoginThrottleTest extends TestCase {

	/** @var array<string, mixed> Fake transient store. */
	private array $store = array();

	protected function setUp(): void {
		parent::setUp();

		$this->store = array();
		$store       = &$this->store;

		Functions\when( 'get_transient' )->alias(
			static function ( string $key ) use ( &$store ) {
				return $store[ $key ] ?? false;
			}
		);
		Functions\when( 'set_transient' )->alias(
			static function ( string $key, $value ) use ( &$store ) {
				$store[ $key ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			static function ( string $key ) use ( &$store ) {
				unset( $store[ $key ] );
				return true;
			}
		);
	}
	public function test_not_locked_out_initially(): void {
		self::assertFalse( LoginThrottle::is_locked_out( 'user@example.com' ) );
	}

	public function test_five_failures_trigger_lockout(): void {
		$id = 'attacker@evil.com';

		for ( $i = 0; $i < LoginThrottle::MAX_FAILURES; $i++ ) {
			LoginThrottle::record_failure( $id );
		}

		self::assertTrue( LoginThrottle::is_locked_out( $id ) );
	}

	public function test_lockout_last_15_minutes(): void {
		$id = 'user@example.com';

		for ( $i = 0; $i < LoginThrottle::MAX_FAILURES; $i++ ) {
			LoginThrottle::record_failure( $id );
		}

		$key = 'wsp_lock_' . md5( $id );
		self::assertArrayHasKey( $key, $this->store );
		self::assertSame( true, $this->store[ $key ] );
	}

	public function test_success_clears_lockout(): void {
		$id = 'user@example.com';

		for ( $i = 0; $i < LoginThrottle::MAX_FAILURES; $i++ ) {
			LoginThrottle::record_failure( $id );
		}
		self::assertTrue( LoginThrottle::is_locked_out( $id ) );

		LoginThrottle::clear( $id );
		self::assertFalse( LoginThrottle::is_locked_out( $id ) );
	}

	public function test_normalize_lowercases_and_trims(): void {
		self::assertSame( 'user@example.com', LoginThrottle::normalize( '  User@Example.COM  ' ) );
	}

	public function test_different_users_do_not_interfere(): void {
		$a = 'a@example.com';
		$b = 'b@example.com';

		for ( $i = 0; $i < LoginThrottle::MAX_FAILURES; $i++ ) {
			LoginThrottle::record_failure( $a );
		}

		self::assertTrue( LoginThrottle::is_locked_out( $a ) );
		self::assertFalse( LoginThrottle::is_locked_out( $b ) );
	}
}
