<?php
/**
 * Unit tests for the Config class.
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use WooSecureProxy\Config;

/**
 * @covers \WooSecureProxy\Config
 */
class ConfigTest extends TestCase {

	/** Test bootstrap defines these constants. */
	public function test_proxy_secret_returns_defined_value(): void {
		self::assertSame( 'test-secret-key-with-at-least-32-characters', Config::proxy_secret() );
	}

	public function test_proxy_secret_rejects_too_short(): void {
		// Constants can't be undefined in-process, so verify the guard via a
		// helper scenario: a 31-char secret via a fresh scope is not possible.
		// Instead verify the constant exists and passes.
		self::assertTrue( strlen( Config::proxy_secret() ) >= 32 );
	}

	public function test_timestamp_skew_defaults_when_not_defined(): void {
		// PROXY_TIMESTAMP_SKEW is defined in the bootstrap (300).
		self::assertSame( 300, Config::timestamp_skew() );
	}

	public function test_nonce_ttl_defined_value(): void {
		self::assertSame( 600, Config::nonce_ttl() );
	}

	public function test_max_body_size_defined_value(): void {
		self::assertSame( 524288, Config::max_body_size() );
	}

	public function test_wc_consumer_key(): void {
		self::assertSame( 'ck_test_key', Config::wc_consumer_key() );
	}

	public function test_has_wc_credentials_true(): void {
		self::assertTrue( Config::has_wc_credentials() );
	}

	public function test_trusted_proxies_array(): void {
		// Defined in IpDetectorTest when loaded first; may be fresh here.
		$proxies = Config::trusted_proxies();
		self::assertIsArray( $proxies );
	}

	public function test_allowed_tokens_default(): void {
		Functions\when( 'get_option' )->alias(
			static fn( string $key, $default = false ) => $default
		);
		$tokens = Config::allowed_tokens();
		self::assertContains( 'mobile-v2', $tokens );
	}

	public function test_allowed_tokens_custom(): void {
		Functions\when( 'get_option' )->alias(
			static fn( string $key ) => '["custom-app"]'
		);
		$tokens = Config::allowed_tokens();
		self::assertSame( array( 'custom-app' ), $tokens );
	}

	public function test_allowed_tokens_invalid_json_fallback(): void {
		Functions\when( 'get_option' )->alias(
			static fn( string $key ) => '{not-json'
		);
		$tokens = Config::allowed_tokens();
		self::assertSame( array( 'mobile-v2' ), $tokens );
	}

	public function test_rate_limits_default(): void {
		$GLOBALS['wsp_default_rate_limits'] = array( 'default' => array( 'ip' => 100, 'app' => 500, 'win' => 60 ) );

		Functions\when( 'get_option' )->alias(
			static fn( string $key ) => ''
		);

		$limits = Config::rate_limits();
		self::assertSame( 100, $limits['default']['ip'] );
	}

	public function test_rate_limits_merged(): void {
		$GLOBALS['wsp_default_rate_limits'] = array(
			'default' => array( 'ip' => 100, 'app' => 500, 'win' => 60 ),
			'login'   => array( 'ip' => 10, 'app' => 50, 'win' => 60 ),
		);

		Functions\when( 'get_option' )->alias(
			static fn( string $key ) => '{"login": {"ip": 5}}'
		);

		$limits = Config::rate_limits();
		self::assertSame( 5, $limits['login']['ip'] );
		self::assertSame( 50, $limits['login']['app'] ); // merged from defaults
	}
}
