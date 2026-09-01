<?php
/**
 * Unit tests for trusted-proxy-aware client IP detection.
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use WooSecureProxy\Helpers\IpDetector;

if ( ! defined( 'WSP_TRUSTED_PROXIES' ) ) {
	define(
		'WSP_TRUSTED_PROXIES',
		array( '10.0.0.1', '10.0.0.2', '192.168.0.0/16', '2001:db8::/32' )
	);
}

/**
 * @covers \WooSecureProxy\Helpers\IpDetector
 */
class IpDetectorTest extends TestCase {

	private array $server_backup = array();

	protected function setUp(): void {
		parent::setUp();

		Functions\when( 'wp_unslash' )->alias( static fn( $v ) => $v );

		$this->server_backup = $_SERVER;
		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		parent::tearDown();
	}

	public function test_returns_remote_addr_when_no_forwarding_header(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';

		self::assertSame( '203.0.113.10', IpDetector::get_client_ip() );
	}

	public function test_spoofed_xff_ignored_from_untrusted_remote_addr(): void {
		$_SERVER['REMOTE_ADDR']            = '203.0.113.99';
		$_SERVER['HTTP_X_FORWARDED_FOR']   = '6.6.6.6';

		self::assertSame( '203.0.113.99', IpDetector::get_client_ip() );
	}

	public function test_trusted_single_proxy_hop_uses_xff_client(): void {
		$_SERVER['REMOTE_ADDR']            = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR']   = '203.0.113.7';

		self::assertSame( '203.0.113.7', IpDetector::get_client_ip() );
	}

	public function test_two_trusted_proxy_hops_picks_rightmost_untrusted(): void {
		// XFF: client, first proxy (trusted), second proxy (trusted).
		// REMOTE_ADDR is the last trusted proxy. Rightmost untrusted = client.
		$_SERVER['REMOTE_ADDR']          = '10.0.0.2';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5, 10.0.0.1';

		self::assertSame( '203.0.113.5', IpDetector::get_client_ip() );
	}

	public function test_cidr_match_ipv4_trusted_proxy(): void {
		$_SERVER['REMOTE_ADDR']          = '192.168.5.20';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.42';

		self::assertSame( '203.0.113.42', IpDetector::get_client_ip() );
	}

	public function test_cidr_no_match_returns_remote_addr(): void {
		$_SERVER['REMOTE_ADDR']          = '172.16.5.5';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.42';

		self::assertSame( '172.16.5.5', IpDetector::get_client_ip() );
	}

	public function test_ipv6_trusted_proxy_cidr(): void {
		$_SERVER['REMOTE_ADDR']          = '2001:db8::1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '2001:dead:beef::1';

		self::assertSame( '2001:dead:beef::1', IpDetector::get_client_ip() );
	}

	public function test_ipv6_remote_addr_not_in_trusted_list_ignores_xff(): void {
		$_SERVER['REMOTE_ADDR']          = '2001:abcd::1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '2001:dead:beef::1';

		self::assertSame( '2001:abcd::1', IpDetector::get_client_ip() );
	}

	public function test_all_xff_entries_trusted_returns_remote_addr(): void {
		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.2';

		self::assertSame( '10.0.0.1', IpDetector::get_client_ip() );
	}

	public function test_invalid_remote_addr_returns_zero(): void {
		$_SERVER['REMOTE_ADDR'] = 'not-an-ip';

		self::assertSame( '0.0.0.0', IpDetector::get_client_ip() );
	}

	public function test_empty_remote_addr_returns_zero(): void {
		unset( $_SERVER['REMOTE_ADDR'] );

		self::assertSame( '0.0.0.0', IpDetector::get_client_ip() );
	}

	public function test_trusted_proxy_but_no_xff_returns_remote_addr(): void {
		$_SERVER['REMOTE_ADDR'] = '10.0.0.1';
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );

		self::assertSame( '10.0.0.1', IpDetector::get_client_ip() );
	}

	public function test_xff_with_invalid_entries_picks_valid_untrusted(): void {
		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip, 203.0.113.9';

		self::assertSame( '203.0.113.9', IpDetector::get_client_ip() );
	}

	public function test_xff_chain_all_untrusted_picks_rightmost(): void {
		// Rightmost untrusted in the chain (REMOTE_ADDR is trusted, so walk left).
		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 203.0.113.2';

		self::assertSame( '203.0.113.2', IpDetector::get_client_ip() );
	}
}
