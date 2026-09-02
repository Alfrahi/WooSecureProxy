<?php
/**
 * Observability tests (Prompt 15).
 *
 * Asserts that across a full request lifecycle, no secret material
 * (passwords, PROXY_SECRET, JWTs) ever appears in the structured log output.
 *
 * @package WooSecureProxy\Tests\Integration
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Integration;

use Brain\Monkey\Functions;
use WP_REST_Request;
use WooSecureProxy\Proxy\RequestHandler;

final class ObservabilityTest extends TestCase {

	private const APP_TOKEN = 'mobile-v2';
	private const PASSWORD  = 'Gr4phite-Krypton-9921!';
	private const SENTINEL  = 'deadbeefcafe-unique-jwt-sentinel';

	/** @var array<string, mixed> Fake transient store. */
	private array $transients = array();

	protected function setUp(): void {
		parent::setUp();

		$GLOBALS['wsp_test_log_buffer'] = array();
		$this->transients               = array();
		$store                          = &$this->transients;

		$GLOBALS['wsp_default_rate_limits'] = array(
			'default' => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
		);
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';

		Functions\when( 'wp_unslash' )->alias( static fn( $v ) => $v );
		Functions\when( 'get_option' )->alias(
			static fn( string $key, $default = false ) => 'wsp_allowed_tokens_json' === $key ? '["mobile-v2"]' : $default
		);
		Functions\when( 'get_transient' )->alias(
			static function ( string $key ) use ( &$store ) {
				return $store[ $key ] ?? false;
			}
		);
		Functions\when( 'set_transient' )->justReturn( true );
		Functions\when( 'wp_cache_get' )->justReturn( false );
		Functions\when( 'wp_cache_set' )->justReturn( true );
		Functions\when( 'wp_cache_add' )->justReturn( true );
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		Functions\when( 'update_option' )->justReturn( true );

		Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'wrong credentials' ) );
	}

	private function make_request( string $action, array $data = array(), string $method = 'POST', ?string $jwt = null ): WP_REST_Request {
		$body      = (string) json_encode( array( 'action' => $action, 'data' => $data, 'method' => $method ) );
		$timestamp = (string) time();
		$nonce     = bin2hex( random_bytes( 8 ) );

		$request = new WP_REST_Request( $body );
		$request->set_header( 'x-app-token', self::APP_TOKEN );
		$request->set_header( 'x-timestamp', $timestamp );
		$request->set_header( 'x-nonce', $nonce );
		$request->set_header( 'x-signature', hash_hmac( 'sha256', $timestamp . $nonce . $body, PROXY_SECRET ) );
		if ( null !== $jwt ) {
			$request->set_header( 'x-customer-jwt', $jwt );
		}
		return $request;
	}

	private function full_log_text(): string {
		return implode( "\n", $GLOBALS['wsp_test_log_buffer'] ?? array() );
	}

	private function assert_no_secret_material_in_logs(): void {
		$logs = $this->full_log_text();
		$this->assertStringNotContainsString( self::PASSWORD, $logs, 'password leaked into logs' );
		$this->assertStringNotContainsString( PROXY_SECRET, $logs, 'PROXY_SECRET leaked into logs' );
		$this->assertStringNotContainsString( self::SENTINEL, $logs, 'JWT leaked into logs' );
		// Consumer credentials must never appear either.
		$this->assertStringNotContainsString( WC_CONSUMER_KEY, $logs, 'consumer key leaked' );
		$this->assertStringNotContainsString( WC_CONSUMER_SECRET, $logs, 'consumer secret leaked' );
	}

	public function test_failed_login_lifecycle_logs_nothing_secret(): void {
		for ( $i = 0; $i < 6; $i++ ) {
			$request  = $this->make_request(
				'customerLogin',
				array(
					'username_or_email' => 'victim@example.com',
					'password'          => self::PASSWORD,
				)
			);
			$response = ( new RequestHandler() )->handle_request( $request );
			$this->assertContains( $response->get_status(), array( 401, 423 ) );
		}

		$this->assertNotSame( '', $this->full_log_text(), 'expected some log output' );
		$this->assert_no_secret_material_in_logs();
	}

	public function test_logout_with_jwt_does_not_log_token(): void {
		$request  = $this->make_request(
			'customerLogout',
			array( 'refresh_token' => self::SENTINEL . '.refresh' ),
			'POST',
			self::SENTINEL . '.access'
		);
		$response = ( new RequestHandler() )->handle_request( $request );
		$this->assertSame( 200, $response->get_status() );

		$this->assert_no_secret_material_in_logs();
	}

	public function test_unknown_action_and_signature_failures_log_no_secrets(): void {
		// Unknown action.
		$response = ( new RequestHandler() )->handle_request(
			$this->make_request( 'definitelyNotAnAction', array( 'password' => self::PASSWORD ) )
		);
		$this->assertSame( 403, $response->get_status() );

		// Bad signature.
		$bad = $this->make_request( 'getProducts', array( 'password' => self::PASSWORD ) );
		$bad->set_header( 'x-signature', str_repeat( '0', 64 ) );
		$response = ( new RequestHandler() )->handle_request( $bad );
		$this->assertSame( 403, $response->get_status() );

		$this->assertNotSame( '', $this->full_log_text() );
		$this->assert_no_secret_material_in_logs();
	}
}
