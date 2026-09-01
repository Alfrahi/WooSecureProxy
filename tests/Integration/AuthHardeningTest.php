<?php
/**
 * Integration tests for Prompt 7: account lockout + registration hardening.
 * Verifies brute-force lockout, reset on success, oracle uniformity, and
 * stronger password policy.
 *
 * @package WooSecureProxy\Tests\Integration
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Integration;

use Brain\Monkey\Functions;
use WP_REST_Request;
use WooSecureProxy\Proxy\RequestHandler;

final class AuthHardeningTest extends TestCase
{
    private const APP_TOKEN = 'mobile-v2';

    /** @var array<string, mixed> Fake transient store. */
    private array $transients = array();

    protected function setUp(): void
    {
        parent::setUp();

        $this->transients = array();
        $store = &$this->transients;

        $GLOBALS['wsp_default_rate_limits'] = array(
            'default'          => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
            'customerLogin'    => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
            'customerRegister' => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
        );

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';

        Functions\when( 'wp_unslash' )->alias( static fn( $v ) => $v );
        Functions\when( 'get_option' )->alias(
            static fn( string $key ) => $key === 'wsp_allowed_tokens_json' ? '["mobile-v2"]' : ''
        );

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

        Functions\when( 'wp_cache_get' )->justReturn( false );
        Functions\when( 'wp_cache_set' )->justReturn( true );
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );

        Functions\when( 'sanitize_email' )->alias( static fn( $v ) => $v );
        Functions\when( 'is_email' )->alias(
            static fn( $v ) => is_string( $v ) && str_contains( $v, '@' )
        );
        Functions\when( 'email_exists' )->justReturn( false );
    }

    private function make_request( string $action, string $identifier = 'user@example.com', string $password = 'badpass123456' ): WP_REST_Request
    {
        $body = (string) json_encode(
            array(
                'action' => $action,
                'data'   => array(
                    'username_or_email' => $identifier,
                    'email'             => $identifier,
                    'password'          => $password,
                ),
                'method' => 'POST',
            )
        );
        $timestamp = (string) time();
        $nonce     = bin2hex( random_bytes( 8 ) );

        $request = new WP_REST_Request( $body );
        $request->set_header( 'x-app-token', self::APP_TOKEN );
        $request->set_header( 'x-timestamp', $timestamp );
        $request->set_header( 'x-nonce', $nonce );
        $request->set_header( 'x-signature', hash_hmac( 'sha256', $timestamp . $nonce . $body, PROXY_SECRET ) );
        return $request;
    }

    private function handle( WP_REST_Request $request ): array
    {
        $handler  = new RequestHandler();
        $response = $handler->handle_request( $request );
        return array(
            'status' => $response->get_status(),
            'data'   => $response->get_data(),
        );
    }

    public function test_lockout_after_five_failures(): void {
        Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'bad' ) );

        for ( $i = 1; $i <= 5; $i++ ) {
            $result = $this->handle( $this->make_request( 'customerLogin' ) );
            $this->assertSame( 401, $result['status'], "failure {$i}" );
        }

        // 6th attempt is locked out.
        $result = $this->handle( $this->make_request( 'customerLogin' ) );
        $this->assertSame( 423, $result['status'], '6th attempt should be locked out' );
    }

    public function test_lockout_persists_for_new_attempts(): void {
        Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'bad' ) );

        for ( $i = 0; $i < 5; $i++ ) {
            $this->handle( $this->make_request( 'customerLogin' ) );
        }

        // Next attempt is locked out.
        $result = $this->handle( $this->make_request( 'customerLogin' ) );
        $this->assertSame( 423, $result['status'] );
        $this->assertSame( 'account_locked', $result['data']['error']['code'] ?? '' );
    }

    public function test_clear_resets_lockout(): void {
        Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'bad' ) );

        for ( $i = 0; $i < 5; $i++ ) {
            $this->handle( $this->make_request( 'customerLogin' ) );
        }

        // Lockout active.
        $this->assertSame( 423, $this->handle( $this->make_request( 'customerLogin' ) )['status'] );

        // Simulate admin clearing it.
        \WooSecureProxy\Helpers\LoginThrottle::clear( 'user@example.com' );

        // Now authentication can proceed again (still wrong password).
        $result = $this->handle( $this->make_request( 'customerLogin' ) );
        $this->assertSame( 401, $result['status'] );
    }

    public function test_oracle_uniformity_no_user_vs_wrong_password(): void {
        // Both cases return the same 401/message.
        Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'bad' ) );

        $result = $this->handle( $this->make_request( 'customerLogin', 'nonexistent@example.com' ) );
        $this->assertSame( 401, $result['status'] );
        $this->assertSame( 'invalid_credentials', $result['data']['error']['code'] ?? '' );
        $this->assertSame( 'Invalid email or password', $result['data']['error']['message'] ?? '' );
    }

    public function test_registration_rejects_short_password(): void {
        $result = $this->handle(
            $this->make_request( 'customerRegister', 'new@example.com', 'short' )
        );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'invalid_data', $result['data']['error']['code'] ?? '' );
    }

    public function test_registration_rejects_password_matching_email(): void {
        $result = $this->handle(
            $this->make_request( 'customerRegister', 'new@example.com', 'new@example.com' )
        );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'weak_password', $result['data']['error']['code'] ?? '' );
    }

    public function test_registration_rejects_password_matching_username(): void {
        $body = json_encode(
            array(
                'action' => 'customerRegister',
                'data'   => array(
                    'email'    => 'new@example.com',
                    'username' => 'longusername12',
                    'password' => 'longusername12',
                ),
                'method' => 'POST',
            )
        );
        $timestamp = (string) time();
        $nonce     = bin2hex( random_bytes( 8 ) );
        $request   = new WP_REST_Request( $body );
        $request->set_header( 'x-app-token', self::APP_TOKEN );
        $request->set_header( 'x-timestamp', $timestamp );
        $request->set_header( 'x-nonce', $nonce );
        $request->set_header( 'x-signature', hash_hmac( 'sha256', $timestamp . $nonce . $body, PROXY_SECRET ) );

        $result = $this->handle( $request );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'weak_password', $result['data']['error']['code'] ?? '' );
    }
}

