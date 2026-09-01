<?php
/**
 * Regression tests for Prompt 3: rate limiting must apply to customerLogin /
 * customerRegister (previously bypassed — unlimited brute force).
 *
 * @package WooSecureProxy\Tests\Integration
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Integration;

use Brain\Monkey\Functions;
use WP_REST_Request;
use WooSecureProxy\Proxy\RequestHandler;

final class RateLimitAuthEndpointsTest extends TestCase
{
    private const APP_TOKEN = 'mobile-v2';

    /** @var array<string, int> Stateful fake object cache. */
    private array $store = array();

    protected function setUp(): void
    {
        parent::setUp();

        $GLOBALS['wsp_default_rate_limits'] = array(
            'default'          => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
            'customerLogin'    => array( 'ip' => 10, 'app' => 100, 'win' => 60 ),
            'customerRegister' => array( 'ip' => 5, 'app' => 50, 'win' => 60 ),
        );

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';

        $store = &$this->store;

        Functions\when( 'wp_unslash' )->alias( static fn( $v ) => $v );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'get_option' )->alias(
            static fn( string $key ) => $key === 'wsp_allowed_tokens_json' ? '["mobile-v2"]' : ''
        );

        Functions\when( 'wp_cache_get' )->alias(
            static function ( string $key ) use ( &$store ) {
                return $store[ $key ] ?? false;
            }
        );
        Functions\when( 'wp_cache_set' )->alias(
            static function ( string $key, $value ) use ( &$store ) {
                $store[ $key ] = $value;
                return true;
            }
        );

        // wp_authenticate always fails in these tests — rate limiting must trigger anyway.
        Functions\when( 'wp_authenticate' )->justReturn( new \WP_Error( 'invalid', 'bad' ) );
        Functions\when( 'sanitize_email' )->alias( static fn( $v ) => $v );
        Functions\when( 'is_email' )->alias(
            static fn( $v ) => is_string( $v ) && str_contains( $v, '@' )
        );
        Functions\when( 'email_exists' )->justReturn( false );
    }

    /** Builds a signed login/register request. */
    private function make_request( string $action ): WP_REST_Request
    {
        $body      = (string) json_encode(
            array( 'action' => $action, 'data' => array( 'username_or_email' => 'a@b.c', 'password' => 'x' ), 'method' => 'POST' )
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

    private function status_of( WP_REST_Request $request ): int
    {
        $handler  = new RequestHandler();
        $response = $handler->handle_request( $request );
        return $response->get_status();
    }

    public function test_12th_login_attempt_returns_429(): void {
        for ( $i = 1; $i <= 10; $i++ ) {
            $this->assertSame( 401, $this->status_of( $this->make_request( 'customerLogin' ) ), "attempt {$i}" );
        }

        $this->assertSame( 429, $this->status_of( $this->make_request( 'customerLogin' ) ) );
        $this->assertSame( 429, $this->status_of( $this->make_request( 'customerLogin' ) ) );
    }

    public function test_6th_register_attempt_returns_429(): void {
        for ( $i = 1; $i <= 5; $i++ ) {
            $status = $this->status_of( $this->make_request( 'customerRegister' ) );
            $this->assertNotSame( 429, $status, "attempt {$i}" );
        }

        $this->assertSame( 429, $this->status_of( $this->make_request( 'customerRegister' ) ) );
    }
}

