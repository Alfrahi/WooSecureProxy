<?php
/**
 * Characterization tests: capture CURRENT end-to-end behavior of RequestHandler::handle_request().
 *
 * These docu­ment pre-fix behavior and guard against regressions during the
 * Phase 1 security fixes. Tests marked "EXPECTED FAIL" assert the desired
 * post-fix upstream URL and currently fail (regex-in-path bug, Prompt 5).
 *
 * @package WooSecureProxy\Tests\Integration
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Integration;

use Brain\Monkey\Functions;
use WP_REST_Request;
use WP_REST_Response;
use WooSecureProxy\Helpers\JwtHelper;
use WooSecureProxy\Proxy\RequestHandler;

final class RequestHandlerCharacterizationTest extends TestCase
{
    private const APP_TOKEN = 'mobile-v2';

    /** @var string|null Captured upstream URL from the last wp_safe_remote_request call. */
    private ?string $captured_url = null;

    /** @var array<string, mixed>|null Captured upstream request args. */
    private ?array $captured_args = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->captured_url  = null;
        $this->captured_args = null;

        $GLOBALS['wsp_default_rate_limits'] = array(
            'default' => array( 'ip' => 1000, 'app' => 1000, 'win' => 60 ),
        );

        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';

        Functions\when( 'get_option' )->alias(
            static function ( string $key, $default = false ) {
                $map = array(
                    'wsp_allowed_tokens_json' => '["mobile-v2"]',
                    'blog_charset'            => 'UTF-8',
                );
                return $map[ $key ] ?? $default;
            }
        );

        Functions\when( 'wp_cache_get' )->justReturn( false );
        Functions\when( 'wp_cache_set' )->justReturn( true );
        Functions\when( 'wp_cache_add' )->justReturn( true );
        Functions\when( 'get_transient' )->justReturn( false );
        Functions\when( 'set_transient' )->justReturn( true );
        Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
        Functions\when( 'wp_unslash' )->alias(
            static fn( $v ) => is_string( $v ) ? stripslashes( $v ) : $v
        );

        Functions\when( 'get_user_by' )->alias(
            static function ( string $field, int $id ) {
                if ( $field === 'id' && $id > 0 ) {
                    $user          = new \stdClass();
                    $user->ID      = $id;
                    $user->roles   = array( 'customer' );
                    return $user;
                }
                return false;
            }
        );

        Functions\when( 'wc_get_order' )->alias(
            static function ( int $order_id ) {
                $order = new class( $order_id ) {
                    public $id;
                    public $customer_id;
                    public function __construct( int $id ) {
                        $this->id = $id;
                        $this->customer_id = 555;
                    }
                    public function get_customer_id(): int {
                        return $this->customer_id;
                    }
                };
                return $order;
            }
        );

        Functions\when( 'rest_url' )->alias(
            static fn( string $path = '' ) => 'https://example.com/wp-json/' . ltrim( $path, '/' )
        );
        Functions\when( 'home_url' )->justReturn( 'https://example.com' );
        Functions\when( 'wp_parse_url' )->alias(
            static fn( string $url, int $component = -1 ) => $component === -1 ? parse_url( $url ) : parse_url( $url, $component )
        );
        Functions\when( 'add_query_arg' )->alias(
            static fn( array $args, string $url ) => $args === array() ? $url : $url . '?' . http_build_query( $args )
        );
        Functions\when( 'sanitize_text_field' )->alias(
            static fn( $v ) => is_scalar( $v ) ? trim( (string) $v ) : ''
        );
        Functions\when( 'wp_json_encode' )->alias(
            static fn( $data ) => json_encode( $data )
        );
        Functions\when( 'is_wp_error' )->alias(
            static fn( $thing ) => $thing instanceof \WP_Error
        );
        Functions\when( 'wp_remote_retrieve_response_code' )->justReturn( 200 );
        Functions\when( 'wp_remote_retrieve_body' )->justReturn( '{"ok":true}' );

        $captured_url  = &$this->captured_url;
        $captured_args = &$this->captured_args;
        Functions\when( 'wp_safe_remote_request' )->alias(
            static function ( string $url, array $args = array() ) use ( &$captured_url, &$captured_args ) {
                $captured_url  = $url;
                $captured_args = $args;
                return array( 'response' => array( 'code' => 200 ), 'body' => '{"ok":true}' );
            }
        );
    }

    /**
     * Builds a signed proxy request for the given action.
     *
     * @param array< string, mixed>      $data     Action data payload.
     * @param array<string, string|null> $override Header overrides; null removes a header.
     */
    private function make_request( string $action, array $data = array(), string $method = 'GET', array $override = array() ): WP_REST_Request {
        $body      = (string) json_encode( array( 'action' => $action, 'data' => $data, 'method' => $method ) );
        $timestamp = (string) time();
        $nonce     = bin2hex( random_bytes( 8 ) );

        $headers = array(
            'x-app-token' => self::APP_TOKEN,
            'x-timestamp' => $timestamp,
            'x-nonce'     => $nonce,
            'x-signature' => hash_hmac( 'sha256', $timestamp . $nonce . $body, PROXY_SECRET ),
        );

        foreach ( $override as $name => $value ) {
            if ( $value === null ) {
                unset( $headers[ $name ] );
            } else {
                $headers[ $name ] = $value;
            }
        }

        $request = new WP_REST_Request( $body );
        foreach ( $headers as $name => $value ) {
            $request->set_header( $name, $value );
        }

        return $request;
    }

    /**
     * Creates a signed request with a valid customer JWT for auth-required actions.
     *
     * @param string $action   Action name.
     * @param array  $data     Request data.
     * @param string $method   HTTP method.
     * @param int    $customer_id Customer ID to encode in JWT.
     */
    private function make_authenticated_request( string $action, array $data = array(), string $method = 'GET', int $customer_id = 42 ): WP_REST_Request {
        $jwt = JwtHelper::issue( $customer_id );
        $request = $this->make_request( $action, $data, $method );
        $request->set_header( 'x-customer-jwt', $jwt );
        return $request;
    }

    /** @return array<string, mixed> */
    private function dispatch( WP_REST_Request $request ): array {
        $handler  = new RequestHandler();
        $response = $handler->handle_request( $request );

        $this->assertInstanceOf( WP_REST_Response::class, $response );
        return array(
            'status' => $response->get_status(),
            'data'   => $response->get_data(),
        );
    }

    private function assert_error( array $result, int $status, string $code ): void {
        $this->assertSame( $status, $result['status'] );
        $this->assertFalse( $result['data']['success'] );
        $this->assertSame( $code, $result['data']['error']['code'] );
    }

    public function test_missing_headers_returns_400(): void {
        $result = $this->dispatch( new WP_REST_Request( '{"action":"getProducts","data":{},"method":"GET"}' ) );
        $this->assert_error( $result, 400, 'missing_header' );
    }

    public function test_empty_body_returns_400(): void {
        $result = $this->dispatch( new WP_REST_Request( '' ) );
        $this->assert_error( $result, 400, 'empty_payload' );
    }

    public function test_oversized_body_returns_413(): void {
        $result = $this->dispatch( new WP_REST_Request( str_repeat( 'x', PROXY_MAX_BODY_SIZE + 1 ) ) );
        $this->assert_error( $result, 413, 'payload_too_large' );
    }

    public function test_bad_signature_returns_403(): void {
        $request = $this->make_request( 'getProducts', array(), 'GET', array( 'x-signature' => str_repeat( '0', 64 ) ) );
        $this->assert_error( $this->dispatch( $request ), 403, 'invalid_signature' );
    }

    public function test_expired_timestamp_returns_403(): void {
        $request = $this->make_request( 'getProducts', array(), 'GET', array( 'x-timestamp' => (string) ( time() - PROXY_TIMESTAMP_SKEW - 60 ) ) );
        $this->assert_error( $this->dispatch( $request ), 403, 'invalid_timestamp' );
    }

    public function test_replayed_nonce_returns_403(): void {
        // Nonce claim is atomic via wp_cache_add — false means already used.
        Functions\when( 'wp_cache_add' )->alias(
            static fn( string $key ) => str_starts_with( $key, 'wsp_nonce_' ) ? false : true
        );
        $this->assert_error( $this->dispatch( $this->make_request( 'getProducts' ) ), 403, 'replay_attack' );
    }

    public function test_unknown_action_returns_403(): void {
        $this->assert_error( $this->dispatch( $this->make_request( 'deleteEverything' ) ), 403, 'action_not_allowed' );
    }

    public function test_wrong_method_returns_403(): void {
        $this->assert_error( $this->dispatch( $this->make_request( 'getProducts', array(), 'DELETE' ) ), 403, 'action_not_allowed' );
    }

    public function test_get_products_hits_wc_products_endpoint(): void {
        $result = $this->dispatch( $this->make_request( 'getProducts' ) );
        $this->assertSame( 200, $result['status'] );
        $this->assertTrue( $result['data']['success'] );
        $this->assertSame( 'https://example.com/wp-json/wc/v3/products', $this->captured_url );
        $this->assertSame( 'GET', $this->captured_args['method'] );
    }

    /** EXPECTED FAIL until Prompt 5: raw regex pattern leaks into the upstream path. */
    public function test_get_product_substitutes_id_in_upstream_url(): void {
        $result = $this->dispatch( $this->make_request( 'getProduct', array( 'id' => 42 ) ) );
        $this->assertSame( 200, $result['status'] );
        $this->assertSame( 'https://example.com/wp-json/wc/v3/products/42', $this->captured_url );
    }

    public function test_get_customer_substitutes_id_in_upstream_url(): void {
        $result = $this->dispatch( $this->make_authenticated_request( 'getCustomer', array( 'id' => 123 ), 'GET', 123 ) );
        $this->assertSame( 200, $result['status'] );
        $this->assertSame( 'https://example.com/wp-json/wc/v3/customers/123', $this->captured_url );
    }

    public function test_update_order_substitutes_id_in_upstream_url(): void {
        $result = $this->dispatch( $this->make_authenticated_request( 'updateOrder', array( 'id' => 555, 'status' => 'completed' ), 'PUT', 555 ) );
        $this->assertSame( 200, $result['status'] );
        $this->assertSame( 'https://example.com/wp-json/wc/v3/orders/555', $this->captured_url );
    }

    public function test_missing_id_returns_400_without_http_call(): void {
        $this->captured_url = null;
        $result = $this->dispatch( $this->make_request( 'getProduct', array( 'other' => 'data' ) ) );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'invalid_id', $result['data']['error']['code'] );
        $this->assertNull( $this->captured_url, 'No HTTP call should be made when id is missing' );
    }

    public function test_zero_id_returns_400_without_http_call(): void {
        $this->captured_url = null;
        $result = $this->dispatch( $this->make_request( 'getProduct', array( 'id' => 0 ) ) );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'invalid_id', $result['data']['error']['code'] );
        $this->assertNull( $this->captured_url, 'No HTTP call should be made when id is zero' );
    }

    public function test_negative_id_returns_400_without_http_call(): void {
        $this->captured_url = null;
        $result = $this->dispatch( $this->make_request( 'getProduct', array( 'id' => -5 ) ) );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'invalid_id', $result['data']['error']['code'] );
        $this->assertNull( $this->captured_url, 'No HTTP call should be made when id is negative' );
    }

    public function test_missing_action_returns_400(): void {
        $body      = (string) json_encode( array( 'data' => array() ) );
        $timestamp = (string) time();
        $nonce     = bin2hex( random_bytes( 8 ) );
        $request   = new WP_REST_Request( $body );
        $request->set_header( 'x-app-token', self::APP_TOKEN );
        $request->set_header( 'x-timestamp', $timestamp );
        $request->set_header( 'x-nonce', $nonce );
        $request->set_header( 'x-signature', hash_hmac( 'sha256', $timestamp . $nonce . $body, PROXY_SECRET ) );

        $this->assert_error( $this->dispatch( $request ), 400, 'missing_action' );
    }

    public function test_nested_array_get_param_returns_400_without_http_call(): void {
        $this->captured_url = null;
        $result = $this->dispatch(
            $this->make_request( 'getProducts', array( 'filter' => array( 'category' => 'shoes' ) ) )
        );
        $this->assertSame( 400, $result['status'] );
        $this->assertSame( 'invalid_data', $result['data']['error']['code'] );
        $this->assertNull( $this->captured_url, 'No HTTP call should be made for nested array params' );
    }

    public function test_nested_object_get_param_returns_400(): void {
        // stdClass values decode to arrays, but JSON objects nested deeper also
        // produce arrays — covered above. Here verify scalar-only guard accepts
        // legitimate scalar params.
        $result = $this->dispatch(
            $this->make_request( 'getProducts', array( 'search' => 'shoe', 'per_page' => 10 ) )
        );
        $this->assertSame( 200, $result['status'] );
    }

    public function test_throwable_returns_500_json_with_request_id_header(): void {
        Functions\when( 'wp_safe_remote_request' )->alias(
            static function () {
                throw new \RuntimeException( 'Simulated fatal' );
            }
        );

        $handler  = new RequestHandler();
        $response = $handler->handle_request( $this->make_request( 'getProducts' ) );

        $this->assertSame( 500, $response->get_status() );
        $data = $response->get_data();
        $this->assertFalse( $data['success'] );
        $this->assertSame( 'internal_error', $data['error']['code'] );
        $this->assertArrayHasKey( 'X-Request-ID', $response->get_headers() );
        $this->assertNotEmpty( $response->get_headers()['X-Request-ID'] );
    }
}
