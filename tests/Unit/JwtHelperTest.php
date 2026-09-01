<?php
/**
 * Prompt 4 tests: JWT revocation enforcement, 60-min access TTL, refresh flow, aud claim.
 *
 * @package WooSecureProxy\Tests\Unit
 */

declare(strict_types=1);

namespace WooSecureProxy\Tests\Unit;

use Brain\Monkey\Functions;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use WooSecureProxy\Helpers\JwtHelper;

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
    define( 'DAY_IN_SECONDS', 86400 );
}

final class JwtHelperTest extends TestCase
{
    /** @var array<string, mixed> Fake transient store. */
    private array $transients = array();

    protected function setUp(): void
    {
        parent::setUp();

        $this->transients = array();
        $store            = &$this->transients;

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

        Functions\when( 'home_url' )->justReturn( 'https://example.com' );
        Functions\when( 'wp_parse_url' )->alias(
            static fn( string $url, int $component = -1 ) => $component === -1 ? parse_url( $url ) : parse_url( $url, $component )
        );

        Functions\when( 'get_user_by' )->alias(
            static function ( string $field, int $id ) {
                if ( $field === 'id' && $id > 0 ) {
                    $user        = new \stdClass();
                    $user->ID    = $id;
                    $user->roles = array( 'customer' );
                    return $user;
                }
                return false;
            }
        );
    }

    /** Decodes a token signed with PROXY_SECRET. */
    private function decode( string $token ): object
    {
        return JWT::decode( $token, new Key( PROXY_SECRET, 'HS256' ) );
    }

    public function test_issue_defaults_to_60_minute_ttl_and_customer_scope(): void {
        $payload = $this->decode( JwtHelper::issue( 42 ) );

        $this->assertSame( 3600, $payload->exp - $payload->iat );
        $this->assertSame( 'customer', $payload->scope );
        $this->assertSame( 'woosecureproxy', $payload->aud );
        $this->assertSame( 'example.com', $payload->iss );
        $this->assertNotEmpty( $payload->jti );
    }

    public function test_validate_returns_customer_id_for_valid_token(): void {
        $this->assertSame( 42, JwtHelper::validate( JwtHelper::issue( 42 ) ) );
    }

    public function test_validate_rejects_revoked_token(): void {
        $token = JwtHelper::issue( 42 );

        $this->assertNotNull( JwtHelper::validate( $token ), 'valid before revoke' );

        JwtHelper::revoke( $token );

        $this->assertTrue( JwtHelper::is_revoked( $token ) );
        $this->assertNull( JwtHelper::validate( $token ), 'revoked token must be rejected' );
    }

    public function test_validate_rejects_wrong_audience(): void {
        $payload = array(
            'iss'   => 'example.com',
            'aud'   => 'someone-else',
            'iat'   => time(),
            'exp'   => time() + 3600,
            'sub'   => 42,
            'scope' => 'customer',
            'jti'   => bin2hex( random_bytes( 16 ) ),
        );
        $token = JWT::encode( $payload, PROXY_SECRET, 'HS256' );

        $this->assertNull( JwtHelper::validate( $token ) );
    }

    public function test_refresh_issues_new_access_token(): void {
        $refresh_token = JwtHelper::issue_refresh( 42 );
        $payload       = $this->decode( $refresh_token );

        $this->assertSame( 'refresh', $payload->scope );
        $this->assertSame( 43200 * 60, $payload->exp - $payload->iat );

        $new_access = JwtHelper::refresh( $refresh_token );

        $this->assertNotNull( $new_access );
        $access_payload = $this->decode( $new_access );
        $this->assertSame( 'customer', $access_payload->scope );
        $this->assertSame( 3600, $access_payload->exp - $access_payload->iat );
        $this->assertSame( 42, JwtHelper::validate( $new_access ) );
    }

    public function test_refresh_rejects_access_token(): void {
        $access_token = JwtHelper::issue( 42 );

        $this->assertNull( JwtHelper::refresh( $access_token ), 'access scope must not refresh' );
    }

    public function test_refresh_rejects_revoked_refresh_token(): void {
        $refresh_token = JwtHelper::issue_refresh( 42 );

        JwtHelper::revoke( $refresh_token );

        $this->assertNull( JwtHelper::refresh( $refresh_token ) );
    }

    public function test_is_revoked_treats_invalid_token_as_revoked(): void {
        $this->assertTrue( JwtHelper::is_revoked( 'not-a-real-token' ) );
    }
}
