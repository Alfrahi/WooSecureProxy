<?php
declare(strict_types=1);

/**
 * JWT Helper for customer authentication tokens.
 *
 * Handles issuance, validation, revocation, and revocation checking of short-lived
 * customer JWTs using HS256 and the global PROXY_SECRET.
 *
 * These tokens are used to authenticate logged-in customers when making requests
 * through the secure proxy (e.g. mobile app, POS, etc.).
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */
namespace WooSecureProxy\Helpers;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Exception;

class JwtHelper
{
    /**
     * Returns the PROXY_SECRET if it is properly defined and strong enough.
     *
     * @return string The secret key, or empty string if missing/invalid.
     */
    им    private static function getSecret(): string
    {
        return defined('PROXY_SECRET') && is_string(PROXY_SECRET) && strlen(PROXY_SECRET) >= 32
        ? PROXY_SECRET
        : '';
    }

    /**
     * Issues a new JWT for a given customer.
     *
     * @param int $customerId        WordPress user ID of the customer.
     * @param int $expiresMinutes    Token lifetime in minutes (default: 10080 = 7 days).
     *
     * @return string Encoded JWT token.
     * @throws Exception If PROXY_SECRET is not configured properly.
     * @since  1.0.0
     */
    public static function issue(int $customerId, int $expiresMinutes = 10080): string
    {
        $secret = self::getSecret();
        if ($secret === '') {
            throw new Exception('PROXY_SECRET is not defined or too weak');
        }

        $issuedAt = time();
        $expireAt = $issuedAt + ($expiresMinutes * 60);

        $payload = [
            'iss'    => parse_url(home_url(), PHP_URL_HOST), // Issuer (site domain)
            'iat'    => $issuedAt,                           // Issued at
            'exp'    => $expireAt,                           // Expiration time
            'sub'    => $customerId,                         // Subject (customer ID)
            'scope'  => 'customer',                          // Fixed scope
            'jti'    => bin2hex(random_bytes(16)),           // Unique token ID (for revocation)
        ];

        return JWT::encode($payload, $secret, 'HS256');
    }

    /**
     * Validates a JWT and returns the customer ID if valid.
     *
     * Performs full validation including:
     * - Signature verification
     * - Expiration, not-before, issuer
     * - Scope and subject checks
     * - User existence and role verification
     *
     * @param string|null $token Raw JWT token from Authorization header.
     *
     * @return int|null Customer user ID on success, null on any failure.
     * @since  1.0.0
     */
    public static function validate(?string $token): ?int
    {
        if (!$token) {
            return null;
        }

        $secret = self::getSecret();
        if ($secret === '') {
            return null;
        }

        try {
            $decoded = JWT::decode($token, new Key($secret, 'HS256'));

            // Required claims
            if (!isset($decoded->sub) || !is_numeric($decoded->sub)) {
                return null;
            }

            if (($decoded->scope ?? '') !== 'customer') {
                return null;
            }

            if (($decoded->iss ?? '') !== parse_url(home_url(), PHP_URL_HOST)) {
                return null;
            }

            $customerId = (int)$decoded->sub;
            $user = get_user_by('id', $customerId);

            if (!$user || !in_array('customer', (array)$user->roles, true)) {
                return null;
            }

            return $customerId;

        } catch (ExpiredException $e) {
            return null; // Token expired
        } catch (SignatureInvalidException $e) {
            return null; // Invalid signature
        } catch (BeforeValidException $e) {
            return null; // Token not yet valid
        } catch (Exception $e) {
            return null; // Any other JWT error
        }
    }

    /**
     * Revokes a JWT by storing its JTI (JWT ID) in a transient for 30 days.
     *
     * @param string $token The JWT to revoke.
     * @return void
     * @since  1.0.0
     */
    public static function revoke(string $token): void
    {
        try {
            $decoded = JWT::decode($token, new Key(self::getSecret(), 'HS256'));
            if (isset($decoded->jti)) {
                set_transient('wsp_jwt_revoked_' . $decoded->jti, true, 30 * DAY_IN_SECONDS);
            }
        } catch (Exception $e) {
            // Ignore invalid/expired tokens — nothing to revoke
        }
    }

    /**
     * Checks whether a JWT has been revoked using its JTI.
     *
     * @param string $token The JWT to check.
     * @return bool True if revoked or invalid, false if active and valid.
     * @since  1.0.0
     */
    public static function isRevoked(string $token): bool
    {
        try {
            $decoded = JWT::decode($token, new Key(self::getSecret(), 'HS256'));
            if (isset($decoded->jti)) {
                return (bool)get_transient('wsp_jwt_revoked_' . $decoded->jti);
            }
        } catch (Exception $e) {
            return true; // Consider any invalid token as revoked/unsafe
        }

        return false;
    }
}
