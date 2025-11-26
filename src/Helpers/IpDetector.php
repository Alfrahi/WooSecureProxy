<?php
/**
 * Helper utility to reliably detect the real client IP address.
 *
 * Works behind reverse proxies, Cloudflare, load balancers, etc.
 * Prioritizes WooCommerce's built-in geolocation method when available,
 * otherwise falls back to common trusted proxy headers with strict validation.
 *
 * Only public/reserved-range-disallowed IPs are accepted from headers.
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */
namespace WooSecureProxy\Helpers;

class IpDetector
{
    /**
     * Returns the real client IP address, respecting trusted proxy headers.
     *
     * Detection order:
     * 1. WC_Geolocation::get_ip_address() – most reliable when WooCommerce is active
     * 2. Common trusted headers (CF-Connecting-IP, X-Forwarded-For, etc.)
     * 3. REMOTE_ADDR as final fallback
     *
     * Only returns public IPs from forwarded headers — private/reserved ranges are ignored.
     *
     * @return string Valid IPv4 or IPv6 address, never empty.
     * @since  1.0.0
     */
    public static function get_client_ip(): string
    {
        // Use WooCommerce's trusted geolocation method if available
        if (class_exists('WC_Geolocation')) {
            return WC_Geolocation::get_ip_address();
        }

        /**
         * List of common trusted proxy headers in order of preference.
         *
         * @var array<string>
         */
        $trusted_headers = [
            'HTTP_CF_CONNECTING_IP',    // Cloudflare
            'HTTP_X_FORWARDED_FOR',     // Most common proxy header
            'HTTP_X_REAL_IP',           // Nginx proxy
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
        ];

        foreach ($trusted_headers as $header) {
            if (!empty($_SERVER[$header])) {
                // Take first IP in case of comma-separated list
                $ip = trim(explode(',', $_SERVER[$header])[0]);

                // Only accept public IPs — reject private/reserved ranges
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        // Final fallback — should rarely be used on properly configured servers
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
