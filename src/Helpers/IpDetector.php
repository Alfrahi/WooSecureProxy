<?php
/**
 * Helper utility to reliably detect the real client IP address.
 *
 * Fail-closed design: REMOTE_ADDR is always the default answer. Forwarding
 * headers (X-Forwarded-For) are only consulted when REMOTE_ADDR itself is a
 * trusted proxy, as configured via the WSP_TRUSTED_PROXIES constant (exact
 * IPs and/or CIDR ranges, IPv4 and IPv6).
 *
 * @package WooSecureProxy\Helpers
 * @since   1.0.0
 */

namespace WooSecureProxy\Helpers;

/**
 * Trusted-proxy-aware client IP detection.
 */
class IpDetector {

	/**
	 * Returns the real client IP address.
	 *
	 * Resolution rules:
	 * 1. REMOTE_ADDR is always the baseline answer.
	 * 2. Forwarding headers are only considered when REMOTE_ADDR matches an
	 *    entry in the WSP_TRUSTED_PROXIES constant (exact IP or CIDR range).
	 * 3. When trusted, the X-Forwarded-For chain is walked right-to-left
	 *    (with REMOTE_ADDR appended) and the first untrusted, valid IP is
	 *    returned. Client-supplied leftmost entries are never trusted blindly.
	 *
	 * @return string Valid IPv4 or IPv6 address, '0.0.0.0' when indeterminate.
	 * @since  1.0.0
	 */
	public static function get_client_ip(): string {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		if ( ! filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return '0.0.0.0';
		}

		$trusted_proxies = self::get_trusted_proxies();

		if ( empty( $trusted_proxies ) || ! self::is_trusted_proxy( $remote_addr, $trusted_proxies ) ) {
			return $remote_addr;
		}
		if ( empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			return $remote_addr;
		}

		$chain   = array_map( 'trim', explode( ',', (string) wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
		$chain[] = $remote_addr;

		for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
			$candidate = $chain[ $i ];

			if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				continue;
			}

			if ( self::is_trusted_proxy( $candidate, $trusted_proxies ) ) {
				continue;
			}

			return $candidate;
		}

		return $remote_addr;
	}

	/**
	 * Returns the configured list of trusted proxies.
	 *
	 * Reads the WSP_TRUSTED_PROXIES constant, which may be an array or a
	 * comma-separated string of exact IPs and/or CIDR ranges.
	 *
	 * @return array<int, string> Normalized list; empty when not configured.
	 * @since  1.0.0
	 */
	private static function get_trusted_proxies(): array {
		if ( ! defined( 'WSP_TRUSTED_PROXIES' ) ) {
			return array();
		}

		$proxies = constant( 'WSP_TRUSTED_PROXIES' );

		if ( is_string( $proxies ) ) {
			$proxies = explode( ',', $proxies );
		}

		if ( ! is_array( $proxies ) ) {
			return array();
		}

		return array_values( array_filter( array_map( 'trim', $proxies ) ) );
	}

	/**
	 * Checks whether an IP matches the trusted proxy list (exact or CIDR).
	 *
	 * @param string             $ip      IP address to check.
	 * @param array<int, string> $proxies Exact IPs and/or CIDR ranges.
	 * @return bool
	 * @since  1.0.0
	 */
	private static function is_trusted_proxy( string $ip, array $proxies ): bool {
		foreach ( $proxies as $proxy ) {
			if ( false !== strpos( $proxy, '/' ) ) {
				if ( self::ip_in_cidr( $ip, $proxy ) ) {
					return true;
				}
			} elseif ( strcasecmp( $ip, $proxy ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Checks whether an IP is inside a CIDR range (IPv4 or IPv6).
	 *
	 * @param string $ip   IP address to test.
	 * @param string $cidr CIDR notation (e.g. '10.0.0.0/8', '2001:db8::/32').
	 * @return bool
	 * @since  1.0.0
	 */
	private static function ip_in_cidr( string $ip, string $cidr ): bool {
		$parts = explode( '/', $cidr );

		if ( 2 !== count( $parts ) ) {
			return false;
		}

		$subnet = trim( $parts[0] );
		$bits   = trim( $parts[1] );

		if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) || ! is_numeric( $bits ) ) {
			return false;
		}

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bits = (int) $bits;
		$max  = strlen( $ip_bin ) * 8;

		if ( $bits < 0 || $bits > $max ) {
			return false;
		}

		$full_bytes = intdiv( $bits, 8 );
		$remainder  = $bits % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( 0 === $remainder ) {
			return true;
		}

		$mask = ( 0xff << ( 8 - $remainder ) ) & 0xff;

		return ( ord( $ip_bin[ $full_bytes ] ) & $mask ) === ( ord( $subnet_bin[ $full_bytes ] ) & $mask );
	}
}
